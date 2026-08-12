package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/appleauth"
	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/config"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/Akhilmadineni/clixor-backend/internal/httpapi"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/Akhilmadineni/clixor-backend/internal/outbox"
	"github.com/Akhilmadineni/clixor-backend/internal/presence"
	"github.com/Akhilmadineni/clixor-backend/internal/push"
	"github.com/Akhilmadineni/clixor-backend/internal/ratelimit"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/Akhilmadineni/clixor-backend/internal/store/postgres"
	"github.com/Akhilmadineni/clixor-backend/internal/verification"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var persistence store.Store
	var bus events.Bus
	var limiter ratelimit.Limiter
	var mediaService media.Service
	var verifier verification.Service
	var pushService push.Service
	var presenceService presence.Service
	durableStore := false
	switch cfg.Store {
	case "memory":
		persistence = memory.New()
		bus = events.NewMemoryBus()
		limiter = ratelimit.NewMemory()
		mediaService = media.Unavailable{}
		verifier = verification.Development{Code: "000000"}
		pushService = push.Disabled{}
		presenceService = presence.NewMemory()
		logger.Warn("using non-durable memory dependencies; suitable only for tests and local smoke runs")
	case "postgres":
		pgStore, err := postgres.Open(ctx, cfg.DatabaseURL, cfg.AutoMigrate)
		if err != nil {
			logger.Error("open persistence", "error", err)
			os.Exit(1)
		}
		persistence = pgStore
		durableStore = true
		natsBus, err := events.NewNATS(cfg.NATSURL, cfg.TLSCAFile)
		if err != nil {
			persistence.Close()
			logger.Error("open event bus", "error", err)
			os.Exit(1)
		}
		bus = natsBus
		redisLimiter, err := ratelimit.NewRedis(ctx, cfg.RedisURL, cfg.TLSCAFile)
		if err != nil {
			bus.Close()
			persistence.Close()
			logger.Error("open rate limiter", "error", err)
			os.Exit(1)
		}
		limiter = redisLimiter
		redisPresence, err := presence.NewRedis(ctx, cfg.RedisURL, cfg.TLSCAFile)
		if err != nil {
			limiter.Close()
			bus.Close()
			persistence.Close()
			logger.Error("open presence store", "error", err)
			os.Exit(1)
		}
		presenceService = redisPresence
		s3Media, err := media.NewS3(
			ctx, cfg.S3.Endpoint, cfg.S3.PublicEndpoint, cfg.S3.AccessKey, cfg.S3.SecretKey,
			cfg.S3.Bucket, cfg.S3.UseTLS, cfg.TLSCAFile,
		)
		if err != nil {
			limiter.Close()
			presenceService.Close()
			bus.Close()
			persistence.Close()
			logger.Error("open media store", "error", err)
			os.Exit(1)
		}
		mediaService = s3Media
		if cfg.Verification.Provider == "telnyx" {
			telnyxSender, err := verification.NewTelnyxSMS(
				cfg.Verification.TelnyxAPIKey,
				cfg.Verification.TelnyxFromNumber,
				cfg.Verification.TelnyxMessagingProfileID,
				strings.TrimRight(cfg.PublicBaseURL, "/")+"/v1/webhooks/telnyx/messaging",
			)
			if err != nil {
				mediaService.Close()
				limiter.Close()
				presenceService.Close()
				bus.Close()
				persistence.Close()
				logger.Error("open SMS transport", "error", err)
				os.Exit(1)
			}
			otpVerifier, err := verification.NewOTP(
				ctx, cfg.RedisURL, cfg.TLSCAFile, telnyxSender,
				cfg.Verification.OTPSecret,
				verification.Policy{
					CodeLength:       cfg.Verification.OTPCodeLength,
					ChallengeTTL:     cfg.Verification.OTPChallengeTTL,
					ResendCooldown:   cfg.Verification.OTPResendCooldown,
					LockoutTTL:       cfg.Verification.OTPLockoutTTL,
					MaxAttempts:      cfg.Verification.OTPMaxAttempts,
					PhoneSendHourly:  cfg.Verification.OTPPhoneSendHourly,
					PhoneSendDaily:   cfg.Verification.OTPPhoneSendDaily,
					GlobalSendMinute: cfg.Verification.OTPGlobalSendMinute,
					GlobalSendDaily:  cfg.Verification.OTPGlobalSendDaily,
					AllowedPrefixes:  cfg.Verification.OTPAllowedPrefixes,
				},
				cfg.Verification.TelnyxPublicKey,
			)
			if err != nil {
				mediaService.Close()
				limiter.Close()
				presenceService.Close()
				bus.Close()
				persistence.Close()
				logger.Error("open verification service", "error", err)
				os.Exit(1)
			}
			verifier = otpVerifier
		} else {
			verifier = verification.Unavailable{}
			logger.Warn("phone verification is disabled until provider credentials are installed")
		}
		if cfg.APNS.TeamID != "" && cfg.APNS.KeyID != "" && cfg.APNS.PrivateKeyFile != "" {
			primaryAPNS, err := push.NewAPNS(
				cfg.APNS.TeamID, cfg.APNS.KeyID, cfg.APNS.BundleID,
				cfg.APNS.PrivateKeyFile, cfg.APNS.Environment,
			)
			if err != nil {
				mediaService.Close()
				limiter.Close()
				presenceService.Close()
				bus.Close()
				persistence.Close()
				logger.Error("open APNs provider", "error", err)
				os.Exit(1)
			}
			pushService = primaryAPNS
			if cfg.APNS.Environment == "production" {
				sandbox := cfg.APNSSandbox
				if sandbox.TeamID == "" {
					// Traditional APNs signing keys work with both endpoints. Separate
					// sandbox credentials remain available for environment-scoped keys.
					sandbox = cfg.APNS
					sandbox.Environment = "sandbox"
				}
				sandboxAPNS, sandboxErr := push.NewAPNS(
					sandbox.TeamID, sandbox.KeyID, sandbox.BundleID,
					sandbox.PrivateKeyFile, "sandbox",
				)
				if sandboxErr != nil {
					primaryAPNS.Close()
					mediaService.Close()
					limiter.Close()
					presenceService.Close()
					bus.Close()
					persistence.Close()
					logger.Error("open sandbox APNs provider", "error", sandboxErr)
					os.Exit(1)
				}
				pushService = &push.EnvironmentFallback{Primary: primaryAPNS, Fallback: sandboxAPNS}
			}
		} else {
			pushService = push.Disabled{}
			logger.Warn("APNs is disabled; push credentials are not configured")
		}
	default:
		logger.Error("unsupported CLUSTER_STORE", "store", cfg.Store)
		os.Exit(1)
	}
	defer persistence.Close()
	defer bus.Close()
	defer limiter.Close()
	defer mediaService.Close()
	defer pushService.Close()
	defer presenceService.Close()
	if closer, ok := verifier.(verification.Closer); ok {
		defer closer.Close()
	}

	tokenManager := auth.NewTokenManager(
		cfg.JWTIssuer, cfg.AccessSecret, cfg.AccessTTL, cfg.RefreshTTL, persistence,
	)
	appleVerifier, err := appleauth.New(cfg.AppleClientID)
	if err != nil {
		logger.Error("configure Apple identity verification", "error", err)
		os.Exit(1)
	}
	api := httpapi.New(
		persistence, tokenManager, bus, limiter, mediaService, verifier, appleVerifier,
		presenceService, cfg.MetricsToken, logger,
	)
	if durableStore {
		go outbox.New(persistence, bus, pushService, logger).Run(ctx)
	}
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       35 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       75 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("api_started", "address", cfg.HTTPAddr, "environment", cfg.Environment)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown_requested")
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("api_stopped", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful_shutdown_failed", "error", err)
		_ = server.Close()
	}
}
