package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/appleauth"
	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/Akhilmadineni/clixor-backend/internal/presence"
	"github.com/Akhilmadineni/clixor-backend/internal/ratelimit"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/Akhilmadineni/clixor-backend/internal/verification"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	store             store.Store
	tokens            *auth.TokenManager
	bus               events.Bus
	limiter           ratelimit.Limiter
	media             media.Service
	verifier          verification.Service
	apple             appleauth.Verifier
	presence          presence.Service
	logger            *slog.Logger
	dummyHash         string
	metricsToken      string
	trustedProxyCIDRs []netip.Prefix
}

func New(store store.Store, tokens *auth.TokenManager, bus events.Bus, limiter ratelimit.Limiter, mediaService media.Service, verifier verification.Service, apple appleauth.Verifier, presenceService presence.Service, trustedProxyCIDRs []netip.Prefix, metricsToken string, logger *slog.Logger) *Server {
	dummyHash, _ := auth.HashPassword("not-a-real-password-123")
	return &Server{
		store: store, tokens: tokens, bus: bus, limiter: limiter, media: mediaService,
		verifier: verifier, apple: apple, presence: presenceService, metricsToken: metricsToken,
		trustedProxyCIDRs: append([]netip.Prefix(nil), trustedProxyCIDRs...),
		logger:            logger, dummyHash: dummyHash,
	}
}

func (s *Server) Router() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(s.requestIDHeader)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(30 * time.Second))
	router.Use(s.securityHeaders)
	router.Use(s.requestLogger)
	router.Use(s.rateLimit("api", 600, time.Minute, false))

	router.Get("/health/live", s.live)
	router.Get("/health/ready", s.ready)
	router.Get("/", s.legal)
	router.Get("/privacy", s.legal)
	router.Get("/legal", s.legal)
	router.Get("/terms", s.legal)
	router.Handle("/metrics", s.protectMetrics(promhttp.Handler()))

	router.Route("/v1", func(router chi.Router) {
		router.Post("/webhooks/telnyx/messaging", s.telnyxMessagingWebhook)
		router.Route("/auth", func(router chi.Router) {
			router.Use(s.rateLimit("auth", 20, 5*time.Minute, true))
			router.Post("/register", s.register)
			router.Post("/login", s.login)
			router.Post("/refresh", s.refresh)
			router.Post("/phone/start", s.startPhoneVerification)
			router.Post("/phone/verify", s.verifyPhone)
			router.Post("/apple", s.verifyAppleIdentity)
		})

		router.Group(func(router chi.Router) {
			router.Use(s.authenticate)
			router.Use(s.rateLimitIdentity("user", 1200, time.Minute))
			router.Post("/auth/logout", s.logout)
			router.Get("/me", s.me)
			router.Delete("/me", s.deleteAccount)
			router.With(s.rateLimitIdentity("age-assurance-read", 240, 24*time.Hour)).
				Get("/me/age-assurance", s.getAgeAssurance)
			router.With(s.rateLimitIdentity("age-assurance-write", 10, 24*time.Hour)).
				Put("/me/age-assurance", s.putAgeAssurance)

			router.Patch("/me", s.updateProfile)
			router.Post("/me/phone/start", s.startPhoneLink)
			router.Post("/me/phone/verify", s.verifyPhoneLink)
			router.Post("/users/lookup", s.lookupUsers)
			router.Get("/users/search", s.searchUsers)
			router.Route("/devices", func(router chi.Router) {
				router.Get("/", s.listDevices)
				router.Put("/{deviceID}", s.upsertDevice)
				router.Put("/{deviceID}/prekeys", s.putPreKeys)
			})
			router.Post("/users/{userID}/prekeys:claim", s.claimPreKey)
			router.Get("/users/{userID}/presence", s.getPresence)
			router.Route("/conversations", func(router chi.Router) {
				router.Get("/", s.listConversations)
				router.Post("/", s.createConversation)
				router.Route("/{conversationID}", func(router chi.Router) {
					router.Get("/", s.getConversation)
					router.Patch("/", s.updateConversation)
					router.Delete("/", s.deleteConversation)
					router.Get("/members", s.listMembers)
					router.Post("/members", s.addMember)
					router.Delete("/members/{userID}", s.removeMember)
					router.Put("/owner", s.transferOwner)
					router.Get("/messages", s.listMessages)
					router.Post("/messages", s.createMessage)
					router.Get("/receipts", s.listReceipts)
					router.Put("/receipt", s.putReceipt)
					router.Post("/media", s.createMediaUpload)
					router.Get("/entities/{kind}", s.listEntities)
					router.Put("/entities/{kind}/{entityID}", s.putEntity)
					router.Delete("/entities/{kind}/{entityID}", s.deleteEntity)
				})
			})
			router.Post("/media/{mediaID}/complete", s.completeMediaUpload)
			router.Get("/media/{mediaID}/download", s.mediaDownload)
			router.Get("/realtime", s.realtime)
		})
	})
	return router
}

func (s *Server) requestIDHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", middleware.GetReqID(r.Context()))
		next.ServeHTTP(w, r)
	})
}

func (s *Server) protectMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.metricsToken == "" {
			next.ServeHTTP(w, r)
			return
		}
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeDomainError(w, domain.ErrUnauthenticated)
			return
		}
		provided := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		if len(provided) != len(s.metricsToken) ||
			subtle.ConstantTimeCompare([]byte(provided), []byte(s.metricsToken)) != 1 {
			writeDomainError(w, domain.ErrUnauthenticated)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimitIdentity(namespace string, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := identityFrom(r.Context())
			if !ok {
				writeDomainError(w, domain.ErrUnauthenticated)
				return
			}
			key := namespace + ":" + id.UserID.String() + ":" + id.DeviceID.String()
			allowed, err := s.limiter.Allow(r.Context(), key, limit, window)
			if err != nil {
				s.logger.Error("rate_limiter_unavailable", "error", err, "namespace", namespace)
				writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
				return
			}
			if !allowed {
				observability.RateLimited.WithLabelValues(namespace).Inc()
				w.Header().Set("Retry-After", "60")
				writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) rateLimit(namespace string, limit int, window time.Duration, failClosed bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := clientIPForRateLimit(r, s.trustedProxyCIDRs)
			key := namespace + ":" + host
			allowed, err := s.limiter.Allow(r.Context(), key, limit, window)
			if err != nil {
				s.logger.Error("rate_limiter_unavailable", "error", err, "namespace", namespace)
				if failClosed {
					writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
					return
				}
			} else if !allowed {
				observability.RateLimited.WithLabelValues(namespace).Inc()
				w.Header().Set("Retry-After", "60")
				writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(wrapped, r)
		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		duration := time.Since(started)
		observability.HTTPRequests.WithLabelValues(r.Method, route, strconv.Itoa(wrapped.Status())).Inc()
		observability.HTTPDuration.WithLabelValues(r.Method, route).Observe(duration.Seconds())
		s.logger.Info("http_request",
			"request_id", middleware.GetReqID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.Status(),
			"bytes", wrapped.BytesWritten(),
			"duration_ms", duration.Milliseconds(),
		)
	})
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeDomainError(w, domain.ErrUnauthenticated)
			return
		}
		claims, err := s.tokens.ParseAccess(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
		if err != nil {
			writeDomainError(w, err)
			return
		}
		userID, userErr := uuid.Parse(claims.Subject)
		deviceID, deviceErr := uuid.Parse(claims.DeviceID)
		sessionID, sessionErr := uuid.Parse(claims.SessionID)
		if userErr != nil || deviceErr != nil || sessionErr != nil {
			writeDomainError(w, domain.ErrUnauthenticated)
			return
		}
		active, err := s.store.SessionActive(r.Context(), sessionID, userID, deviceID)
		if err != nil {
			s.logger.Error("session_check_failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
			return
		}
		if !active {
			writeDomainError(w, domain.ErrUnauthenticated)
			return
		}
		next.ServeHTTP(w, r.WithContext(withIdentity(r.Context(), identity{
			UserID: userID, DeviceID: deviceID, SessionID: sessionID,
		})))
	})
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	checks := []func(context.Context) error{
		s.store.Ping,
		s.bus.Ping,
		s.limiter.Ping,
		s.presence.Ping,
	}
	if verifier, ok := s.verifier.(verification.HealthChecker); ok {
		checks = append(checks, verifier.Ping)
	}
	for _, check := range checks {
		if err := check(r.Context()); err != nil {
			s.logger.Error("readiness_dependency_failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "not_ready", "A required dependency is unavailable.")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func rawJSON(value any) json.RawMessage {
	payload, _ := json.Marshal(value)
	return payload
}
