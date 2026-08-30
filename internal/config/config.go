package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	netmail "net/mail"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ociRegionPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)+$`)

type Config struct {
	Environment       string
	HTTPAddr          string
	PublicBaseURL     string
	TLSCAFile         string
	Store             string
	DatabaseURL       string
	DatabaseMaxConns  int
	DatabaseMinConns  int
	RedisURL          string
	NATSURL           string
	JWTIssuer         string
	AccessSecret      string
	MetricsToken      string
	AppleClientID     string
	TrustedProxyCIDRs []netip.Prefix
	AccessTTL         time.Duration
	RefreshTTL        time.Duration
	AutoMigrate       bool
	MediaProvider     string
	S3                S3Config
	OCIObjectStorage  OCIObjectStorageConfig
	Verification      VerificationConfig
	Mail              MailConfig
	APNS              APNSConfig
	APNSSandbox       APNSConfig
	PushDelivery      PushDeliveryConfig
}

type S3Config struct {
	Endpoint       string
	PublicEndpoint string
	Region         string
	AccessKey      string
	SecretKey      string
	Bucket         string
	UseTLS         bool
}

type OCIObjectStorageConfig struct {
	Region    string
	Namespace string
	Bucket    string
}

type VerificationConfig struct {
	Provider                 string
	OTPSecret                string
	OTPCodeLength            int
	OTPChallengeTTL          time.Duration
	OTPResendCooldown        time.Duration
	OTPLockoutTTL            time.Duration
	OTPMaxAttempts           int
	OTPPhoneSendHourly       int
	OTPPhoneSendDaily        int
	OTPGlobalSendMinute      int
	OTPGlobalSendDaily       int
	OTPAllowedPrefixes       []string
	TelnyxAPIKey             string
	TelnyxFromNumber         string
	TelnyxMessagingProfileID string
	TelnyxPublicKey          string
}

type APNSConfig struct {
	TeamID         string
	KeyID          string
	BundleID       string
	PrivateKeyFile string
	Environment    string
}

type PushDeliveryConfig struct {
	BatchSize           int
	WorkerConcurrency   int
	MaxAttempts         int
	BaseDelay           time.Duration
	MaxDelay            time.Duration
	DeliveredRetention  time.Duration
	DeadLetterRetention time.Duration
}

type MailConfig struct {
	Provider                 string
	SMTPAddress              string
	SMTPUsername             string
	SMTPPassword             string
	SMTPServerName           string
	SMTPCAFile               string
	From                     string
	PasswordResetSecret      string
	PasswordResetTTL         time.Duration
	PasswordResetLength      int
	PasswordResetMaxAttempts int
}

func Load() (Config, error) {
	trustedProxyCIDRs, err := envCIDRs(
		"CLUSTER_TRUSTED_PROXY_CIDRS",
		"127.0.0.0/8,::1/128",
	)
	if err != nil {
		return Config{}, err
	}
	databaseMaxConns, err := envInt("CLUSTER_DATABASE_MAX_CONNS", 35)
	if err != nil {
		return Config{}, err
	}
	databaseMinConns, err := envInt("CLUSTER_DATABASE_MIN_CONNS", 5)
	if err != nil {
		return Config{}, err
	}
	accessTTL, err := time.ParseDuration(env("CLUSTER_ACCESS_TTL", "15m"))
	if err != nil {
		return Config{}, fmt.Errorf("CLUSTER_ACCESS_TTL: %w", err)
	}
	refreshTTL, err := time.ParseDuration(env("CLUSTER_REFRESH_TTL", "720h"))
	if err != nil {
		return Config{}, fmt.Errorf("CLUSTER_REFRESH_TTL: %w", err)
	}
	otpChallengeTTL, err := envDuration("CLUSTER_OTP_CHALLENGE_TTL", "10m")
	if err != nil {
		return Config{}, err
	}
	otpResendCooldown, err := envDuration("CLUSTER_OTP_RESEND_COOLDOWN", "1m")
	if err != nil {
		return Config{}, err
	}
	otpLockoutTTL, err := envDuration("CLUSTER_OTP_LOCKOUT_TTL", "15m")
	if err != nil {
		return Config{}, err
	}
	otpCodeLength, err := envInt("CLUSTER_OTP_CODE_LENGTH", 6)
	if err != nil {
		return Config{}, err
	}
	otpMaxAttempts, err := envInt("CLUSTER_OTP_MAX_ATTEMPTS", 5)
	if err != nil {
		return Config{}, err
	}
	otpPhoneSendHourly, err := envInt("CLUSTER_OTP_PHONE_SEND_HOURLY", 5)
	if err != nil {
		return Config{}, err
	}
	otpPhoneSendDaily, err := envInt("CLUSTER_OTP_PHONE_SEND_DAILY", 10)
	if err != nil {
		return Config{}, err
	}
	otpGlobalSendMinute, err := envInt("CLUSTER_OTP_GLOBAL_SEND_MINUTE", 60)
	if err != nil {
		return Config{}, err
	}
	otpGlobalSendDaily, err := envInt("CLUSTER_OTP_GLOBAL_SEND_DAILY", 10_000)
	if err != nil {
		return Config{}, err
	}
	passwordResetTTL, err := envDuration("CLUSTER_PASSWORD_RESET_TTL", "10m")
	if err != nil {
		return Config{}, err
	}
	passwordResetLength, err := envInt("CLUSTER_PASSWORD_RESET_CODE_LENGTH", 8)
	if err != nil {
		return Config{}, err
	}
	passwordResetMaxAttempts, err := envInt("CLUSTER_PASSWORD_RESET_MAX_ATTEMPTS", 5)
	if err != nil {
		return Config{}, err
	}
	pushBatchSize, err := envInt("CLUSTER_PUSH_DELIVERY_BATCH_SIZE", 100)
	if err != nil {
		return Config{}, err
	}
	pushMaxAttempts, err := envInt("CLUSTER_PUSH_MAX_ATTEMPTS", 8)
	if err != nil {
		return Config{}, err
	}
	pushWorkerConcurrency, err := envInt("CLUSTER_PUSH_WORKER_CONCURRENCY", 16)
	if err != nil {
		return Config{}, err
	}
	pushBaseDelay, err := envDuration("CLUSTER_PUSH_RETRY_BASE_DELAY", "2s")
	if err != nil {
		return Config{}, err
	}
	pushMaxDelay, err := envDuration("CLUSTER_PUSH_RETRY_MAX_DELAY", "15m")
	if err != nil {
		return Config{}, err
	}
	pushDeliveredRetention, err := envDuration("CLUSTER_PUSH_DELIVERED_RETENTION", "24h")
	if err != nil {
		return Config{}, err
	}
	pushDeadLetterRetention, err := envDuration("CLUSTER_PUSH_DEAD_LETTER_RETENTION", "720h")
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Environment:       env("CLUSTER_ENV", "development"),
		HTTPAddr:          env("CLUSTER_HTTP_ADDR", ":8080"),
		PublicBaseURL:     env("CLUSTER_PUBLIC_BASE_URL", "http://127.0.0.1:8080"),
		TLSCAFile:         os.Getenv("CLUSTER_TLS_CA_FILE"),
		Store:             env("CLUSTER_STORE", "postgres"),
		DatabaseURL:       env("CLUSTER_DATABASE_URL", "postgres://clustr:clustr@127.0.0.1:5432/clustr?sslmode=disable"),
		DatabaseMaxConns:  databaseMaxConns,
		DatabaseMinConns:  databaseMinConns,
		RedisURL:          env("CLUSTER_REDIS_URL", "redis://127.0.0.1:6379/0"),
		NATSURL:           env("CLUSTER_NATS_URL", "nats://127.0.0.1:4222"),
		JWTIssuer:         env("CLUSTER_JWT_ISSUER", "clustr-api"),
		AccessSecret:      os.Getenv("CLUSTER_JWT_ACCESS_SECRET"),
		MetricsToken:      os.Getenv("CLUSTER_METRICS_TOKEN"),
		AppleClientID:     env("CLUSTER_APPLE_CLIENT_ID", "com.Clustr.Clustr.Clustr"),
		TrustedProxyCIDRs: trustedProxyCIDRs,
		AccessTTL:         accessTTL,
		RefreshTTL:        refreshTTL,
		AutoMigrate:       envBool("CLUSTER_AUTO_MIGRATE", true),
		MediaProvider:     env("CLUSTER_MEDIA_PROVIDER", "s3"),
		S3: S3Config{
			Endpoint:       env("CLUSTER_S3_ENDPOINT", "127.0.0.1:9000"),
			PublicEndpoint: os.Getenv("CLUSTER_S3_PUBLIC_ENDPOINT"),
			Region:         env("CLUSTER_S3_REGION", "us-east-1"),
			AccessKey:      env("CLUSTER_S3_ACCESS_KEY", "clustr"),
			SecretKey:      os.Getenv("CLUSTER_S3_SECRET_KEY"),
			Bucket:         env("CLUSTER_S3_BUCKET", "clustr-media"),
			UseTLS:         envBool("CLUSTER_S3_USE_TLS", false),
		},
		OCIObjectStorage: OCIObjectStorageConfig{
			Region:    os.Getenv("CLUSTER_OCI_OBJECT_STORAGE_REGION"),
			Namespace: os.Getenv("CLUSTER_OCI_OBJECT_STORAGE_NAMESPACE"),
			Bucket:    os.Getenv("CLUSTER_OCI_OBJECT_STORAGE_BUCKET"),
		},
		Verification: VerificationConfig{
			Provider:      env("CLUSTER_VERIFICATION_PROVIDER", "disabled"),
			OTPSecret:     os.Getenv("CLUSTER_OTP_HMAC_SECRET"),
			OTPCodeLength: otpCodeLength, OTPChallengeTTL: otpChallengeTTL,
			OTPResendCooldown: otpResendCooldown, OTPLockoutTTL: otpLockoutTTL,
			OTPMaxAttempts: otpMaxAttempts, OTPPhoneSendHourly: otpPhoneSendHourly,
			OTPPhoneSendDaily: otpPhoneSendDaily, OTPGlobalSendMinute: otpGlobalSendMinute,
			OTPGlobalSendDaily:       otpGlobalSendDaily,
			OTPAllowedPrefixes:       envCSV("CLUSTER_OTP_ALLOWED_PREFIXES"),
			TelnyxAPIKey:             os.Getenv("CLUSTER_TELNYX_API_KEY"),
			TelnyxFromNumber:         os.Getenv("CLUSTER_TELNYX_FROM_NUMBER"),
			TelnyxMessagingProfileID: os.Getenv("CLUSTER_TELNYX_MESSAGING_PROFILE_ID"),
			TelnyxPublicKey:          os.Getenv("CLUSTER_TELNYX_PUBLIC_KEY"),
		},
		Mail: MailConfig{
			Provider:                 env("CLUSTER_MAIL_PROVIDER", "disabled"),
			SMTPAddress:              os.Getenv("CLUSTER_SMTP_ADDRESS"),
			SMTPUsername:             os.Getenv("CLUSTER_SMTP_USERNAME"),
			SMTPPassword:             os.Getenv("CLUSTER_SMTP_PASSWORD"),
			SMTPServerName:           os.Getenv("CLUSTER_SMTP_SERVER_NAME"),
			SMTPCAFile:               os.Getenv("CLUSTER_SMTP_CA_FILE"),
			From:                     env("CLUSTER_MAIL_FROM", "Clixor <no-reply@atlanteanz.com>"),
			PasswordResetSecret:      os.Getenv("CLUSTER_PASSWORD_RESET_HMAC_SECRET"),
			PasswordResetTTL:         passwordResetTTL,
			PasswordResetLength:      passwordResetLength,
			PasswordResetMaxAttempts: passwordResetMaxAttempts,
		},
		APNS: APNSConfig{
			TeamID:         os.Getenv("CLUSTER_APNS_TEAM_ID"),
			KeyID:          os.Getenv("CLUSTER_APNS_KEY_ID"),
			BundleID:       env("CLUSTER_APNS_BUNDLE_ID", "com.Clustr.Clustr.Clustr"),
			PrivateKeyFile: os.Getenv("CLUSTER_APNS_PRIVATE_KEY_FILE"),
			Environment:    env("CLUSTER_APNS_ENVIRONMENT", "production"),
		},
		APNSSandbox: APNSConfig{
			TeamID:         os.Getenv("CLUSTER_APNS_SANDBOX_TEAM_ID"),
			KeyID:          os.Getenv("CLUSTER_APNS_SANDBOX_KEY_ID"),
			BundleID:       os.Getenv("CLUSTER_APNS_SANDBOX_BUNDLE_ID"),
			PrivateKeyFile: os.Getenv("CLUSTER_APNS_SANDBOX_PRIVATE_KEY_FILE"),
			Environment:    "sandbox",
		},
		PushDelivery: PushDeliveryConfig{
			BatchSize: pushBatchSize, WorkerConcurrency: pushWorkerConcurrency,
			MaxAttempts: pushMaxAttempts,
			BaseDelay:   pushBaseDelay, MaxDelay: pushMaxDelay,
			DeliveredRetention:  pushDeliveredRetention,
			DeadLetterRetention: pushDeadLetterRetention,
		},
	}
	if cfg.Store == "memory" && cfg.AccessSecret == "" {
		cfg.AccessSecret = "development-only-secret-change-me"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (cfg Config) Validate() error {
	switch cfg.Environment {
	case "development", "staging", "production":
	default:
		return fmt.Errorf("unsupported CLUSTER_ENV %q", cfg.Environment)
	}
	if cfg.Store != "memory" && cfg.Store != "postgres" {
		return fmt.Errorf("unsupported CLUSTER_STORE %q", cfg.Store)
	}
	if cfg.DatabaseMaxConns < 1 || cfg.DatabaseMaxConns > 200 {
		return errors.New("CLUSTER_DATABASE_MAX_CONNS must be between 1 and 200")
	}
	if cfg.DatabaseMinConns < 0 || cfg.DatabaseMinConns > cfg.DatabaseMaxConns {
		return errors.New("CLUSTER_DATABASE_MIN_CONNS must be between 0 and CLUSTER_DATABASE_MAX_CONNS")
	}
	if cfg.Environment == "production" && cfg.Store != "postgres" {
		return errors.New("production requires CLUSTER_STORE=postgres")
	}
	if cfg.Store != "memory" && len(cfg.AccessSecret) < 32 {
		return errors.New("CLUSTER_JWT_ACCESS_SECRET must contain at least 32 bytes")
	}
	if cfg.AccessTTL < time.Minute || cfg.AccessTTL > time.Hour {
		return errors.New("CLUSTER_ACCESS_TTL must be between 1m and 1h")
	}
	if cfg.RefreshTTL < time.Hour || cfg.RefreshTTL > 365*24*time.Hour {
		return errors.New("CLUSTER_REFRESH_TTL must be between 1h and 8760h")
	}
	if err := cfg.validatePushDelivery(); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.JWTIssuer) == "" {
		return errors.New("CLUSTER_JWT_ISSUER is required")
	}
	switch cfg.MediaProvider {
	case "s3":
	case "oci":
		if strings.TrimSpace(cfg.OCIObjectStorage.Region) == "" ||
			strings.TrimSpace(cfg.OCIObjectStorage.Namespace) == "" ||
			strings.TrimSpace(cfg.OCIObjectStorage.Bucket) == "" {
			return errors.New("OCI media requires CLUSTER_OCI_OBJECT_STORAGE_REGION, CLUSTER_OCI_OBJECT_STORAGE_NAMESPACE, and CLUSTER_OCI_OBJECT_STORAGE_BUCKET")
		}
		if !ociRegionPattern.MatchString(cfg.OCIObjectStorage.Region) {
			return errors.New("CLUSTER_OCI_OBJECT_STORAGE_REGION is invalid")
		}
	default:
		return fmt.Errorf("unsupported CLUSTER_MEDIA_PROVIDER %q", cfg.MediaProvider)
	}
	if cfg.Verification.Provider != "telnyx" && cfg.Verification.Provider != "disabled" {
		return errors.New("CLUSTER_VERIFICATION_PROVIDER must be telnyx or disabled")
	}
	if cfg.Environment == "production" && cfg.Verification.Provider != "telnyx" {
		return errors.New("production requires CLUSTER_VERIFICATION_PROVIDER=telnyx")
	}
	if err := cfg.validateVerification(); err != nil {
		return err
	}
	if err := cfg.validateMail(); err != nil {
		return err
	}
	if cfg.Environment == "production" && strings.TrimSpace(cfg.AppleClientID) == "" {
		return errors.New("production CLUSTER_APPLE_CLIENT_ID is required")
	}
	if cfg.Environment != "production" {
		return nil
	}
	if len(cfg.MetricsToken) < 32 || cfg.MetricsToken == cfg.AccessSecret {
		return errors.New("production CLUSTER_METRICS_TOKEN must be a distinct secret of at least 32 bytes")
	}
	if cfg.AutoMigrate {
		return errors.New("production requires CLUSTER_AUTO_MIGRATE=false; run the migration job before rollout")
	}
	publicURL, err := url.Parse(cfg.PublicBaseURL)
	if err != nil || publicURL.Scheme != "https" || publicURL.Host == "" || publicURL.User != nil {
		return errors.New("production CLUSTER_PUBLIC_BASE_URL must be an https URL without credentials")
	}
	databaseURL, err := url.Parse(cfg.DatabaseURL)
	if err != nil || (databaseURL.Scheme != "postgres" && databaseURL.Scheme != "postgresql") {
		return errors.New("production CLUSTER_DATABASE_URL must be a PostgreSQL URL")
	}
	switch databaseURL.Query().Get("sslmode") {
	case "require", "verify-ca", "verify-full":
	default:
		return errors.New("production PostgreSQL must use sslmode=require, verify-ca, or verify-full")
	}
	redisURL, err := url.Parse(cfg.RedisURL)
	if err != nil || redisURL.Scheme != "rediss" || redisURL.Host == "" {
		return errors.New("production CLUSTER_REDIS_URL must use rediss://")
	}
	natsURL, err := url.Parse(cfg.NATSURL)
	if err != nil || natsURL.Scheme != "tls" || natsURL.Host == "" {
		return errors.New("production CLUSTER_NATS_URL must use tls://")
	}
	if cfg.MediaProvider == "s3" {
		if !cfg.S3.UseTLS || cfg.S3.Endpoint == "" || cfg.S3.PublicEndpoint == "" || cfg.S3.Region == "" || cfg.S3.AccessKey == "" ||
			cfg.S3.SecretKey == "" || cfg.S3.Bucket == "" {
			return errors.New("production S3 configuration requires TLS, region, internal/public endpoints, bucket, and credentials")
		}
	}
	if cfg.APNS.TeamID == "" || cfg.APNS.KeyID == "" || cfg.APNS.BundleID == "" ||
		cfg.APNS.PrivateKeyFile == "" {
		return errors.New("production APNs credentials are required")
	}
	if cfg.APNS.Environment != "production" {
		return errors.New("production requires CLUSTER_APNS_ENVIRONMENT=production")
	}
	sandboxConfigured := cfg.APNSSandbox.TeamID != "" || cfg.APNSSandbox.KeyID != "" ||
		cfg.APNSSandbox.BundleID != "" || cfg.APNSSandbox.PrivateKeyFile != ""
	if sandboxConfigured && (cfg.APNSSandbox.TeamID == "" || cfg.APNSSandbox.KeyID == "" ||
		cfg.APNSSandbox.BundleID == "" || cfg.APNSSandbox.PrivateKeyFile == "") {
		return errors.New("sandbox APNs credentials must be configured together")
	}
	return nil
}

func (cfg Config) validatePushDelivery() error {
	pushDelivery := cfg.PushDelivery
	// Config values constructed directly in tests or small development tools
	// retain the same production defaults as Load.
	if pushDelivery == (PushDeliveryConfig{}) {
		pushDelivery = PushDeliveryConfig{
			BatchSize: 100, WorkerConcurrency: 16, MaxAttempts: 8, BaseDelay: 2 * time.Second,
			MaxDelay: 15 * time.Minute, DeliveredRetention: 24 * time.Hour,
			DeadLetterRetention: 30 * 24 * time.Hour,
		}
	}
	if pushDelivery.BatchSize < 1 || pushDelivery.BatchSize > 1000 {
		return errors.New("CLUSTER_PUSH_DELIVERY_BATCH_SIZE must be between 1 and 1000")
	}
	if pushDelivery.WorkerConcurrency < 1 || pushDelivery.WorkerConcurrency > 100 {
		return errors.New("CLUSTER_PUSH_WORKER_CONCURRENCY must be between 1 and 100")
	}
	if pushDelivery.MaxAttempts < 1 || pushDelivery.MaxAttempts > 20 {
		return errors.New("CLUSTER_PUSH_MAX_ATTEMPTS must be between 1 and 20")
	}
	if pushDelivery.BaseDelay < 100*time.Millisecond || pushDelivery.BaseDelay > 5*time.Minute {
		return errors.New("CLUSTER_PUSH_RETRY_BASE_DELAY must be between 100ms and 5m")
	}
	if pushDelivery.MaxDelay < pushDelivery.BaseDelay || pushDelivery.MaxDelay > 24*time.Hour {
		return errors.New("CLUSTER_PUSH_RETRY_MAX_DELAY must be at least the base delay and no more than 24h")
	}
	if pushDelivery.DeliveredRetention < time.Hour || pushDelivery.DeliveredRetention > 30*24*time.Hour {
		return errors.New("CLUSTER_PUSH_DELIVERED_RETENTION must be between 1h and 720h")
	}
	if pushDelivery.DeadLetterRetention < 24*time.Hour || pushDelivery.DeadLetterRetention > 365*24*time.Hour {
		return errors.New("CLUSTER_PUSH_DEAD_LETTER_RETENTION must be between 24h and 8760h")
	}
	return nil
}

func (cfg Config) validateMail() error {
	mail := cfg.Mail
	if mail.Provider != "smtp" && mail.Provider != "disabled" {
		return errors.New("CLUSTER_MAIL_PROVIDER must be smtp or disabled")
	}
	if mail.PasswordResetTTL < 5*time.Minute || mail.PasswordResetTTL > 30*time.Minute {
		return errors.New("CLUSTER_PASSWORD_RESET_TTL must be between 5m and 30m")
	}
	if mail.PasswordResetLength != 8 {
		return errors.New("CLUSTER_PASSWORD_RESET_CODE_LENGTH must be 8")
	}
	if mail.PasswordResetMaxAttempts < 3 || mail.PasswordResetMaxAttempts > 10 {
		return errors.New("CLUSTER_PASSWORD_RESET_MAX_ATTEMPTS must be between 3 and 10")
	}
	if mail.Provider != "smtp" {
		return nil
	}
	host, _, err := net.SplitHostPort(mail.SMTPAddress)
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("CLUSTER_SMTP_ADDRESS must be a host:port address")
	}
	if strings.TrimSpace(mail.SMTPUsername) == "" || mail.SMTPPassword == "" {
		return errors.New("CLUSTER_SMTP_USERNAME and CLUSTER_SMTP_PASSWORD are required")
	}
	serverName := strings.TrimSpace(mail.SMTPServerName)
	if serverName == "" {
		serverName = host
	}
	if net.ParseIP(serverName) != nil || strings.ContainsAny(serverName, "\r\n/:@") {
		return errors.New("CLUSTER_SMTP_SERVER_NAME must be a DNS hostname")
	}
	from, err := netmail.ParseAddress(mail.From)
	if err != nil || strings.TrimSpace(from.Address) == "" {
		return errors.New("CLUSTER_MAIL_FROM must contain a valid mailbox")
	}
	if len(mail.PasswordResetSecret) < 32 ||
		mail.PasswordResetSecret == cfg.AccessSecret ||
		mail.PasswordResetSecret == cfg.MetricsToken ||
		mail.PasswordResetSecret == cfg.Verification.OTPSecret {
		return errors.New("CLUSTER_PASSWORD_RESET_HMAC_SECRET must be a distinct secret of at least 32 bytes")
	}
	return nil
}

func (cfg Config) validateVerification() error {
	verification := cfg.Verification
	if verification.OTPCodeLength < 6 || verification.OTPCodeLength > 8 {
		return errors.New("CLUSTER_OTP_CODE_LENGTH must be between 6 and 8")
	}
	if verification.OTPChallengeTTL < 2*time.Minute || verification.OTPChallengeTTL > 30*time.Minute {
		return errors.New("CLUSTER_OTP_CHALLENGE_TTL must be between 2m and 30m")
	}
	if verification.OTPResendCooldown < 30*time.Second ||
		verification.OTPResendCooldown >= verification.OTPChallengeTTL {
		return errors.New("CLUSTER_OTP_RESEND_COOLDOWN must be at least 30s and less than the challenge TTL")
	}
	if verification.OTPLockoutTTL < time.Minute || verification.OTPLockoutTTL > 24*time.Hour {
		return errors.New("CLUSTER_OTP_LOCKOUT_TTL must be between 1m and 24h")
	}
	if verification.OTPMaxAttempts < 3 || verification.OTPMaxAttempts > 10 {
		return errors.New("CLUSTER_OTP_MAX_ATTEMPTS must be between 3 and 10")
	}
	if verification.OTPPhoneSendHourly < 1 ||
		verification.OTPPhoneSendDaily < verification.OTPPhoneSendHourly ||
		verification.OTPGlobalSendMinute < 1 ||
		verification.OTPGlobalSendDaily < verification.OTPGlobalSendMinute {
		return errors.New("OTP send limits are inconsistent")
	}
	if verification.Provider != "telnyx" {
		return nil
	}
	if len(verification.OTPSecret) < 32 || verification.OTPSecret == cfg.AccessSecret ||
		verification.OTPSecret == cfg.MetricsToken {
		return errors.New("CLUSTER_OTP_HMAC_SECRET must be a distinct secret of at least 32 bytes")
	}
	if verification.TelnyxAPIKey == "" || !e164(verification.TelnyxFromNumber) ||
		verification.TelnyxMessagingProfileID == "" {
		return errors.New("Telnyx API key, E.164 sender, and messaging profile are required")
	}
	publicKey, err := base64.StdEncoding.DecodeString(verification.TelnyxPublicKey)
	if err != nil || len(publicKey) != 32 {
		return errors.New("CLUSTER_TELNYX_PUBLIC_KEY must be a base64-encoded Ed25519 public key")
	}
	for _, prefix := range verification.OTPAllowedPrefixes {
		if len(prefix) < 2 || prefix[0] != '+' {
			return fmt.Errorf("invalid CLUSTER_OTP_ALLOWED_PREFIXES value %q", prefix)
		}
		for _, character := range prefix[1:] {
			if character < '0' || character > '9' {
				return fmt.Errorf("invalid CLUSTER_OTP_ALLOWED_PREFIXES value %q", prefix)
			}
		}
	}
	if cfg.Environment == "production" && len(verification.OTPAllowedPrefixes) == 0 {
		return errors.New("production CLUSTER_OTP_ALLOWED_PREFIXES must explicitly constrain SMS destinations")
	}
	return nil
}

func e164(value string) bool {
	if len(value) < 9 || len(value) > 16 || value[0] != '+' || value[1] == '0' {
		return false
	}
	for _, character := range value[1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envDuration(key, fallback string) (time.Duration, error) {
	value, err := time.ParseDuration(env(key, fallback))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return value, nil
}

func envInt(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return value, nil
}

func envCSV(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func envCIDRs(key, fallback string) ([]netip.Prefix, error) {
	raw := env(key, fallback)
	parts := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid CIDR %q: %w", key, value, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
