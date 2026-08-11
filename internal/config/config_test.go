package config

import (
	"strings"
	"testing"
	"time"
)

func TestProductionConfigurationRequiresEncryptedDependencies(t *testing.T) {
	cfg := validProductionConfig()
	cfg.RedisURL = "redis://redis.internal:6379/0"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rediss") {
		t.Fatalf("expected insecure Redis URL to fail validation, received %v", err)
	}

	cfg = validProductionConfig()
	cfg.DatabaseURL = "postgres://user:pass@db.internal/clustr?sslmode=disable"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "sslmode") {
		t.Fatalf("expected insecure PostgreSQL URL to fail validation, received %v", err)
	}

	cfg = validProductionConfig()
	cfg.AutoMigrate = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "migration job") {
		t.Fatalf("expected API-managed production migrations to fail validation, received %v", err)
	}
}

func TestValidProductionConfiguration(t *testing.T) {
	if err := validProductionConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProductionVerificationRequiresExplicitCostAndSecretControls(t *testing.T) {
	cfg := validProductionConfig()
	cfg.Verification.OTPAllowedPrefixes = nil
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ALLOWED_PREFIXES") {
		t.Fatalf("expected an explicit destination allowlist, received %v", err)
	}

	cfg = validProductionConfig()
	cfg.Verification.OTPSecret = cfg.AccessSecret
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "distinct secret") {
		t.Fatalf("expected OTP secret reuse to fail, received %v", err)
	}
}

func validProductionConfig() Config {
	return Config{
		Environment:   "production",
		PublicBaseURL: "https://api.clustr.app",
		Store:         "postgres",
		DatabaseURL:   "postgres://user:pass@db.internal/clustr?sslmode=verify-full",
		RedisURL:      "rediss://:pass@redis.internal:6379/0",
		NATSURL:       "tls://nats.internal:4222",
		JWTIssuer:     "clustr-api",
		AccessSecret:  strings.Repeat("s", 48),
		MetricsToken:  strings.Repeat("m", 48),
		AppleClientID: "com.example.Clustr",
		AccessTTL:     15 * time.Minute,
		RefreshTTL:    30 * 24 * time.Hour,
		AutoMigrate:   false,
		S3: S3Config{
			Endpoint: "s3.internal", PublicEndpoint: "media.clustr.app",
			AccessKey: "access", SecretKey: "secret", Bucket: "clustr-media", UseTLS: true,
		},
		Verification: VerificationConfig{
			Provider: "telnyx", OTPSecret: strings.Repeat("o", 48), OTPCodeLength: 6,
			OTPChallengeTTL: 10 * time.Minute, OTPResendCooldown: time.Minute,
			OTPLockoutTTL: 15 * time.Minute, OTPMaxAttempts: 5,
			OTPPhoneSendHourly: 5, OTPPhoneSendDaily: 10,
			OTPGlobalSendMinute: 60, OTPGlobalSendDaily: 10_000,
			OTPAllowedPrefixes: []string{"+1"},
			TelnyxAPIKey:       "key", TelnyxFromNumber: "+13125550100",
			TelnyxMessagingProfileID: "profile",
			TelnyxPublicKey:          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
		APNS: APNSConfig{
			TeamID: "team", KeyID: "key", BundleID: "app.bundle",
			PrivateKeyFile: "/run/secrets/AuthKey.p8", Environment: "production",
		},
	}
}
