package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTrustedProxyCIDRsAreStrictlyParsed(t *testing.T) {
	t.Setenv("TEST_TRUSTED_PROXIES", "127.0.0.1/8, ::1/128, 172.31.254.2/32")
	prefixes, err := envCIDRs("TEST_TRUSTED_PROXIES", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("172.31.254.2/32"),
	}
	if len(prefixes) != len(want) {
		t.Fatalf("prefix count = %d, want %d", len(prefixes), len(want))
	}
	for index := range want {
		if prefixes[index] != want[index] {
			t.Fatalf("prefix[%d] = %s, want %s", index, prefixes[index], want[index])
		}
	}

	t.Setenv("TEST_TRUSTED_PROXIES", "127.0.0.1")
	if _, err := envCIDRs("TEST_TRUSTED_PROXIES", ""); err == nil {
		t.Fatal("expected an address without a CIDR mask to fail")
	}
}

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

func TestDatabasePoolLimitsAreValidated(t *testing.T) {
	cfg := validProductionConfig()
	cfg.DatabaseMaxConns = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "DATABASE_MAX_CONNS") {
		t.Fatalf("expected zero maximum connections to fail validation, received %v", err)
	}

	cfg = validProductionConfig()
	cfg.DatabaseMinConns = cfg.DatabaseMaxConns + 1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "DATABASE_MIN_CONNS") {
		t.Fatalf("expected minimum connections above maximum to fail validation, received %v", err)
	}
}

func TestMediaProviderDefaultsToS3(t *testing.T) {
	t.Setenv("CLUSTER_ENV", "development")
	t.Setenv("CLUSTER_STORE", "memory")
	t.Setenv("CLUSTER_MEDIA_PROVIDER", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MediaProvider != "s3" {
		t.Fatalf("media provider = %q, want s3", cfg.MediaProvider)
	}
}

func TestOCIObjectStorageConfigurationIsValidated(t *testing.T) {
	cfg := validProductionConfig()
	cfg.MediaProvider = "oci"
	cfg.S3 = S3Config{}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "OCI media requires") {
		t.Fatalf("expected incomplete OCI configuration to fail, received %v", err)
	}

	cfg.OCIObjectStorage = OCIObjectStorageConfig{
		Region: "us-phoenix-1", Namespace: "exampletenancy", Bucket: "clixor-media",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid OCI media configuration failed: %v", err)
	}

	cfg.OCIObjectStorage.Region = "https://attacker.example"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "REGION is invalid") {
		t.Fatalf("expected invalid OCI region to fail, received %v", err)
	}

	cfg.OCIObjectStorage.Region = "us-phoenix-1"
	cfg.MediaProvider = "unsupported"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "CLUSTER_MEDIA_PROVIDER") {
		t.Fatalf("expected unsupported media provider to fail, received %v", err)
	}
}

func TestValidProductionConfiguration(t *testing.T) {
	if err := validProductionConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSandboxAPNSCredentialsMustBeConfiguredTogether(t *testing.T) {
	cfg := validProductionConfig()
	cfg.APNSSandbox.TeamID = "sandbox-team"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "sandbox APNs credentials") {
		t.Fatalf("expected partial sandbox credentials to fail validation, received %v", err)
	}

	cfg.APNSSandbox = APNSConfig{
		TeamID: "sandbox-team", KeyID: "sandbox-key", BundleID: "com.example.Clixor",
		PrivateKeyFile: "/run/secrets/AuthKey-sandbox.p8", Environment: "sandbox",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("complete sandbox credentials failed validation: %v", err)
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

func TestPasswordResetCodeLengthMatchesPublicContract(t *testing.T) {
	for _, length := range []int{6, 12} {
		cfg := validProductionConfig()
		cfg.Mail.PasswordResetLength = length
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "must be 8") {
			t.Fatalf("password reset length %d returned %v, want fixed-length validation error", length, err)
		}
	}
}

func TestProductionMayKeepUnverifiedOutboundMailDisabled(t *testing.T) {
	cfg := validProductionConfig()
	cfg.Mail.Provider = "disabled"
	cfg.Mail.PasswordResetSecret = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("production with explicitly disabled mail failed validation: %v", err)
	}
}

func TestSMTPRequiresAuthenticatedTLSSubmissionConfiguration(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.Mail.SMTPUsername = "" },
		func(cfg *Config) { cfg.Mail.SMTPPassword = "" },
		func(cfg *Config) { cfg.Mail.SMTPServerName = "127.0.0.1" },
	} {
		cfg := validProductionConfig()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatal("unsafe SMTP submission configuration was accepted")
		}
	}
}

func TestPushDeliveryPolicyIsBounded(t *testing.T) {
	valid := PushDeliveryConfig{
		BatchSize: 100, WorkerConcurrency: 16, MaxAttempts: 8,
		BaseDelay: 2 * time.Second, MaxDelay: 15 * time.Minute,
		DeliveredRetention: 24 * time.Hour, DeadLetterRetention: 30 * 24 * time.Hour,
	}
	for _, test := range []struct {
		name   string
		mutate func(*PushDeliveryConfig)
	}{
		{"unbounded attempts", func(policy *PushDeliveryConfig) { policy.MaxAttempts = 21 }},
		{"excess concurrency", func(policy *PushDeliveryConfig) { policy.WorkerConcurrency = 101 }},
		{"inverted delay", func(policy *PushDeliveryConfig) { policy.MaxDelay = time.Second }},
		{"short dead letter retention", func(policy *PushDeliveryConfig) { policy.DeadLetterRetention = time.Hour }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validProductionConfig()
			cfg.PushDelivery = valid
			test.mutate(&cfg.PushDelivery)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid push delivery policy was accepted")
			}
		})
	}
}

func validProductionConfig() Config {
	return Config{
		Environment:      "production",
		PublicBaseURL:    "https://api.clustr.app",
		Store:            "postgres",
		DatabaseURL:      "postgres://user:pass@db.internal/clustr?sslmode=verify-full",
		DatabaseMaxConns: 12,
		DatabaseMinConns: 2,
		RedisURL:         "rediss://:pass@redis.internal:6379/0",
		NATSURL:          "tls://nats.internal:4222",
		JWTIssuer:        "clustr-api",
		AccessSecret:     strings.Repeat("s", 48),
		MetricsToken:     strings.Repeat("m", 48),
		AppleClientID:    "com.example.Clustr",
		AccessTTL:        15 * time.Minute,
		RefreshTTL:       30 * 24 * time.Hour,
		AutoMigrate:      false,
		MediaProvider:    "s3",
		S3: S3Config{
			Endpoint: "s3.internal", PublicEndpoint: "media.clustr.app",
			Region: "us-east-1", AccessKey: "access", SecretKey: "secret",
			Bucket: "clustr-media", UseTLS: true,
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
		Mail: MailConfig{
			Provider: "smtp", SMTPAddress: "smtp.email.us-phoenix-1.oci.oraclecloud.com:587",
			SMTPUsername: "smtp-user", SMTPPassword: "smtp-password",
			SMTPServerName:      "smtp.email.us-phoenix-1.oci.oraclecloud.com",
			From:                "Clixor <no-reply@atlanteanz.com>",
			PasswordResetSecret: strings.Repeat("r", 48),
			PasswordResetTTL:    10 * time.Minute, PasswordResetLength: 8,
			PasswordResetMaxAttempts: 5,
		},
		APNS: APNSConfig{
			TeamID: "team", KeyID: "key", BundleID: "app.bundle",
			PrivateKeyFile: "/run/secrets/AuthKey.p8", Environment: "production",
		},
	}
}
