package config

import (
	"encoding/base64"
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

func TestMediaDefaultsPreserveProduction05bOneGiBContract(t *testing.T) {
	t.Setenv("CLUSTER_ENV", "development")
	t.Setenv("CLUSTER_STORE", "memory")
	for _, key := range []string{
		"CLUSTER_MEDIA_CONVERSATION_MAX_BYTES", "CLUSTER_MEDIA_PROFILE_MAX_BYTES",
		"CLUSTER_MEDIA_PENDING_USER_MAX_BYTES", "CLUSTER_MEDIA_PENDING_CONVERSATION_MAX_BYTES",
		"CLUSTER_MEDIA_STORED_USER_MAX_BYTES", "CLUSTER_MEDIA_STORED_CONVERSATION_MAX_BYTES",
	} {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Media.ConversationMaxBytes != 1<<30 || cfg.Media.ProfileMaxBytes != 20<<20 {
		t.Fatalf("media object defaults = conversation %d profile %d", cfg.Media.ConversationMaxBytes, cfg.Media.ProfileMaxBytes)
	}
	if cfg.Media.PendingUserMaxBytes < cfg.Media.ConversationMaxBytes ||
		cfg.Media.PendingConversationMaxBytes < cfg.Media.ConversationMaxBytes ||
		cfg.Media.StoredUserMaxBytes < cfg.Media.PendingUserMaxBytes ||
		cfg.Media.StoredConversationMaxBytes < cfg.Media.PendingConversationMaxBytes {
		t.Fatalf("media quota defaults cannot reserve the public maximum: %+v", cfg.Media)
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
		func(cfg *Config) { cfg.Mail.SMTPTransport = "opportunistic" },
		func(cfg *Config) { cfg.Mail.QueueEncryptionKey = "not-base64" },
		func(cfg *Config) {
			cfg.AccessSecret = strings.Repeat("a", 32)
			cfg.Mail.QueueEncryptionKey = base64.StdEncoding.EncodeToString([]byte(cfg.AccessSecret))
		},
		func(cfg *Config) {
			cfg.Mail.SMTPPassword = strings.Repeat("q", 32)
		},
		func(cfg *Config) {
			cfg.Mail.SMTPPassword = strings.Repeat("p", 48)
			cfg.Mail.PasswordResetSecret = cfg.Mail.SMTPPassword
		},
	} {
		cfg := validProductionConfig()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatal("unsafe SMTP submission configuration was accepted")
		}
	}
}

func TestMailQueueDeliveryPolicyIsBounded(t *testing.T) {
	for _, mutate := range []func(*MailConfig){
		func(mail *MailConfig) { mail.QueueBatchSize = 1001 },
		func(mail *MailConfig) { mail.QueueWorkerConcurrency = 51 },
		func(mail *MailConfig) { mail.QueueMaxAttempts = 21 },
		func(mail *MailConfig) { mail.QueueMaxDelay = time.Second },
		func(mail *MailConfig) { mail.QueueDeadLetterRetention = time.Hour },
	} {
		cfg := validProductionConfig()
		mutate(&cfg.Mail)
		if err := cfg.Validate(); err == nil {
			t.Fatal("unsafe mail queue policy was accepted")
		}
	}
}

func TestLoadMigrationNeedsOnlyDatabaseConfiguration(t *testing.T) {
	t.Setenv("CLUSTER_DATABASE_URL", "postgres://clixor:secret@postgres.internal/clixor?sslmode=require")
	t.Setenv("CLUSTER_DATABASE_MAX_CONNS", "9")
	t.Setenv("CLUSTER_DATABASE_MIN_CONNS", "1")
	// Prove malformed API-only values are outside the migration command's
	// credential and validation boundary.
	t.Setenv("CLUSTER_MAIL_PROVIDER", "unsafe-value")
	t.Setenv("CLUSTER_JWT_ACCESS_SECRET", "")
	cfg, err := LoadMigration()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseMaxConns != 9 || cfg.DatabaseMinConns != 1 || cfg.DatabaseURL == "" {
		t.Fatalf("unexpected migration config: %+v", cfg)
	}
}

func TestLoadMigrationRejectsMissingOrUnsafeDatabaseConfiguration(t *testing.T) {
	for name, values := range map[string][3]string{
		"missing":       {"", "12", "2"},
		"wrong-scheme":  {"https://postgres.internal/clixor", "12", "2"},
		"missing-host":  {"postgres:///clixor", "12", "2"},
		"bad-max":       {"postgres://host/db", "zero", "2"},
		"inverted-pool": {"postgres://host/db", "2", "3"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("CLUSTER_DATABASE_URL", values[0])
			t.Setenv("CLUSTER_DATABASE_MAX_CONNS", values[1])
			t.Setenv("CLUSTER_DATABASE_MIN_CONNS", values[2])
			if _, err := LoadMigration(); err == nil {
				t.Fatal("unsafe migration configuration was accepted")
			}
		})
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

func TestMediaLimitsRejectUnsafeCapacityAndCleanupSettings(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "attachment above compatibility ceiling",
			mutate: func(cfg *Config) {
				cfg.Media.ConversationMaxBytes = (1 << 30) + 1
			},
			want: "CONVERSATION_MAX_BYTES",
		},
		{
			name: "unbounded media verification concurrency",
			mutate: func(cfg *Config) {
				cfg.Media.VerificationConcurrency = 1000
			},
			want: "VERIFY_CONCURRENCY",
		},
		{
			name: "reservation shorter than client upload",
			mutate: func(cfg *Config) {
				cfg.Media.PendingTTL = 10 * time.Second
			},
			want: "PENDING_TTL",
		},
		{
			name: "outer write timeout cuts off completion",
			mutate: func(cfg *Config) {
				cfg.HTTPWriteTimeout = cfg.Media.CompletionTimeout
			},
			want: "HTTP_WRITE_TIMEOUT",
		},
		{
			name: "user bytes below a single attachment",
			mutate: func(cfg *Config) {
				cfg.Media.PendingUserMaxBytes = 32 << 20
			},
			want: "PENDING_USER_MAX_BYTES",
		},
		{
			name: "unbounded cleanup batch",
			mutate: func(cfg *Config) {
				cfg.Media.CleanupBatchSize = 10_000
			},
			want: "CLEANUP_BATCH_SIZE",
		},
		{
			name: "stored bytes below pending reservations",
			mutate: func(cfg *Config) {
				cfg.Media.StoredUserMaxBytes = 64 << 20
			},
			want: "STORED_USER_MAX_BYTES",
		},
		{
			name: "unbounded stored conversation count",
			mutate: func(cfg *Config) {
				cfg.Media.StoredConversationMaxCount = 2_000_000
			},
			want: "stored object counts",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg := validProductionConfig()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error=%v, want %q", err, test.want)
			}
		})
	}
}

func validProductionConfig() Config {
	return Config{
		Environment:      "production",
		HTTPWriteTimeout: 135 * time.Second,
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
		Media: MediaConfig{
			ConversationMaxBytes: 1 << 30, ProfileMaxBytes: 20 << 20,
			CompletionTimeout: 2 * time.Minute, VerificationConcurrency: 4,
			PendingTTL: 5 * time.Minute, PendingUserMaxCount: 8,
			PendingUserMaxBytes: 2 << 30, PendingConversationMaxCount: 32,
			PendingConversationMaxBytes: 8 << 30,
			StoredUserMaxCount:          2_000, StoredUserMaxBytes: 20 << 30,
			StoredConversationMaxCount: 10_000, StoredConversationMaxBytes: 100 << 30,
			CleanupInterval: 30 * time.Second, CleanupBatchSize: 500,
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
			Provider: "smtp", SMTPAddress: "smtp.email.us-phoenix-1.oci.oraclecloud.com:465",
			SMTPUsername: "smtp-user", SMTPPassword: "smtp-password",
			SMTPServerName:     "smtp.email.us-phoenix-1.oci.oraclecloud.com",
			SMTPTransport:      "implicit_tls",
			From:               "Clixor <no-reply@mail.atlanteanz.com>",
			QueueEncryptionKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32))),
			QueueBatchSize:     50, QueueWorkerConcurrency: 4, QueueMaxAttempts: 8,
			QueueBaseDelay: 5 * time.Second, QueueMaxDelay: 30 * time.Minute,
			QueueDeliveredRetention:  24 * time.Hour,
			QueueDeadLetterRetention: 30 * 24 * time.Hour,
			PasswordResetSecret:      strings.Repeat("r", 48),
			PasswordResetTTL:         10 * time.Minute, PasswordResetLength: 8,
			PasswordResetMaxAttempts: 5,
		},
		APNS: APNSConfig{
			TeamID: "team", KeyID: "key", BundleID: "app.bundle",
			PrivateKeyFile: "/run/secrets/AuthKey.p8", Environment: "production",
		},
	}
}
