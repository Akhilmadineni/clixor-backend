package postgres

import (
	"context"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
)

func TestEmbeddedMigrationVersionsAreUnique(t *testing.T) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	versions := make(map[int64]string)
	var maximum int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := strconv.ParseInt(strings.SplitN(entry.Name(), "_", 2)[0], 10, 64)
		if err != nil {
			t.Fatalf("invalid migration name %q: %v", entry.Name(), err)
		}
		if previous, exists := versions[version]; exists {
			t.Fatalf("duplicate migration version %d in %q and %q", version, previous, entry.Name())
		}
		versions[version] = entry.Name()
		if version > maximum {
			maximum = version
		}
	}
	for want := int64(1); want <= maximum; want++ {
		if _, exists := versions[want]; !exists {
			t.Fatalf("missing migration version %d", want)
		}
	}
}

func TestPushHardeningMigrationIsRollingCompatible(t *testing.T) {
	raw, err := migrationFiles.ReadFile("migrations/000009_push_delivery_hardening.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	if strings.Contains(sql, "devices_push_token_unique") || strings.Contains(sql, "LOCK TABLE devices") {
		t.Fatal("migration 9 must remain compatible with production-05b device writes")
	}
	for _, required := range []string{
		"UNIQUE (outbox_event_id, device_id)",
		"status IN ('pending', 'delivered', 'invalid_token', 'dead_letter', 'canceled')",
		"push_deliveries_pending_idx",
		"migration 12",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("push delivery migration is missing %q", required)
		}
	}
}

func TestPushTokenUniquenessMigrationIsCoordinatedAndDeterministic(t *testing.T) {
	raw, err := migrationFiles.ReadFile("migrations/000013_push_token_uniqueness.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"LOCK TABLE devices IN ACCESS EXCLUSIVE MODE",
		"lower(btrim(push_token))",
		"last_seen_at DESC NULLS LAST",
		"created_at DESC",
		"devices_push_token_unique",
		"WHERE push_token <> ''",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("push-token uniqueness migration is missing %q", required)
		}
	}
}

func TestProfileMediaMigrationCleansExtensionsForLegacyAccountDeletion(t *testing.T) {
	raw, err := migrationFiles.ReadFile("migrations/000008_profile_media.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"users_cleanup_account_extensions_on_delete",
		"OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL",
		"UPDATE conversation_invite_links",
		"DELETE FROM password_reset_challenges",
		"DELETE FROM profile_media_objects",
		"'media.delete'",
		"jsonb_build_object('object_keys', object_keys)",
		"/ 500 AS batch_number",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("profile media migration is missing legacy-delete cleanup %q", required)
		}
	}
}

func TestPostgresRetentionPruneRejectsUnboundedLimitsBeforeQuery(t *testing.T) {
	persistence := &Store{}
	for _, limit := range []int{0, -1, store.MaxRetentionPruneBatchSize + 1} {
		if _, err := persistence.PrunePushDeliveries(
			context.Background(), time.Now(), time.Now(), limit,
		); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("push prune limit %d returned %v", limit, err)
		}
		if _, err := persistence.PrunePublishedOutbox(
			context.Background(), time.Now(), limit,
		); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("outbox prune limit %d returned %v", limit, err)
		}
	}
}
