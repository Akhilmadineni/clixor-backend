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

func TestConversationMemberIdentityNamespaceMigrationIsHistorySafe(t *testing.T) {
	raw, err := migrationFiles.ReadFile("migrations/000018_conversation_member_identity_namespace.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"SET LOCAL lock_timeout = '5s'",
		"SET LOCAL statement_timeout = '30s'",
		"LOCK TABLE users IN EXCLUSIVE MODE",
		"LOCK TABLE conversations IN EXCLUSIVE MODE",
		"LOCK TABLE conversation_members, conversation_member_local_ids,\n    conversation_member_tombstones",
		"IN SHARE ROW EXCLUSIVE MODE",
		"INSERT INTO conversation_member_local_ids(conversation_id,user_id,local_id)",
		"FROM conversation_member_tombstones tombstone",
		"mapping.local_id<>tombstone.local_id",
		"reserved.local_id=active.user_id",
		"PERFORM id FROM conversations WHERE id=NEW.conversation_id FOR UPDATE",
		"conversation_member_backend_local_disjoint",
		"BEFORE INSERT ON conversation_members",
		"BEFORE INSERT ON conversation_member_local_ids",
		"conversation member local IDs are immutable",
		"conversation member tombstones are immutable",
		"BEFORE INSERT ON conversation_member_tombstones",
		"BEFORE UPDATE ON conversation_member_tombstones",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("identity-namespace migration is missing %q", required)
		}
	}
	userLockAt := strings.Index(sql, "LOCK TABLE users IN EXCLUSIVE MODE")
	conversationLockAt := strings.Index(sql, "LOCK TABLE conversations IN EXCLUSIVE MODE")
	lockAt := strings.Index(sql, "LOCK TABLE conversation_members, conversation_member_local_ids")
	lockTimeoutAt := strings.Index(sql, "SET LOCAL lock_timeout")
	statementTimeoutAt := strings.Index(sql, "SET LOCAL statement_timeout")
	validationAt := strings.Index(sql, "DO $$")
	triggerAt := strings.Index(sql, "CREATE TRIGGER conversation_members_identity_namespace_insert")
	if lockTimeoutAt < 0 || statementTimeoutAt < 0 || userLockAt < 0 || conversationLockAt < 0 || lockAt < 0 || validationAt < 0 || triggerAt < 0 ||
		lockTimeoutAt > statementTimeoutAt || statementTimeoutAt > userLockAt || userLockAt > conversationLockAt ||
		conversationLockAt > lockAt || lockAt > validationAt || lockAt > triggerAt {
		t.Fatal("identity namespace tables must be write-locked before validation and trigger creation")
	}
	for _, forbidden := range []string{"UPDATE conversation_member_local_ids SET", "ON CONFLICT DO UPDATE"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("identity-namespace migration can remap immutable history via %q", forbidden)
		}
	}
}

func TestImmutableMediaPublicationMigrationIsRollingCompatible(t *testing.T) {
	raw, err := migrationFiles.ReadFile("migrations/000014_media_immutable_publication.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"ADD COLUMN upload_capability_id text",
		"status <> 'ready' OR upload_capability_id IS NULL",
		"VALIDATE CONSTRAINT media_objects_ready_capability_revoked_check",
		"CREATE OR REPLACE FUNCTION cleanup_account_extensions_on_delete()",
		"'published/' || object_key",
		"substring(object_key FROM 11)",
		"upload_valid_until + interval '3 minutes'",
		"'not_before', deletion.not_before",
		"available_at",
		"/ 500 AS batch_number",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("immutable media migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"DROP TABLE", "DROP COLUMN", "ALTER COLUMN object_key",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("immutable media migration contains rolling-incompatible %q", forbidden)
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

func TestMediaReservationMigrationAddsExpiryQuotaAndSchedulingSupport(t *testing.T) {
	raw, err := migrationFiles.ReadFile("migrations/000010_media_reservations.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"media_objects_pending_expiry_check",
		"profile_media_objects_pending_expiry_check",
		"media_objects_pending_owner_idx",
		"media_objects_pending_conversation_idx",
		"media_objects_stored_owner_idx",
		"media_objects_stored_conversation_idx",
		"profile_media_objects_stored_owner_idx",
		"upload_valid_until",
		"verification_lease_token",
		"verification_locked_until",
		"media_objects_verification_lease_check",
		"profile_media_objects_verification_lease_check",
		"media_objects_verification_lease_idx",
		"profile_media_objects_verification_lease_idx",
		"ADD COLUMN available_at",
		"ON outbox_events (available_at, id)",
		"outbox_media_delete_unpublished_idx",
		"topic = 'media.delete'",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("media reservation migration is missing %q", required)
		}
	}
}

func TestOutboxRetentionMigrationHasPartialPublishedIndex(t *testing.T) {
	raw, err := migrationFiles.ReadFile("migrations/000011_outbox_retention.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"outbox_published_retention_idx",
		"ON outbox_events (published_at, id)",
		"WHERE published_at IS NOT NULL",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("outbox retention migration is missing %q", required)
		}
	}
}

func TestMailMigrationStoresOnlyEncryptedPayloadAndCascadesPrivacyState(t *testing.T) {
	raw, err := migrationFiles.ReadFile("migrations/000012_encrypted_mail_delivery.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"CREATE TABLE mail_deliveries",
		"encrypted_payload bytea NOT NULL",
		"ON DELETE CASCADE",
		"mail_deliveries_pending_idx",
		"dead_letter",
		"canceled",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("mail migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"recipient text", "email text", "reset_code", "subject text", "body text",
	} {
		if strings.Contains(strings.ToLower(sql), forbidden) {
			t.Fatalf("mail migration stores plaintext field %q", forbidden)
		}
	}
}

func TestConversationMemberTombstoneMigrationIsStoreOwnedAndCascades(t *testing.T) {
	raw, err := migrationFiles.ReadFile("migrations/000015_conversation_member_tombstones.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{"CREATE TABLE conversation_member_tombstones", "local_id uuid NOT NULL", "ON DELETE CASCADE", "PRIMARY KEY (conversation_id, user_id)"} {
		if !strings.Contains(sql, required) {
			t.Fatalf("tombstone migration is missing %q", required)
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
