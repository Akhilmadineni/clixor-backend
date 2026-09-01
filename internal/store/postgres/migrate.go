package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(4318675309)`); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(4318675309)`)
	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
			)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	if err := validateConversationMemberBridgePreflight(ctx, conn); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	versions := make(map[int64]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		versionText := strings.SplitN(entry.Name(), "_", 2)[0]
		version, err := strconv.ParseInt(versionText, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid migration name %q", entry.Name())
		}
		if previous, exists := versions[version]; exists {
			return fmt.Errorf("duplicate migration version %d in %q and %q", version, previous, entry.Name())
		}
		versions[version] = entry.Name()
		var applied bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, string(sql)); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, version)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// validateConversationMemberBridgePreflight prevents a version-only migration
// runner from treating an older, already-recorded copy of migration 16 as if it
// contained the rolling-write bridge added later. Migration 17 repeats the
// equivalent SQL gate for runners other than this package. A database which
// stopped after the amended migration 16 may safely resume, but a database that
// recorded the old migration must be restored/reviewed instead of guessing at
// membership identities that may already have been deleted.
type migrationQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func validateConversationMemberBridgePreflight(ctx context.Context, conn migrationQueryer) error {
	var migration16Applied, migration20Applied bool
	if err := conn.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=16),
		       EXISTS(SELECT 1 FROM schema_migrations WHERE version=20)`,
	).Scan(&migration16Applied, &migration20Applied); err != nil {
		return fmt.Errorf("check conversation-member bridge migration ledger: %w", err)
	}
	if migration20Applied && !migration16Applied {
		return fmt.Errorf("unsafe migration ledger: migration 20 is recorded without prerequisite migration 16")
	}
	if !migration16Applied {
		return nil
	}

	var bridgeReady bool
	if err := conn.QueryRow(ctx, `
		SELECT
			EXISTS (
				SELECT 1
				FROM pg_trigger trigger
				JOIN pg_proc function ON function.oid=trigger.tgfoid
				WHERE trigger.tgrelid=to_regclass('conversation_members')
				  AND trigger.tgname='conversation_members_bridge_identity_insert'
				  AND NOT trigger.tgisinternal AND trigger.tgenabled<>'D'
				  AND function.proname='reserve_conversation_member_bridge_identity'
			) AND EXISTS (
				SELECT 1
				FROM pg_trigger trigger
				JOIN pg_proc function ON function.oid=trigger.tgfoid
				WHERE trigger.tgrelid=to_regclass('conversation_members')
				  AND trigger.tgname='conversation_members_bridge_tombstone_delete'
				  AND NOT trigger.tgisinternal AND trigger.tgenabled<>'D'
				  AND function.proname='preserve_conversation_member_bridge_tombstone'
			)`,
	).Scan(&bridgeReady); err != nil {
		return fmt.Errorf("inspect conversation-member compatibility bridge: %w", err)
	}
	if !bridgeReady {
		return fmt.Errorf("unsafe migration ledger: migration 16 is recorded without the required conversation-member compatibility bridge; restore the pre-rollout snapshot or run an explicitly reviewed repair")
	}

	var missingMappings bool
	if err := conn.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM conversation_members member
			WHERE NOT EXISTS (
				SELECT 1 FROM conversation_member_local_ids mapping
				WHERE mapping.conversation_id=member.conversation_id
				  AND mapping.user_id=member.user_id
			)
		)`,
	).Scan(&missingMappings); err != nil {
		return fmt.Errorf("validate conversation-member compatibility bridge: %w", err)
	}
	if missingMappings {
		return fmt.Errorf("unsafe migration ledger: migration 16 compatibility bridge has active members without immutable local identities")
	}
	return nil
}

func ValidateMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	var required int64
	versions := make(map[int64]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		versionText := strings.SplitN(entry.Name(), "_", 2)[0]
		version, err := strconv.ParseInt(versionText, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid migration name %q", entry.Name())
		}
		if previous, exists := versions[version]; exists {
			return fmt.Errorf("duplicate migration version %d in %q and %q", version, previous, entry.Name())
		}
		versions[version] = entry.Name()
		if version > required {
			required = version
		}
	}
	var applied bool
	err = pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, required).Scan(&applied)
	if err != nil {
		return fmt.Errorf("check schema migration %d: %w", required, err)
	}
	if !applied {
		return fmt.Errorf("database schema migration %d has not been applied", required)
	}
	if err := validateConversationMemberBridgePreflight(ctx, pool); err != nil {
		return fmt.Errorf("validate migration compatibility bridge: %w", err)
	}
	return nil
}
