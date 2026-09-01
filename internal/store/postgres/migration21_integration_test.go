package postgres

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestPostgresMigration21ScrubsLegacyPushAndSealsInvariants(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "migration21-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: user.ID, Name: "migration", Platform: "ios",
		PushToken: "migration21-token-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	member, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "migration21-member-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID, MemberIDs: []uuid.UUID{member.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := persistence.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		ALTER TABLE outbox_events DROP CONSTRAINT IF EXISTS outbox_events_topic_domain_check;
		DROP INDEX IF EXISTS outbox_account_erasure_idx;
		DROP INDEX IF EXISTS conversation_member_tombstones_user_idx;
		DROP INDEX IF EXISTS conversation_members_single_owner_idx;`); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(conversation)
	var outboxID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload)
		VALUES('conversation.created',$1,$2) RETURNING id`, conversation.ID, payload,
	).Scan(&outboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO push_deliveries(
			outbox_event_id,device_id,title,body,kind,conversation_id,entity_id,notification_id
		) VALUES($1,$2,'Private title','Private body','expense',$3,$4,$5)`,
		outboxID, device.ID, conversation.ID, uuid.New(), uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	raw, err := migrationFiles.ReadFile("migrations/000021_outbox_topic_domain.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(raw)); err != nil {
		t.Fatal(err)
	}
	var title, body, kind string
	if err := tx.QueryRow(ctx, `
		SELECT title,body,kind FROM push_deliveries
		WHERE outbox_event_id=$1 AND device_id=$2`, outboxID, device.ID,
	).Scan(&title, &body, &kind); err != nil {
		t.Fatal(err)
	}
	if title != "Clixor" || body != "You have new activity. Open the app to view it." || kind != "activity" {
		t.Fatalf("legacy push was not genericized: title=%q body=%q kind=%q", title, body, kind)
	}
	for _, index := range []string{
		"outbox_account_erasure_idx",
		"conversation_member_tombstones_user_idx",
		"conversation_members_single_owner_idx",
	} {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, index).Scan(&exists); err != nil || !exists {
			t.Fatalf("migration index %s missing: exists=%t err=%v", index, exists, err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload)
		VALUES('conversation.updated',$1,$2)`, conversation.ID, payload); err != nil {
		t.Fatalf("sealed domain rejected conversation.updated: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE conversation_members SET role='owner'
		WHERE conversation_id=$1 AND user_id=$2`, conversation.ID, member.ID); err == nil {
		t.Fatal("single-owner index accepted a second owner")
	}
}

func TestPostgresMigration21RejectsEveryOwnershipDriftShape(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	raw, err := migrationFiles.ReadFile("migrations/000021_outbox_topic_domain.sql")
	if err != nil {
		t.Fatal(err)
	}
	for name, corrupt := range map[string]func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, uuid.UUID) error{
		"zero owners": func(ctx context.Context, tx pgx.Tx, conversation, owner, _ uuid.UUID) error {
			_, err := tx.Exec(ctx, `
				UPDATE conversation_members SET role='member'
				WHERE conversation_id=$1 AND user_id=$2`, conversation, owner)
			return err
		},
		"multiple owners": func(ctx context.Context, tx pgx.Tx, conversation, _, member uuid.UUID) error {
			_, err := tx.Exec(ctx, `
				UPDATE conversation_members SET role='owner'
				WHERE conversation_id=$1 AND user_id=$2`, conversation, member)
			return err
		},
		"created_by mismatch": func(ctx context.Context, tx pgx.Tx, conversation, _, member uuid.UUID) error {
			_, err := tx.Exec(ctx, `
				UPDATE conversations SET created_by=$2 WHERE id=$1`, conversation, member)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			owner, err := persistence.CreateUser(ctx, store.CreateUserParams{
				Email: "migration21-owner-" + uuid.NewString() + "@example.com",
			})
			if err != nil {
				t.Fatal(err)
			}
			member, err := persistence.CreateUser(ctx, store.CreateUserParams{
				Email: "migration21-drift-member-" + uuid.NewString() + "@example.com",
			})
			if err != nil {
				t.Fatal(err)
			}
			conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
				Kind: "group", CreatedBy: owner.ID, MemberIDs: []uuid.UUID{member.ID},
			})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := persistence.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `
				ALTER TABLE outbox_events DROP CONSTRAINT IF EXISTS outbox_events_topic_domain_check;
				DROP INDEX IF EXISTS outbox_account_erasure_idx;
				DROP INDEX IF EXISTS conversation_member_tombstones_user_idx;
				DROP INDEX IF EXISTS conversation_members_single_owner_idx;`); err != nil {
				t.Fatal(err)
			}
			if err := corrupt(ctx, tx, conversation.ID, owner.ID, member.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, string(raw)); err == nil ||
				!strings.Contains(err.Error(), "conversation must have exactly one owner matching created_by") {
				t.Fatalf("ownership drift migration error=%v", err)
			}
		})
	}
}
