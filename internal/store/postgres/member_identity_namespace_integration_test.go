package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresMembershipPathsRejectBackendUUIDReservedAsAnotherLocalID(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	type fixture struct {
		owner        domain.User
		joining      domain.User
		conversation domain.Conversation
	}
	newFixture := func(t *testing.T) fixture {
		t.Helper()
		phone := "+1312" + strconv.FormatInt(time.Now().UnixNano()%10_000_000, 10)
		joining, err := persistence.CreateUser(ctx, store.CreateUserParams{
			Email: uuid.NewString() + "@example.com", Phone: phone, PasswordHash: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		owner, err := persistence.CreateUser(ctx, store.CreateUserParams{
			Email: uuid.NewString() + "@example.com", PasswordHash: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
			Kind: "group", CreatedBy: owner.ID,
			Metadata: json.RawMessage(`{"members":[{"id":"` + joining.ID.String() +
				`","backendUserId":"` + owner.ID.String() + `"}]}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		var localID uuid.UUID
		if err := persistence.pool.QueryRow(ctx, `
			SELECT local_id FROM conversation_member_local_ids
			WHERE conversation_id=$1 AND user_id=$2`, conversation.ID, owner.ID,
		).Scan(&localID); err != nil || localID != joining.ID {
			t.Fatalf("fixture reservation got=%s err=%v want=%s", localID, err, joining.ID)
		}
		return fixture{owner: owner, joining: joining, conversation: conversation}
	}
	assertRejectedAndUnambiguous := func(t *testing.T, f fixture) {
		t.Helper()
		if _, err := persistence.Conversation(ctx, f.conversation.ID, f.joining.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("rejected user gained access: %v", err)
		}
		members, err := persistence.ListConversationMembers(ctx, f.conversation.ID, f.owner.ID)
		if err != nil || len(members) != 1 || members[0].UserID != f.owner.ID {
			t.Fatalf("ambiguous roster committed: members=%+v err=%v", members, err)
		}
		payload := json.RawMessage(`{"paidBy":"` + f.joining.ID.String() +
			`","splitBetween":["` + f.joining.ID.String() + `"]}`)
		if _, err := persistence.PutEntity(ctx, domain.Entity{
			ConversationID: f.conversation.ID, Kind: "expense", ID: uuid.New(),
			Payload: payload, CreatedBy: f.owner.ID,
		}, nil); err != nil {
			t.Fatalf("reserved UUID stopped identifying its sole financial owner: %v", err)
		}
	}

	t.Run("direct add", func(t *testing.T) {
		f := newFixture(t)
		if err := persistence.AddConversationMember(
			ctx, f.conversation.ID, f.owner.ID, f.joining.ID, "member",
		); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("direct add returned %v, want conflict", err)
		}
		assertRejectedAndUnambiguous(t, f)
	})

	t.Run("phone invite claim", func(t *testing.T) {
		f := newFixture(t)
		if err := persistence.CreateConversationInvites(
			ctx, f.conversation.ID, f.owner.ID, []string{f.joining.Phone},
		); err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.ClaimConversationInvites(ctx, f.joining.ID, f.joining.Phone); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("phone claim returned %v, want conflict", err)
		}
		var pending bool
		if err := persistence.pool.QueryRow(ctx, `
			SELECT claimed_at IS NULL FROM conversation_invites
			WHERE conversation_id=$1 AND phone=$2`, f.conversation.ID, f.joining.Phone,
		).Scan(&pending); err != nil || !pending {
			t.Fatalf("rejected phone claim was consumed: pending=%t err=%v", pending, err)
		}
		assertRejectedAndUnambiguous(t, f)
	})

	t.Run("link invite acceptance", func(t *testing.T) {
		f := newFixture(t)
		tokenHash := sha256.Sum256([]byte(uuid.NewString()))
		invite, err := persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
			ConversationID: f.conversation.ID, ActorID: f.owner.ID, TokenHash: tokenHash[:],
			ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.AcceptConversationInvite(ctx, tokenHash[:], f.joining.ID); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("link acceptance returned %v, want conflict", err)
		}
		var uses int
		if err := persistence.pool.QueryRow(ctx, `
			SELECT uses FROM conversation_invite_links WHERE id=$1`, invite.ID,
		).Scan(&uses); err != nil || uses != 0 {
			t.Fatalf("rejected link acceptance consumed uses=%d err=%v", uses, err)
		}
		assertRejectedAndUnambiguous(t, f)
	})

	t.Run("historical member rejoin", func(t *testing.T) {
		f := newFixture(t)
		returningLocalID := uuid.New()
		if _, err := persistence.pool.Exec(ctx, `
			INSERT INTO conversation_member_local_ids(conversation_id,user_id,local_id)
			VALUES($1,$2,$3)`, f.conversation.ID, f.joining.ID, returningLocalID); err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.pool.Exec(ctx, `
			INSERT INTO conversation_member_tombstones(conversation_id,user_id,local_id)
			VALUES($1,$2,$3)`, f.conversation.ID, f.joining.ID, returningLocalID); err != nil {
			t.Fatal(err)
		}
		if err := persistence.AddConversationMember(
			ctx, f.conversation.ID, f.owner.ID, f.joining.ID, "member",
		); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("rejoin returned %v, want conflict", err)
		}
		var tombstoneLocalID uuid.UUID
		if err := persistence.pool.QueryRow(ctx, `
			SELECT local_id FROM conversation_member_tombstones
			WHERE conversation_id=$1 AND user_id=$2`, f.conversation.ID, f.joining.ID,
		).Scan(&tombstoneLocalID); err != nil || tombstoneLocalID != returningLocalID {
			t.Fatalf("rejected rejoin changed history: local=%s err=%v", tombstoneLocalID, err)
		}
		assertRejectedAndUnambiguous(t, f)
	})
}

func TestPostgresIdentityNamespaceMigrationLockFencesOldWritersAndPreservesHistory(t *testing.T) {
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

	joining, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", PasswordHash: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", PasswordHash: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: owner.ID,
		Metadata: json.RawMessage(`{"members":[{"id":"` + joining.ID.String() +
			`","backendUserId":"` + owner.ID.String() + `"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	historical, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", PasswordHash: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	historicalLocal := uuid.New()
	if _, err := persistence.pool.Exec(ctx, `
		INSERT INTO conversation_member_local_ids(conversation_id,user_id,local_id)
		VALUES($1,$2,$3)`, conversation.ID, historical.ID, historicalLocal); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.pool.Exec(ctx, `
		INSERT INTO conversation_member_tombstones(conversation_id,user_id,local_id)
		VALUES($1,$2,$3)`, conversation.ID, historical.ID, historicalLocal); err != nil {
		t.Fatal(err)
	}

	snapshot := func(t *testing.T) string {
		t.Helper()
		var mappings, tombstones string
		if err := persistence.pool.QueryRow(ctx, `
			SELECT COALESCE(string_agg(user_id::text||':'||local_id::text,',' ORDER BY user_id),'')
			FROM conversation_member_local_ids WHERE conversation_id=$1`, conversation.ID,
		).Scan(&mappings); err != nil {
			t.Fatal(err)
		}
		if err := persistence.pool.QueryRow(ctx, `
			SELECT COALESCE(string_agg(user_id::text||':'||local_id::text,',' ORDER BY user_id),'')
			FROM conversation_member_tombstones WHERE conversation_id=$1`, conversation.ID,
		).Scan(&tombstones); err != nil {
			t.Fatal(err)
		}
		return mappings + "|" + tombstones
	}
	historyBefore := snapshot(t)

	// This is the lock acquired by migration 000018 before its first validation.
	// A write from a previous binary uses ROW EXCLUSIVE and must remain blocked.
	migrationTx, err := persistence.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationTx.Rollback(ctx)
	if _, err := migrationTx.Exec(ctx, `
		LOCK TABLE conversation_members, conversation_member_local_ids
		IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	writerResult := make(chan error, 1)
	go func() {
		_, writeErr := persistence.pool.Exec(ctx, `
			INSERT INTO conversation_members(conversation_id,user_id,role,joined_at)
			VALUES($1,$2,'member',now())`, conversation.ID, joining.ID)
		writerResult <- writeErr
	}()
	select {
	case writeErr := <-writerResult:
		t.Fatalf("old writer bypassed migration lock: %v", writeErr)
	case <-time.After(150 * time.Millisecond):
		// Expected: writer is fenced until the migration transaction commits.
	}
	if err := migrationTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	writeErr := <-writerResult
	var pgErr *pgconn.PgError
	if !errors.As(writeErr, &pgErr) || pgErr.ConstraintName != "conversation_member_backend_local_disjoint" {
		t.Fatalf("writer resumed without namespace enforcement: %v", writeErr)
	}
	var admitted bool
	if err := persistence.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2)`,
		conversation.ID, joining.ID).Scan(&admitted); err != nil || admitted {
		t.Fatalf("rejected writer mutated membership: admitted=%t err=%v", admitted, err)
	}
	if got := snapshot(t); got != historyBefore {
		t.Fatalf("rejected writer changed history:\nbefore %s\nafter  %s", historyBefore, got)
	}

	// A trigger failure aborts its transaction completely; rollback must retain
	// the exact historical mapping and tombstone bytes.
	failingTx, err := persistence.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, failure := failingTx.Exec(ctx, `
		UPDATE conversation_member_local_ids SET local_id=$3
		WHERE conversation_id=$1 AND user_id=$2`, conversation.ID, historical.ID, uuid.New())
	if failure == nil {
		t.Fatal("immutable historical mapping update unexpectedly succeeded")
	}
	if err := failingTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got := snapshot(t); got != historyBefore {
		t.Fatalf("failed transaction changed history:\nbefore %s\nafter  %s", historyBefore, got)
	}

	// The migration runner must skip the already-recorded version without
	// recreating triggers or rewriting any historical identity.
	if err := Migrate(ctx, persistence.pool); err != nil {
		t.Fatalf("idempotent migration rerun: %v", err)
	}
	if got := snapshot(t); got != historyBefore {
		t.Fatalf("migration rerun changed history:\nbefore %s\nafter  %s", historyBefore, got)
	}
}
