package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresSecureConversationInviteLifecycle(t *testing.T) {
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

	owner := createPostgresInviteUser(t, ctx, persistence, "owner")
	admin := createPostgresInviteUser(t, ctx, persistence, "admin")
	member := createPostgresInviteUser(t, ctx, persistence, "member")
	firstJoiner := createPostgresInviteUser(t, ctx, persistence, "first")
	secondJoiner := createPostgresInviteUser(t, ctx, persistence, "second")
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Postgres invite", CreatedBy: owner,
		MemberIDs: []uuid.UUID{admin, member},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.AddConversationMember(ctx, conversation.ID, owner, admin, "admin"); err != nil {
		t.Fatal(err)
	}

	rawToken := "cinv_postgres_token_that_must_never_be_persisted"
	tokenHash := sha256.Sum256([]byte(rawToken))
	params := store.CreateConversationInviteParams{
		ConversationID: conversation.ID, ActorID: member, TokenHash: tokenHash[:],
		ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1,
	}
	if _, err := persistence.CreateConversationInvite(ctx, params); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("member create returned %v, want forbidden", err)
	}
	params.ActorID = admin
	invite, err := persistence.CreateConversationInvite(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	var persistedHash []byte
	if err := persistence.pool.QueryRow(ctx, `
		SELECT token_hash FROM conversation_invite_links WHERE id=$1`, invite.ID).Scan(&persistedHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persistedHash, tokenHash[:]) || bytes.Contains(persistedHash, []byte(rawToken)) {
		t.Fatalf("database did not retain only the digest: %x", persistedHash)
	}

	preview, err := persistence.ConversationInvitePreview(ctx, tokenHash[:], firstJoiner)
	if err != nil || preview.InviteID != invite.ID || preview.AlreadyMember {
		t.Fatalf("preview failed: preview=%+v err=%v", preview, err)
	}
	unknown := sha256.Sum256([]byte("unknown-token"))
	if _, err := persistence.ConversationInvitePreview(ctx, unknown[:], firstJoiner); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown token returned %v, want not found", err)
	}
	accepted, err := persistence.AcceptConversationInvite(ctx, tokenHash[:], firstJoiner)
	if err != nil || !accepted.Joined {
		t.Fatalf("first acceptance failed: accepted=%+v err=%v", accepted, err)
	}
	if !bytes.Contains(accepted.Conversation.Metadata, []byte(firstJoiner.String())) {
		t.Fatalf("invite acceptance did not project new ACL member: %s", accepted.Conversation.Metadata)
	}
	if _, err := persistence.pool.Exec(ctx, `
		UPDATE conversations SET metadata='{"members":[]}'::jsonb WHERE id=$1`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	retried, err := persistence.AcceptConversationInvite(ctx, tokenHash[:], firstJoiner)
	if err != nil || retried.Joined {
		t.Fatalf("idempotent acceptance failed: accepted=%+v err=%v", retried, err)
	}
	if !bytes.Contains(retried.Conversation.Metadata, []byte(firstJoiner.String())) {
		t.Fatalf("idempotent acceptance did not heal the ACL projection: %s", retried.Conversation.Metadata)
	}
	var persistedMetadata []byte
	if err := persistence.pool.QueryRow(ctx,
		`SELECT metadata FROM conversations WHERE id=$1`, conversation.ID,
	).Scan(&persistedMetadata); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(persistedMetadata, []byte(firstJoiner.String())) {
		t.Fatalf("healed invite projection was not persisted: %s", persistedMetadata)
	}
	if _, err := persistence.AcceptConversationInvite(ctx, tokenHash[:], secondJoiner); !errors.Is(err, domain.ErrInviteExhausted) {
		t.Fatalf("max-use acceptance returned %v, want exhausted", err)
	}
	if err := persistence.RevokeConversationInvite(ctx, conversation.ID, owner, invite.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.pool.Exec(ctx, `UPDATE conversations SET metadata='{"members":[]}'::jsonb WHERE id=$1`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	retried, err = persistence.AcceptConversationInvite(ctx, tokenHash[:], firstJoiner)
	if err != nil || retried.Joined || !bytes.Contains(retried.Conversation.Metadata, []byte(firstJoiner.String())) {
		t.Fatalf("revoked idempotent retry did not heal: accepted=%+v err=%v", retried, err)
	}

	expiredHash := sha256.Sum256([]byte("expired-postgres-token"))
	expired, err := persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
		ConversationID: conversation.ID, ActorID: owner, TokenHash: expiredHash[:],
		ExpiresAt: time.Now().Add(time.Hour), MaxUses: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.pool.Exec(ctx, `
		UPDATE conversation_invite_links SET expires_at=now()-interval '1 second' WHERE id=$1`, expired.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.AcceptConversationInvite(ctx, expiredHash[:], secondJoiner); !errors.Is(err, domain.ErrInviteExpired) {
		t.Fatalf("expired acceptance returned %v, want expired", err)
	}

	revokedHash := sha256.Sum256([]byte("revoked-postgres-token"))
	revoked, err := persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
		ConversationID: conversation.ID, ActorID: owner, TokenHash: revokedHash[:],
		ExpiresAt: time.Now().Add(time.Hour), MaxUses: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.RevokeConversationInvite(ctx, conversation.ID, member, revoked.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("member revoke returned %v, want forbidden", err)
	}
	if err := persistence.RevokeConversationInvite(ctx, conversation.ID, owner, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ConversationInvitePreview(ctx, revokedHash[:], secondJoiner); !errors.Is(err, domain.ErrInviteRevoked) {
		t.Fatalf("revoked preview returned %v, want revoked", err)
	}

	limitedHash := sha256.Sum256([]byte("atomic-postgres-token"))
	if _, err := persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
		ConversationID: conversation.ID, ActorID: owner, TokenHash: limitedHash[:],
		ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1,
	}); err != nil {
		t.Fatal(err)
	}
	joiners := make([]uuid.UUID, 4)
	for i := range joiners {
		joiners[i] = createPostgresInviteUser(t, ctx, persistence, "atomic")
	}
	start := make(chan struct{})
	results := make(chan error, len(joiners))
	var group sync.WaitGroup
	for _, userID := range joiners {
		group.Add(1)
		go func(userID uuid.UUID) {
			defer group.Done()
			<-start
			accepted, err := persistence.AcceptConversationInvite(ctx, limitedHash[:], userID)
			if err == nil && !accepted.Joined {
				err = errors.New("acceptance succeeded without joining")
			}
			results <- err
		}(userID)
	}
	close(start)
	group.Wait()
	close(results)
	succeeded, exhausted := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, domain.ErrInviteExhausted):
			exhausted++
		default:
			t.Fatalf("unexpected concurrent acceptance error: %v", err)
		}
	}
	if succeeded != 1 || exhausted != len(joiners)-1 {
		t.Fatalf("atomic max use failed: succeeded=%d exhausted=%d", succeeded, exhausted)
	}
}

func createPostgresInviteUser(t *testing.T, ctx context.Context, persistence *Store, label string) uuid.UUID {
	t.Helper()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-invite-" + label + "-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	return user.ID
}
