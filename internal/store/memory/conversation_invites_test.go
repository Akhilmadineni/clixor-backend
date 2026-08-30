package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestConversationInviteLifecycleAndAuthorization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	persistence := New()
	owner := createInviteTestUser(t, persistence, "invite-owner@example.com")
	admin := createInviteTestUser(t, persistence, "invite-admin@example.com")
	member := createInviteTestUser(t, persistence, "invite-member@example.com")
	firstJoiner := createInviteTestUser(t, persistence, "invite-first@example.com")
	secondJoiner := createInviteTestUser(t, persistence, "invite-second@example.com")
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Private trip", CreatedBy: owner,
		MemberIDs: []uuid.UUID{admin, member},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.AddConversationMember(ctx, conversation.ID, owner, admin, "admin"); err != nil {
		t.Fatal(err)
	}

	rawToken := "cinv_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
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
	if invite.CreatedBy != admin || invite.MaxUses != 1 || invite.Uses != 0 {
		t.Fatalf("unexpected invite metadata: %+v", invite)
	}
	if _, rawStored := persistence.inviteLinks[rawToken]; rawStored {
		t.Fatal("raw bearer token was stored")
	}
	if stored, ok := persistence.inviteLinks[string(tokenHash[:])]; !ok || stored.ID != invite.ID {
		t.Fatalf("hashed invite was not stored: invite=%+v present=%t", stored, ok)
	}
	if _, err := persistence.CreateConversationInvite(ctx, params); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate token hash returned %v, want conflict", err)
	}

	preview, err := persistence.ConversationInvitePreview(ctx, tokenHash[:], firstJoiner)
	if err != nil {
		t.Fatal(err)
	}
	if preview.InviteID != invite.ID || preview.Kind != "group" || preview.Title != "Private trip" || preview.AlreadyMember {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	accepted, err := persistence.AcceptConversationInvite(ctx, tokenHash[:], firstJoiner)
	if err != nil || !accepted.Joined || accepted.Conversation.ID != conversation.ID {
		t.Fatalf("first acceptance failed: accepted=%+v err=%v", accepted, err)
	}
	if !bytes.Contains(accepted.Conversation.Metadata, []byte(firstJoiner.String())) {
		t.Fatalf("invite acceptance did not project new ACL member: %s", accepted.Conversation.Metadata)
	}
	// Simulate metadata written by a legacy node after the relational membership
	// was committed. Retrying the same invite must heal the projection without
	// consuming another use.
	persistence.mu.Lock()
	stale := persistence.conversations[conversation.ID]
	stale.Metadata = []byte(`{"members":[]}`)
	persistence.conversations[conversation.ID] = stale
	persistence.mu.Unlock()
	retried, err := persistence.AcceptConversationInvite(ctx, tokenHash[:], firstJoiner)
	if err != nil || retried.Joined {
		t.Fatalf("idempotent acceptance failed: accepted=%+v err=%v", retried, err)
	}
	if !bytes.Contains(retried.Conversation.Metadata, []byte(firstJoiner.String())) {
		t.Fatalf("idempotent acceptance did not heal the ACL projection: %s", retried.Conversation.Metadata)
	}
	persistence.mu.RLock()
	persistedMetadata := append([]byte(nil), persistence.conversations[conversation.ID].Metadata...)
	persistence.mu.RUnlock()
	if !bytes.Contains(persistedMetadata, []byte(firstJoiner.String())) {
		t.Fatalf("healed invite projection was not persisted: %s", persistedMetadata)
	}
	if uses := persistence.inviteLinks[string(tokenHash[:])].Uses; uses != 1 {
		t.Fatalf("idempotent acceptance consumed %d uses, want 1", uses)
	}
	if _, err := persistence.AcceptConversationInvite(ctx, tokenHash[:], secondJoiner); !errors.Is(err, domain.ErrInviteExhausted) {
		t.Fatalf("max-use acceptance returned %v, want exhausted", err)
	}
	unknown := sha256.Sum256([]byte("unknown-high-entropy-token"))
	if _, err := persistence.ConversationInvitePreview(ctx, unknown[:], firstJoiner); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown token returned %v, want not found", err)
	}
	if err := persistence.RevokeConversationInvite(ctx, conversation.ID, member, invite.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("member revoke returned %v, want forbidden", err)
	}
	if err := persistence.RevokeConversationInvite(ctx, conversation.ID, admin, invite.ID); err != nil {
		t.Fatal(err)
	}
	if err := persistence.RevokeConversationInvite(ctx, conversation.ID, admin, invite.ID); err != nil {
		t.Fatalf("idempotent revoke failed: %v", err)
	}
	if _, err := persistence.ConversationInvitePreview(ctx, tokenHash[:], firstJoiner); !errors.Is(err, domain.ErrInviteRevoked) {
		t.Fatalf("revoked preview returned %v, want revoked", err)
	}
}

func TestConversationInviteExpiryAndAtomicMaxUse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	persistence := New()
	owner := createInviteTestUser(t, persistence, "expiry-owner@example.com")
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: owner,
	})
	if err != nil {
		t.Fatal(err)
	}

	expiredHash := sha256.Sum256([]byte("expired-token"))
	expired, err := persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
		ConversationID: conversation.ID, ActorID: owner, TokenHash: expiredHash[:],
		ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredKey := persistence.inviteLinkKeys[expired.ID]
	expired.ExpiresAt = time.Now().Add(-time.Second)
	persistence.inviteLinks[expiredKey] = expired
	joiner := createInviteTestUser(t, persistence, "expired-joiner@example.com")
	if _, err := persistence.AcceptConversationInvite(ctx, expiredHash[:], joiner); !errors.Is(err, domain.ErrInviteExpired) {
		t.Fatalf("expired acceptance returned %v, want expired", err)
	}

	limitedHash := sha256.Sum256([]byte("single-use-token"))
	if _, err := persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
		ConversationID: conversation.ID, ActorID: owner, TokenHash: limitedHash[:],
		ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1,
	}); err != nil {
		t.Fatal(err)
	}
	joiners := make([]uuid.UUID, 8)
	for i := range joiners {
		joiners[i] = createInviteTestUser(t, persistence, "atomic-"+uuid.NewString()+"@example.com")
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

func createInviteTestUser(t *testing.T, persistence *Store, email string) uuid.UUID {
	t.Helper()
	user, err := persistence.CreateUser(context.Background(), store.CreateUserParams{Email: email})
	if err != nil {
		t.Fatal(err)
	}
	return user.ID
}
