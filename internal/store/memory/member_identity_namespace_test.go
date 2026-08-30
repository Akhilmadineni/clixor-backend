package memory

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestMembershipPathsRejectBackendUUIDReservedAsAnotherLocalID(t *testing.T) {
	t.Parallel()
	type fixture struct {
		persistence  *Store
		owner        domain.User
		joining      domain.User
		conversation domain.Conversation
	}
	newFixture := func(t *testing.T) fixture {
		t.Helper()
		ctx := context.Background()
		persistence := New()
		joining, err := persistence.CreateUser(ctx, store.CreateUserParams{
			Email: uuid.NewString() + "@example.com", Phone: "+1312555" + time.Now().Format("0405"),
		})
		if err != nil {
			t.Fatal(err)
		}
		owner, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@example.com"})
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
		if got := persistence.memberLocalIDs[conversation.ID][owner.ID]; got != joining.ID {
			t.Fatalf("fixture did not reserve joining backend UUID: got %s want %s", got, joining.ID)
		}
		return fixture{persistence: persistence, owner: owner, joining: joining, conversation: conversation}
	}
	assertRejectedAndUnambiguous := func(t *testing.T, f fixture) {
		t.Helper()
		ctx := context.Background()
		if _, err := f.persistence.Conversation(ctx, f.conversation.ID, f.joining.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("rejected user gained conversation access: %v", err)
		}
		members, err := f.persistence.ListConversationMembers(ctx, f.conversation.ID, f.owner.ID)
		if err != nil || len(members) != 1 || members[0].UserID != f.owner.ID {
			t.Fatalf("ambiguous roster committed: members=%+v err=%v", members, err)
		}
		payload := json.RawMessage(`{"paidBy":"` + f.joining.ID.String() +
			`","splitBetween":["` + f.joining.ID.String() + `"]}`)
		if _, err := f.persistence.PutEntity(ctx, domain.Entity{
			ConversationID: f.conversation.ID, Kind: "expense", ID: uuid.New(),
			Payload: payload, CreatedBy: f.owner.ID,
		}, nil); err != nil {
			t.Fatalf("reserved UUID stopped identifying its sole financial owner: %v", err)
		}
	}

	t.Run("direct add", func(t *testing.T) {
		f := newFixture(t)
		err := f.persistence.AddConversationMember(
			context.Background(), f.conversation.ID, f.owner.ID, f.joining.ID, "member",
		)
		if !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("direct add returned %v, want conflict", err)
		}
		assertRejectedAndUnambiguous(t, f)
	})

	t.Run("phone invite claim", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		if err := f.persistence.CreateConversationInvites(
			ctx, f.conversation.ID, f.owner.ID, []string{f.joining.Phone},
		); err != nil {
			t.Fatal(err)
		}
		if _, err := f.persistence.ClaimConversationInvites(ctx, f.joining.ID, f.joining.Phone); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("phone claim returned %v, want conflict", err)
		}
		if _, pending := f.persistence.invites[f.conversation.ID][f.joining.Phone]; !pending {
			t.Fatal("rejected phone claim consumed its invitation")
		}
		assertRejectedAndUnambiguous(t, f)
	})

	t.Run("link invite acceptance", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		tokenHash := sha256.Sum256([]byte(uuid.NewString()))
		invite, err := f.persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
			ConversationID: f.conversation.ID, ActorID: f.owner.ID, TokenHash: tokenHash[:],
			ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.persistence.AcceptConversationInvite(ctx, tokenHash[:], f.joining.ID); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("link acceptance returned %v, want conflict", err)
		}
		if stored := f.persistence.inviteLinks[string(tokenHash[:])]; stored.ID != invite.ID || stored.Uses != 0 {
			t.Fatalf("rejected link acceptance consumed an invite use: %+v", stored)
		}
		assertRejectedAndUnambiguous(t, f)
	})

	t.Run("historical member rejoin", func(t *testing.T) {
		f := newFixture(t)
		returningLocalID := uuid.New()
		f.persistence.mu.Lock()
		f.persistence.memberLocalIDs[f.conversation.ID][f.joining.ID] = returningLocalID
		f.persistence.memberTombstones[f.conversation.ID][f.joining.ID] = store.ConversationMemberTombstone{
			UserID: f.joining.ID, LocalID: returningLocalID,
		}
		f.persistence.mu.Unlock()
		err := f.persistence.AddConversationMember(
			context.Background(), f.conversation.ID, f.owner.ID, f.joining.ID, "member",
		)
		if !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("rejoin returned %v, want conflict", err)
		}
		if tombstone := f.persistence.memberTombstones[f.conversation.ID][f.joining.ID]; tombstone.LocalID != returningLocalID {
			t.Fatalf("rejected rejoin changed history: %+v", tombstone)
		}
		assertRejectedAndUnambiguous(t, f)
	})
}
