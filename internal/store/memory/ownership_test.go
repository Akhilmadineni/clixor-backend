package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestTransferOwnershipMovesConversationDeletionAuthority(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	oldOwner, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "old-owner@example.com", DisplayName: "Old Owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	newOwner, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "new-owner@example.com", DisplayName: "New Owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: oldOwner.ID, MemberIDs: []uuid.UUID{newOwner.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.TransferConversationOwnership(
		ctx, conversation.ID, oldOwner.ID, newOwner.ID,
	); err != nil {
		t.Fatal(err)
	}
	if got := persistence.conversations[conversation.ID].CreatedBy; got != newOwner.ID {
		t.Fatalf("conversation authority=%s, want new owner %s", got, newOwner.ID)
	}
	if err := persistence.DeleteConversation(ctx, conversation.ID, oldOwner.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("old owner deletion returned %v, want forbidden", err)
	}
	if err := persistence.DeleteConversation(ctx, conversation.ID, newOwner.ID); err != nil {
		t.Fatalf("new owner could not delete transferred conversation: %v", err)
	}
}
