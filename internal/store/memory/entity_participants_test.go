package memory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPutEntityRejectsRemovedParticipantButKeepsHistoricalRecordReadable(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	owner, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	ownerLocal, memberLocal := uuid.New(), uuid.New()
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: owner.ID, MemberIDs: []uuid.UUID{member.ID},
		Metadata: json.RawMessage(`{"members":[{"id":"` + ownerLocal.String() + `","backendUserId":"` + owner.ID.String() + `"},{"id":"` + memberLocal.String() + `","backendUserId":"` + member.ID.String() + `"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	oldID := uuid.New()
	oldPayload := json.RawMessage(`{"paidBy":"` + ownerLocal.String() + `","splitBetween":["` + ownerLocal.String() + `","` + memberLocal.String() + `"]}`)
	if _, err := persistence.PutEntity(ctx, domain.Entity{ConversationID: conversation.ID, Kind: "expense", ID: oldID, Payload: oldPayload, CreatedBy: owner.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if err := persistence.RemoveConversationMember(ctx, conversation.ID, owner.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.PutEntity(ctx, domain.Entity{ConversationID: conversation.ID, Kind: "expense", ID: uuid.New(), Payload: oldPayload, CreatedBy: owner.ID}, nil); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("removed participant write returned %v, want invalid", err)
	}
	history, err := persistence.ListEntities(ctx, conversation.ID, owner.ID, "expense", time.Time{}, 20)
	if err != nil || len(history) != 1 || history[0].ID != oldID {
		t.Fatalf("historical entity lost: %+v err=%v", history, err)
	}
}
