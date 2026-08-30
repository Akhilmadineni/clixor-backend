package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresPutEntityRejectsRemovedParticipantButKeepsHistory(t *testing.T) {
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
	createUser := func() domain.User {
		user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	owner, member := createUser(), createUser()
	ownerLocal, memberLocal := uuid.New(), uuid.New()
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: owner.ID, MemberIDs: []uuid.UUID{member.ID},
		Metadata: json.RawMessage(`{"members":[{"id":"` + ownerLocal.String() + `","backendUserId":"` + owner.ID.String() + `"},{"id":"` + memberLocal.String() + `","backendUserId":"` + member.ID.String() + `"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"paid_by":"` + ownerLocal.String() + `","split_between":["` + ownerLocal.String() + `","` + memberLocal.String() + `"]}`)
	oldID := uuid.New()
	if _, err := persistence.PutEntity(ctx, domain.Entity{ConversationID: conversation.ID, Kind: "expense", ID: oldID, Payload: payload, CreatedBy: owner.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if err := persistence.RemoveConversationMember(ctx, conversation.ID, owner.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.PutEntity(ctx, domain.Entity{ConversationID: conversation.ID, Kind: "expense", ID: uuid.New(), Payload: payload, CreatedBy: owner.ID}, nil); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("removed participant write returned %v, want invalid", err)
	}
	history, err := persistence.ListEntities(ctx, conversation.ID, owner.ID, "expense", time.Time{}, 20)
	if err != nil || len(history) != 1 || history[0].ID != oldID {
		t.Fatalf("historical entity lost: %+v err=%v", history, err)
	}
}
