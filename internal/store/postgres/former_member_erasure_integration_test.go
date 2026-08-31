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
)

func TestPostgresDeleteAccountErasesFormerMemberConversationHistory(t *testing.T) {
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
	deleted, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email:       "pg-former-" + uuid.NewString() + "@example.com",
		DisplayName: "Former Person",
	})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err = persistence.UpdateUserProfile(ctx, deleted.ID,
		json.RawMessage(`{"username":"@former_person","display_name":"Former Person"}`))
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-former-owner-" + uuid.NewString() + "@example.com", DisplayName: "Remaining",
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := json.RawMessage(`{"audit":{"backendUserId":"` + deleted.ID.String() +
		`","displayName":"Former Person","email":"` + deleted.Email + `","username":"@former_person"}}`)
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: remaining.ID, MemberIDs: []uuid.UUID{deleted.ID}, Metadata: metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	entityID := uuid.New()
	if _, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "note", ID: entityID, CreatedBy: deleted.ID,
		Payload: json.RawMessage(`{"createdBy":"` + deleted.ID.String() +
			`","creatorName":"Former Person","email":"` + deleted.Email + `","amount":4.25}`),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := persistence.RemoveConversationMember(ctx, conversation.ID, remaining.ID, deleted.ID); err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}
	after, err := persistence.Conversation(ctx, conversation.ID, remaining.ID)
	if err != nil {
		t.Fatal(err)
	}
	entities, err := persistence.ListEntities(ctx, conversation.ID, remaining.ID, "note", time.Time{}, 10)
	if err != nil || len(entities) != 1 || entities[0].ID != entityID {
		t.Fatalf("former-member entity missing: entities=%+v err=%v", entities, err)
	}
	for label, raw := range map[string][]byte{"metadata": after.Metadata, "entity": entities[0].Payload} {
		text := strings.ToLower(string(raw))
		for _, forbidden := range []string{"former person", strings.ToLower(deleted.Email), "@former_person"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s retained %q: %s", label, forbidden, raw)
			}
		}
		if !strings.Contains(text, deleted.ID.String()) {
			t.Fatalf("%s removed shared tombstone id: %s", label, raw)
		}
	}
}
