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

func TestPostgresMessagingLifecycle(t *testing.T) {
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

	alice, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-alice-" + uuid.NewString() + "@example.com", PasswordHash: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-bob-" + uuid.NewString() + "@example.com", PasswordHash: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: alice.ID, Name: "iPhone", Platform: "ios", CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: device.ID, UserID: bob.ID, Name: "Other iPhone", Platform: "ios", CreatedAt: time.Now(),
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("cross-account device reassignment returned %v, want conflict", err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "direct", CreatedBy: alice.ID, MemberIDs: []uuid.UUID{bob.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	reused, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "direct", CreatedBy: bob.ID, MemberIDs: []uuid.UUID{alice.ID},
	})
	if err != nil || reused.ID != conversation.ID {
		t.Fatalf("direct conversation reuse failed: conversation=%+v err=%v", reused, err)
	}

	params := store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: conversation.ID,
		SenderID: alice.ID, SenderDeviceID: device.ID, ContentType: "text",
		Ciphertext: "ZW5jcnlwdGVk", Envelope: json.RawMessage(`{"protocol":"signal-v1"}`),
	}
	message, recipients, err := persistence.CreateMessage(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, _, err := persistence.CreateMessage(ctx, params)
	if err != nil || duplicate.ID != message.ID || message.Seq != 1 || len(recipients) != 2 {
		t.Fatalf("message idempotency failed: first=%+v duplicate=%+v recipients=%v err=%v",
			message, duplicate, recipients, err)
	}
	messages, err := persistence.ListMessages(ctx, conversation.ID, bob.ID, 0, 100)
	if err != nil || len(messages) != 1 {
		t.Fatalf("message replay failed: messages=%+v err=%v", messages, err)
	}
	if _, err := persistence.UpsertReceipt(ctx, domain.Receipt{
		ConversationID: conversation.ID, UserID: bob.ID, DeliveredSeq: 1, ReadSeq: 1,
	}); err != nil {
		t.Fatal(err)
	}
	receipts, err := persistence.ListReceipts(ctx, conversation.ID, alice.ID)
	if err != nil || len(receipts) != 1 {
		t.Fatalf("receipt replay failed: receipts=%+v err=%v", receipts, err)
	}
	entityID := uuid.New()
	expectedCreate := int64(0)
	if _, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "expense", ID: entityID,
		Payload: json.RawMessage(`{"amount":42.50}`), CreatedBy: alice.ID,
	}, &expectedCreate); err != nil {
		t.Fatal(err)
	}
	expectedDelete := int64(1)
	deleted, err := persistence.DeleteEntity(
		ctx, conversation.ID, alice.ID, "expense", entityID, &expectedDelete,
	)
	if err != nil || deleted.DeletedAt == nil || deleted.Version != 2 {
		t.Fatalf("entity tombstone failed: entity=%+v err=%v", deleted, err)
	}
}
