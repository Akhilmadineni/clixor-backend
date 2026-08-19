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

func TestPostgresDeleteAccountTransaction(t *testing.T) {
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

	email := "pg-delete-" + uuid.NewString() + "@example.com"
	deletedUser, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: email, Phone: "+1312" + time.Now().UTC().Format("150405"),
		DisplayName: "Postgres Delete", PasswordHash: "secret-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	deletedUser, err = persistence.UpdateUserProfile(ctx, deletedUser.ID, json.RawMessage(`{
		"display_name":"Postgres Delete","username":"@pg_delete_`+uuid.NewString()[:8]+`"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	remainingUser, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-remaining-" + uuid.NewString() + "@example.com", DisplayName: "Remaining",
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: deletedUser.ID, Name: "Private iPhone", Platform: "ios",
		PushToken: "push-secret", IdentityKey: "identity-secret", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	session := domain.Session{
		ID: uuid.New(), UserID: deletedUser.ID, DeviceID: device.ID,
		RefreshTokenHash: []byte("refresh-secret"), ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	if err := persistence.LinkExternalIdentity(ctx, "apple", uuid.NewString(), deletedUser.ID, email); err != nil {
		t.Fatal(err)
	}
	shared, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Shared", CreatedBy: deletedUser.ID,
		MemberIDs: []uuid.UUID{remainingUser.ID},
		Metadata: json.RawMessage(`{"members":[{"backendUserId":"` + deletedUser.ID.String() +
			`","name":"Postgres Delete","email":"` + email + `"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	expenseID := uuid.New()
	expected := int64(0)
	if _, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: shared.ID, Kind: "expense", ID: expenseID, CreatedBy: deletedUser.ID,
		Payload: json.RawMessage(`{"payer":{"backendUserId":"` + deletedUser.ID.String() +
			`","displayName":"Postgres Delete","email":"` + email + `"}}`),
	}, &expected); err != nil {
		t.Fatal(err)
	}
	personal, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Personal", CreatedBy: deletedUser.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	mediaObject := domain.MediaObject{
		ID: uuid.New(), OwnerID: deletedUser.ID, ConversationID: personal.ID,
		ObjectKey: "pg/private/" + uuid.NewString(), ContentType: "image/jpeg", ByteSize: 7,
	}
	if _, err := persistence.CreateMedia(ctx, mediaObject); err != nil {
		t.Fatal(err)
	}

	if err := persistence.DeleteAccount(ctx, deletedUser.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.UserByEmail(ctx, email); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted email lookup returned %v, want not found", err)
	}
	active, err := persistence.SessionActive(ctx, session.ID, deletedUser.ID, device.ID)
	if err != nil || active {
		t.Fatalf("deleted session remained active: active=%t err=%v", active, err)
	}
	if _, err := persistence.UserByID(ctx, deletedUser.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted user ID returned %v, want not found", err)
	}
	var tombstone domain.User
	err = persistence.pool.QueryRow(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,
		       password_hash,created_at,updated_at
		FROM users WHERE id=$1`, deletedUser.ID,
	).Scan(&tombstone.ID, &tombstone.Email, &tombstone.Phone, &tombstone.DisplayName,
		&tombstone.AvatarURL, &tombstone.Profile, &tombstone.PasswordHash,
		&tombstone.CreatedAt, &tombstone.UpdatedAt)
	if err != nil || tombstone.DisplayName != store.DeletedUserDisplayName ||
		tombstone.Email != "" || tombstone.Phone != "" || tombstone.PasswordHash != "" {
		t.Fatalf("user tombstone is invalid: user=%+v err=%v", tombstone, err)
	}
	retained, err := persistence.Conversation(ctx, shared.ID, remainingUser.ID)
	if err != nil || retained.CreatedBy != remainingUser.ID ||
		string(retained.Metadata) == string(shared.Metadata) {
		t.Fatalf("shared conversation was not transferred/anonymized: conversation=%+v err=%v", retained, err)
	}
	members, err := persistence.ListConversationMembers(ctx, shared.ID, remainingUser.ID)
	if err != nil || len(members) != 1 || members[0].UserID != remainingUser.ID || members[0].Role != "owner" {
		t.Fatalf("shared membership is invalid: members=%+v err=%v", members, err)
	}
	entities, err := persistence.ListEntities(ctx, shared.ID, remainingUser.ID, "expense", time.Time{}, 10)
	if err != nil || len(entities) != 1 || entities[0].Version != 2 {
		t.Fatalf("shared entity history is invalid: entities=%+v err=%v", entities, err)
	}
	if _, err := persistence.Conversation(ctx, personal.ID, remainingUser.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("personal conversation returned %v, want not found", err)
	}
	events, err := persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	foundMediaDelete := false
	for _, event := range events {
		if event.Topic != "media.delete" {
			continue
		}
		var payload store.MediaDeletePayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		foundMediaDelete = len(payload.ObjectKeys) == 1 && payload.ObjectKeys[0] == mediaObject.ObjectKey
	}
	if !foundMediaDelete {
		t.Fatalf("personal MinIO deletion was not queued: %+v", events)
	}
	if _, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: email}); err != nil {
		t.Fatalf("deleted email was not reusable: %v", err)
	}
}
