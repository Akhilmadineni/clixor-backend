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

func TestDeleteAccountErasesPrivateStateAndQueuesPersonalMediaDeletion(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "erase@example.com", Phone: "+13125550177", DisplayName: "Erase Me",
		PasswordHash: "secret-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err = persistence.UpdateUserProfile(ctx, user.ID, json.RawMessage(`{
		"display_name":"Erase Me","username":"@erase_me","bio":"private"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.LinkExternalIdentity(ctx, "apple", "apple-subject", user.ID, user.Email); err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: user.ID, Name: "Private iPhone", Platform: "ios",
		PushToken: "push-secret", IdentityKey: "identity-secret",
		SignedPreKey: json.RawMessage(`{"key":"signed-secret"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.PutOneTimePreKeys(ctx, device.ID, []domain.OneTimePreKey{{
		KeyID: 1, PublicKey: "one-time-secret",
	}}); err != nil {
		t.Fatal(err)
	}
	session := domain.Session{
		ID: uuid.New(), UserID: user.ID, DeviceID: device.ID,
		RefreshTokenHash: []byte("refresh-secret"), CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := persistence.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	personal, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Private", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	mediaObject := domain.MediaObject{
		ID: uuid.New(), OwnerID: user.ID, ConversationID: personal.ID,
		ObjectKey: "users/erase/private-object", ContentType: "image/jpeg", ByteSize: 42,
	}
	if _, err := persistence.CreateMedia(ctx, mediaObject); err != nil {
		t.Fatal(err)
	}

	if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	for label, lookup := range map[string]func() error{
		"email": func() error { _, err := persistence.UserByEmail(ctx, user.Email); return err },
		"phone": func() error { _, err := persistence.UserByPhone(ctx, user.Phone); return err },
		"apple": func() error {
			_, err := persistence.UserByExternalIdentity(ctx, "apple", "apple-subject")
			return err
		},
	} {
		if err := lookup(); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("%s lookup returned %v, want not found", label, err)
		}
	}
	users, err := persistence.UsersByUsernames(ctx, []string{"@erase_me"})
	if err != nil || len(users) != 0 {
		t.Fatalf("username remained discoverable: users=%+v err=%v", users, err)
	}
	active, err := persistence.SessionActive(ctx, session.ID, user.ID, device.ID)
	if err != nil || active {
		t.Fatalf("session remained active: active=%t err=%v", active, err)
	}
	if _, err := persistence.UserByID(ctx, user.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted user ID returned %v, want not found", err)
	}
	anonymizedDevice, err := persistence.Device(ctx, user.ID, device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if anonymizedDevice.Name != "Deleted device" || anonymizedDevice.PushToken != "" ||
		anonymizedDevice.IdentityKey != "" || len(anonymizedDevice.SignedPreKey) != 0 {
		t.Fatalf("device secrets remained: %+v", anonymizedDevice)
	}
	if _, err := persistence.Media(ctx, mediaObject.ID, user.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("personal media row returned %v, want not found", err)
	}
	events, err := persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var deletion store.MediaDeletePayload
	found := false
	for _, event := range events {
		if event.Topic == "media.delete" {
			found = true
			if err := json.Unmarshal(event.Payload, &deletion); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found || len(deletion.ObjectKeys) != 1 || deletion.ObjectKeys[0] != mediaObject.ObjectKey {
		t.Fatalf("durable media deletion was not queued: %+v", events)
	}
}
