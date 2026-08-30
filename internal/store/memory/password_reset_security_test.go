package memory

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPasswordResetRevokesSessionsAndClearsEveryPushToken(t *testing.T) {
	persistence := New()
	defer persistence.Close()
	ctx := context.Background()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "reset-security@example.com", PasswordHash: "old-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceIDs := []uuid.UUID{uuid.New(), uuid.New()}
	for _, deviceID := range deviceIDs {
		if _, err := persistence.UpsertDevice(ctx, domain.Device{
			ID: deviceID, UserID: user.ID, Name: "iPhone", Platform: "ios",
			PushToken: "aabbccdd", CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	session := domain.Session{
		ID: uuid.New(), UserID: user.ID, DeviceID: deviceIDs[0],
		RefreshTokenHash: bytes.Repeat([]byte{1}, 32),
		ExpiresAt:        time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	challenge := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: user.ID, CodeHash: bytes.Repeat([]byte{2}, 32),
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreatePasswordResetChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ConsumePasswordResetChallenge(
		ctx, challenge.ID, challenge.CodeHash, "new-hash", 5,
	); err != nil {
		t.Fatal(err)
	}
	active, err := persistence.SessionActive(ctx, session.ID, user.ID, deviceIDs[0])
	if err != nil || active {
		t.Fatalf("reset session active=%v err=%v", active, err)
	}
	devices, err := persistence.ListDevices(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != len(deviceIDs) {
		t.Fatalf("devices=%d, want %d", len(devices), len(deviceIDs))
	}
	for _, device := range devices {
		if device.PushToken != "" {
			t.Fatalf("device %s retained push token after reset", device.ID)
		}
	}
}
