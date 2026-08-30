package postgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresPushTokenOwnershipIsTransactionalAndUnique(t *testing.T) {
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
	first, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-push-first-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-push-second-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	firstDeviceID, secondDeviceID := uuid.New(), uuid.New()
	token := "aabbccddeeff0011"
	var workers sync.WaitGroup
	workers.Add(2)
	for _, input := range []struct {
		userID, deviceID uuid.UUID
		token            string
	}{{first.ID, firstDeviceID, "AABBCCDDEEFF0011"}, {second.ID, secondDeviceID, token}} {
		input := input
		go func() {
			defer workers.Done()
			if _, upsertErr := persistence.UpsertDevice(ctx, domain.Device{
				ID: input.deviceID, UserID: input.userID, Name: "iPhone",
				Platform: "ios", PushToken: input.token,
			}); upsertErr != nil {
				t.Errorf("upsert device: %v", upsertErr)
			}
		}()
	}
	workers.Wait()
	owners := 0
	var tokenOwner domain.Device
	var conflictingDeviceID uuid.UUID
	for _, input := range []struct {
		userID, deviceID uuid.UUID
	}{{first.ID, firstDeviceID}, {second.ID, secondDeviceID}} {
		device, err := persistence.Device(ctx, input.userID, input.deviceID)
		if err != nil {
			t.Fatal(err)
		}
		if device.PushToken == token {
			owners++
			tokenOwner = device
		} else {
			conflictingDeviceID = device.ID
		}
	}
	if owners != 1 {
		t.Fatalf("push token owners = %d, want exactly one", owners)
	}

	if _, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: conflictingDeviceID, UserID: tokenOwner.UserID, Name: "Conflict", Platform: "ios",
		PushToken: tokenOwner.PushToken,
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("cross-account device upsert returned %v, want conflict", err)
	}
	unchanged, err := persistence.Device(ctx, tokenOwner.UserID, tokenOwner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.PushToken != tokenOwner.PushToken {
		t.Fatalf("failed transaction cleared previous token owner: %q", unchanged.PushToken)
	}
}
