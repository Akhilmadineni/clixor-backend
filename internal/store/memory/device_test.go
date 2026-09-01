package memory

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPushTokenOwnershipMovesAtomicallyAcrossAccounts(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	first, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "push-first@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "push-second@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	token := "aabbccdd"
	firstDeviceID, secondDeviceID := uuid.New(), uuid.New()
	var workers sync.WaitGroup
	workers.Add(2)
	for _, input := range []struct {
		userID, deviceID uuid.UUID
		token            string
	}{
		{first.ID, firstDeviceID, "AABBCCDD"},
		{second.ID, secondDeviceID, token},
	} {
		input := input
		go func() {
			defer workers.Done()
			if _, err := persistence.UpsertDevice(ctx, domain.Device{
				ID: input.deviceID, UserID: input.userID, Name: "iPhone",
				Platform: "ios", PushToken: input.token,
			}); err != nil {
				t.Errorf("upsert device: %v", err)
			}
		}()
	}
	workers.Wait()
	devices := []struct {
		userID, deviceID uuid.UUID
	}{{first.ID, firstDeviceID}, {second.ID, secondDeviceID}}
	owners := 0
	for _, input := range devices {
		device, err := persistence.Device(ctx, input.userID, input.deviceID)
		if err != nil {
			t.Fatal(err)
		}
		if device.PushToken == token {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("push token owners = %d, want exactly one", owners)
	}
}

func TestConflictingDeviceIDCannotStealPushToken(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	owner, _ := persistence.CreateUser(ctx, store.CreateUserParams{Email: "device-owner@example.com"})
	attacker, _ := persistence.CreateUser(ctx, store.CreateUserParams{Email: "device-attacker@example.com"})
	ownerDevice, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: owner.ID, Name: "Owner", Platform: "ios", PushToken: "0011",
	})
	if err != nil {
		t.Fatal(err)
	}
	attackerDevice, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: attacker.ID, Name: "Attacker", Platform: "ios", PushToken: "2233",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: ownerDevice.ID, UserID: attacker.ID, Name: "Conflict",
		Platform: "ios", PushToken: attackerDevice.PushToken,
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("cross-account device upsert returned %v, want conflict", err)
	}
	unchanged, err := persistence.Device(ctx, attacker.ID, attackerDevice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.PushToken != "2233" {
		t.Fatalf("failed transaction cleared prior token owner: %q", unchanged.PushToken)
	}
}
