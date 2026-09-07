package memory

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPreKeyClaimSkipsIncompleteDeviceIdentity(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "incomplete-key@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: user.ID, Name: "Incomplete", Platform: "ios",
		IdentityKey: "identity-without-a-signed-prekey",
	}); err != nil {
		t.Fatal(err)
	}
	completeID := uuid.New()
	if _, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: completeID, UserID: user.ID, Name: "Complete", Platform: "ios",
		IdentityKey:  "complete-identity",
		SignedPreKey: json.RawMessage(`{"key_id":1,"public_key":"public","signature":"signature"}`),
	}); err != nil {
		t.Fatal(err)
	}

	bundles, err := persistence.ClaimPreKeys(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 1 || bundles[0].DeviceID != completeID {
		t.Fatalf("claim returned incomplete devices: %+v", bundles)
	}
}

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
