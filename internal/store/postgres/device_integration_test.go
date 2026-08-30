package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPushTokenUniquenessMigrationNormalizesAndKeepsNewestOwner(t *testing.T) {
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

	tx, err := persistence.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DROP INDEX devices_push_token_unique`); err != nil {
		t.Fatal(err)
	}
	firstUserID, secondUserID := uuid.New(), uuid.New()
	firstDeviceID, secondDeviceID := uuid.New(), uuid.New()
	createdAt := time.Now().UTC().Add(-time.Hour)
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id,email,display_name,password_hash,created_at,updated_at)
		VALUES ($1,$2,'First','',now(),now()),($3,$4,'Second','',now(),now())`,
		firstUserID, "migration-first-"+uuid.NewString()+"@example.com",
		secondUserID, "migration-second-"+uuid.NewString()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices
			(id,user_id,name,platform,push_token,last_seen_at,created_at)
		VALUES
			($1,$2,'Older','ios',' AABBCC ', $5, $6),
			($3,$4,'Newer','ios','aabbcc', $7, $6)`,
		firstDeviceID, firstUserID, secondDeviceID, secondUserID,
		createdAt, createdAt, createdAt.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	raw, err := migrationFiles.ReadFile("migrations/000013_push_token_uniqueness.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(raw)); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `
		SELECT id,push_token FROM devices WHERE id=ANY($1::uuid[]) ORDER BY id`,
		[]uuid.UUID{firstDeviceID, secondDeviceID})
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	owners := make(map[uuid.UUID]string, 2)
	for rows.Next() {
		var id uuid.UUID
		var token string
		if err := rows.Scan(&id, &token); err != nil {
			t.Fatal(err)
		}
		owners[id] = token
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if owners[firstDeviceID] != "" || owners[secondDeviceID] != "aabbcc" {
		t.Fatalf("unexpected migrated ownership: older=%q newer=%q",
			owners[firstDeviceID], owners[secondDeviceID])
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET push_token=$1 WHERE id=$2`,
		strings.ToLower("AABBCC"), firstDeviceID); err == nil {
		t.Fatal("unique push-token index accepted a second owner")
	}
}

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
