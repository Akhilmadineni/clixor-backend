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

func TestAndroidPostgresTokenOwnershipAndQueuePlatform(t *testing.T) {
	db := os.Getenv("TEST_DATABASE_URL")
	if db == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx := context.Background()
	s, err := Open(ctx, db, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := s.CreateUser(ctx, store.CreateUserParams{Email: "android-" + uuid.NewString() + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	suffix := uuid.NewString()
	a, err := s.UpsertDevice(ctx, domain.Device{ID: uuid.New(), UserID: u.ID, Platform: "android", PushToken: "AbCd" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.UpsertDevice(ctx, domain.Device{ID: uuid.New(), UserID: u.ID, Platform: "android", PushToken: "abcd" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	ios, err := s.UpsertDevice(ctx, domain.Device{ID: uuid.New(), UserID: u.ID, Platform: "ios", PushToken: "ABCD" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range []domain.Device{a, b, ios} {
		got, e := s.Device(ctx, u.ID, device.ID)
		if e != nil || got.PushToken != device.PushToken {
			t.Fatal("token case/provider isolation lost")
		}
	}
	b.Platform = "ios"
	if _, err = s.UpsertDevice(ctx, b); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("device platform mutation allowed")
	}
	moved := a
	moved.ID = uuid.New()
	if _, err = s.UpsertDevice(ctx, moved); err != nil {
		t.Fatal(err)
	}
	old, _ := s.Device(ctx, u.ID, a.ID)
	if old.PushToken != "" {
		t.Fatal("stale token owner retained")
	}
	conversation, err := s.CreateConversation(ctx, store.CreateConversationParams{Kind: "group", CreatedBy: u.ID})
	if err != nil {
		t.Fatal(err)
	}
	message, _, err := s.CreateMessage(ctx, store.CreateMessageParams{ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: conversation.ID, SenderID: u.ID, SenderDeviceID: moved.ID, ContentType: "text", Ciphertext: "opaque"})
	if err != nil {
		t.Fatal(err)
	}
	var eventID int64
	if err = s.pool.QueryRow(ctx, `SELECT id FROM outbox_events WHERE aggregate_id=$1 AND topic='message.created' ORDER BY id DESC LIMIT 1`, conversation.ID).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	count, err := s.EnqueuePushDeliveries(ctx, domain.PushDelivery{OutboxEventID: eventID, ConversationID: conversation.ID, EntityID: message.ID, NotificationID: message.ID.String()}, []uuid.UUID{u.ID})
	if err != nil || count != 3 {
		t.Fatalf("enqueue=%d err=%v", count, err)
	}
	// Claims must not spend attempts on disabled providers. Other integration
	// fixtures may remain in this shared database, so check our exact devices.
	batch, err := s.LockPushDeliveryBatch(ctx, 1000, "android")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, delivery := range batch {
		if delivery.Platform != "android" {
			t.Fatal("iOS work claimed for Android worker")
		}
		if delivery.OutboxEventID != eventID {
			continue
		}
		seen++
		if err = s.WithPushDeliveryLease(ctx, delivery.ID, delivery.LeaseToken, func(_ context.Context, leased domain.PushDelivery) error {
			if leased.Platform != "android" || leased.PushToken == "" {
				t.Fatal("lease lost Android provider identity")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if seen != 2 {
		t.Fatalf("Android claims=%d", seen)
	}
	var iosAttempts int
	if err = s.pool.QueryRow(ctx, `SELECT attempts FROM push_deliveries WHERE outbox_event_id=$1 AND device_id=$2`, eventID, ios.ID).Scan(&iosAttempts); err != nil || iosAttempts != 0 {
		t.Fatal("disabled iOS platform spent attempts")
	}
}

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

func TestPostgresConcurrentPushTokenSwapsRetryDeadlocks(t *testing.T) {
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
	first, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "swap-first-" + uuid.NewString() + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "swap-second-" + uuid.NewString() + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	firstDevice := domain.Device{ID: uuid.New(), UserID: first.ID, Name: "first", Platform: "ios", PushToken: "swap-token-a-" + uuid.NewString()}
	secondDevice := domain.Device{ID: uuid.New(), UserID: second.ID, Name: "second", Platform: "ios", PushToken: "swap-token-b-" + uuid.NewString()}
	if firstDevice, err = persistence.UpsertDevice(ctx, firstDevice); err != nil {
		t.Fatal(err)
	}
	if secondDevice, err = persistence.UpsertDevice(ctx, secondDevice); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 10; round++ {
		firstWant, secondWant := secondDevice.PushToken, firstDevice.PushToken
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() {
			<-start
			firstDevice.PushToken = firstWant
			var writeErr error
			firstDevice, writeErr = persistence.UpsertDevice(ctx, firstDevice)
			results <- writeErr
		}()
		go func() {
			<-start
			secondDevice.PushToken = secondWant
			var writeErr error
			secondDevice, writeErr = persistence.UpsertDevice(ctx, secondDevice)
			results <- writeErr
		}()
		close(start)
		for range 2 {
			if err := <-results; err != nil {
				t.Fatalf("round %d token swap failed after retry: %v", round, err)
			}
		}
		if firstDevice.PushToken != firstWant || secondDevice.PushToken != secondWant {
			t.Fatalf("round %d swap mismatch: first=%q second=%q", round, firstDevice.PushToken, secondDevice.PushToken)
		}
	}
}
