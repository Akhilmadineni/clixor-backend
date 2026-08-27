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

func TestPostgresPushDeliveryClaimsAreConcurrentSafeAndLeaseFenced(t *testing.T) {
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
	t.Cleanup(persistence.Close)
	actor, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-push-actor-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-push-recipient-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	actorDevice, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: actor.ID, Name: "Actor", Platform: "ios",
	})
	if err != nil {
		t.Fatal(err)
	}
	recipientDevice, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: recipient.ID, Name: "Recipient", Platform: "ios",
		PushToken: "0102030405060708",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: actor.ID, MemberIDs: []uuid.UUID{recipient.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, _, err := persistence.CreateMessage(ctx, store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: conversation.ID,
		SenderID: actor.ID, SenderDeviceID: actorDevice.ID, ContentType: "text",
		Ciphertext: "encrypted",
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var source domain.OutboxEvent
	for _, event := range events {
		if event.Topic == "message.created" && event.AggregateID == conversation.ID {
			source = event
			break
		}
	}
	if source.ID == 0 {
		t.Fatal("message outbox event not found")
	}
	inserted, err := persistence.EnqueuePushDeliveries(ctx, domain.PushDelivery{
		OutboxEventID: source.ID,
		Title:         "Conversation", Body: "Someone sent a message", Kind: "message",
		ConversationID: conversation.ID, EntityID: message.ID, NotificationID: message.ID.String(),
	}, []uuid.UUID{recipient.ID})
	if err != nil || inserted != 1 {
		t.Fatalf("enqueue inserted=%d err=%v", inserted, err)
	}
	inserted, err = persistence.EnqueuePushDeliveries(ctx, domain.PushDelivery{
		OutboxEventID: source.ID,
		Title:         "Conversation", Body: "Someone sent a message", Kind: "message",
		ConversationID: conversation.ID, EntityID: message.ID, NotificationID: message.ID.String(),
	}, []uuid.UUID{recipient.ID})
	if err != nil || inserted != 0 {
		t.Fatalf("idempotent enqueue inserted=%d err=%v", inserted, err)
	}

	var workers sync.WaitGroup
	workers.Add(2)
	claimed := make(chan domain.PushDelivery, 2)
	for range 2 {
		go func() {
			defer workers.Done()
			batch, lockErr := persistence.LockPushDeliveryBatch(ctx, 1)
			if lockErr != nil {
				t.Errorf("lock delivery: %v", lockErr)
				return
			}
			for _, delivery := range batch {
				claimed <- delivery
			}
		}()
	}
	workers.Wait()
	close(claimed)
	var firstClaim domain.PushDelivery
	count := 0
	for delivery := range claimed {
		firstClaim = delivery
		count++
	}
	if count != 1 || firstClaim.Attempts != 1 || firstClaim.PushToken != recipientDevice.PushToken {
		t.Fatalf("concurrent claims=%d delivery=%+v", count, firstClaim)
	}
	if err := persistence.FinishPushDelivery(
		ctx, firstClaim.ID, uuid.New(), domain.PushDeliveryDelivered, time.Time{}, "",
	); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("wrong lease returned %v, want conflict", err)
	}
	if err := persistence.FinishPushDelivery(
		ctx, firstClaim.ID, firstClaim.LeaseToken, domain.PushDeliveryPending,
		time.Now().Add(-time.Second), "network",
	); err != nil {
		t.Fatal(err)
	}
	retry, err := persistence.LockPushDeliveryBatch(ctx, 1)
	if err != nil || len(retry) != 1 || retry[0].Attempts != 2 {
		t.Fatalf("retry claim=%+v err=%v", retry, err)
	}
	updated, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: recipientDevice.ID, UserID: recipient.ID, Name: "Recipient",
		Platform: "ios", PushToken: "1112131415161718",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.InvalidatePushDelivery(
		ctx, retry[0].ID, retry[0].LeaseToken, retry[0].UserID,
		retry[0].DeviceID, retry[0].PushToken,
	); err != nil {
		t.Fatal(err)
	}
	afterInvalidation, err := persistence.Device(ctx, recipient.ID, recipientDevice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterInvalidation.PushToken != updated.PushToken {
		t.Fatalf("stale invalidation cleared rotated token: %q", afterInvalidation.PushToken)
	}
}

func TestPostgresRetentionPrunesTerminalPushBeforePublishedSource(t *testing.T) {
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
	t.Cleanup(persistence.Close)
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-retention-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: user.ID, Name: "Retention fixture", Platform: "ios",
	})
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-400 * 24 * time.Hour)
	var outboxID int64
	if err := persistence.pool.QueryRow(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload,created_at,published_at)
		VALUES('retention.fixture',$1,'{}'::jsonb,$2,$2)
		RETURNING id`, uuid.New(), old).Scan(&outboxID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = persistence.pool.Exec(context.Background(), `DELETE FROM outbox_events WHERE id=$1`, outboxID)
		_, _ = persistence.pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, user.ID)
	})
	conversationID := uuid.New()
	entityID := uuid.New()
	if _, err := persistence.pool.Exec(ctx, `
		INSERT INTO push_deliveries(
			outbox_event_id,device_id,title,body,kind,conversation_id,entity_id,
			notification_id,status,delivered_at
		) VALUES($1,$2,'Clixor','Activity','activity',$3,$4,$5,'delivered',$6)`,
		outboxID, device.ID, conversationID, entityID, entityID.String(), old); err != nil {
		t.Fatal(err)
	}

	if _, err := persistence.PrunePublishedOutbox(
		ctx, time.Now().UTC(), store.MaxRetentionPruneBatchSize,
	); err != nil {
		t.Fatal(err)
	}
	var sourceExists bool
	if err := persistence.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM outbox_events WHERE id=$1)`, outboxID,
	).Scan(&sourceExists); err != nil {
		t.Fatal(err)
	}
	if !sourceExists {
		t.Fatal("published source was pruned while a terminal push row still referenced it")
	}

	if _, err := persistence.PrunePushDeliveries(
		ctx, time.Now().UTC(), time.Now().UTC(), store.MaxRetentionPruneBatchSize,
	); err != nil {
		t.Fatal(err)
	}
	var deliveryExists bool
	if err := persistence.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM push_deliveries WHERE outbox_event_id=$1)`, outboxID,
	).Scan(&deliveryExists); err != nil {
		t.Fatal(err)
	}
	if deliveryExists {
		t.Fatal("old terminal push delivery was not pruned")
	}

	if _, err := persistence.PrunePublishedOutbox(
		ctx, time.Now().UTC(), store.MaxRetentionPruneBatchSize,
	); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM outbox_events WHERE id=$1)`, outboxID,
	).Scan(&sourceExists); err != nil {
		t.Fatal(err)
	}
	if sourceExists {
		t.Fatal("unreferenced old published source was not pruned")
	}
}
