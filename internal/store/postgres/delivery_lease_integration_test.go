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

func TestPostgresRealtimeDeliveryLeaseSerializesAccountErasure(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	t.Run("publish first", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		persistence, user, event := postgresRealtimeErasureFixture(t, ctx, databaseURL)
		defer persistence.Close()
		callbackStarted := make(chan struct{})
		releaseCallback := make(chan struct{})
		deliveryDone := make(chan error, 1)
		go func() {
			deliveryDone <- persistence.DeliverRealtimeOutbox(
				ctx, event.ID, event.Attempts,
				func(callbackContext context.Context, leased domain.OutboxEvent) error {
					if leased.ID != event.ID {
						return errors.New("wrong realtime lease row")
					}
					if _, err := persistence.UserByID(callbackContext, user.ID); err != nil {
						return err
					}
					close(callbackStarted)
					select {
					case <-callbackContext.Done():
						return callbackContext.Err()
					case <-releaseCallback:
						return nil
					}
				},
			)
		}()
		<-callbackStarted
		deletionStarted := make(chan struct{})
		deletionDone := make(chan error, 1)
		go func() {
			close(deletionStarted)
			deletionDone <- persistence.DeleteAccount(ctx, user.ID)
		}()
		<-deletionStarted
		select {
		case err := <-deletionDone:
			t.Fatalf("erasure crossed active realtime callback: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		close(releaseCallback)
		if err := <-deliveryDone; err != nil {
			t.Fatal(err)
		}
		if err := <-deletionDone; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("erasure first", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		persistence, user, event := postgresRealtimeErasureFixture(t, ctx, databaseURL)
		defer persistence.Close()
		if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
			t.Fatal(err)
		}
		called := false
		err := persistence.DeliverRealtimeOutbox(
			ctx, event.ID, event.Attempts,
			func(context.Context, domain.OutboxEvent) error {
				called = true
				return nil
			},
		)
		if !errors.Is(err, domain.ErrNotFound) || called {
			t.Fatalf("delivery after erasure: called=%t err=%v", called, err)
		}
	})
}

func TestPostgresDeliveryBarrierPreventsCallbackStoreDeadlock(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	persistence, user, event := postgresRealtimeErasureFixture(t, ctx, databaseURL)
	defer persistence.Close()
	if _, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: user.ID, Name: "iPhone", Platform: "ios",
		PushToken: "barrier-" + uuid.NewString(), IdentityKey: "identity",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	callbackStarted := make(chan struct{})
	useStore := make(chan struct{})
	defer func() {
		select {
		case <-useStore:
		default:
			close(useStore)
		}
	}()
	deliveryDone := make(chan error, 1)
	go func() {
		deliveryDone <- persistence.DeliverRealtimeOutbox(
			ctx, event.ID, event.Attempts,
			func(callbackContext context.Context, leased domain.OutboxEvent) error {
				close(callbackStarted)
				select {
				case <-callbackContext.Done():
					return callbackContext.Err()
				case <-useStore:
				}
				inserted, err := persistence.EnqueuePushDeliveries(
					callbackContext,
					domain.PushDelivery{
						OutboxEventID:  leased.ID,
						ConversationID: leased.AggregateID,
						EntityID:       uuid.New(),
						NotificationID: uuid.NewString(),
						Title:          "generic", Body: "generic", Kind: "activity",
					},
					[]uuid.UUID{user.ID},
				)
				if err != nil {
					return err
				}
				if inserted != 1 {
					return errors.New("callback Store method did not enqueue one delivery")
				}
				return nil
			},
		)
	}()
	<-callbackStarted

	deletionDone := make(chan error, 1)
	go func() { deletionDone <- persistence.DeleteAccount(ctx, user.ID) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var deletionWaiting bool
		err := persistence.pool.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM pg_stat_activity
				WHERE wait_event='advisory'
				  AND query LIKE '%pg_advisory_xact_lock($1)%'
			)`).Scan(&deletionWaiting)
		if err == nil && deletionWaiting {
			break
		}
		if time.Now().After(deadline) {
			close(useStore)
			t.Fatalf("account erasure never waited at delivery barrier: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(useStore)

	if err := <-deliveryDone; err != nil {
		t.Fatalf("leased callback Store call deadlocked or failed: %v", err)
	}
	if err := <-deletionDone; err != nil {
		t.Fatalf("account erasure after callback failed: %v", err)
	}
}

func TestPostgresPushDeliveryLeaseSerializesAccountErasure(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	t.Run("publish first", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		persistence, user, delivery := postgresPushErasureFixture(t, ctx, databaseURL)
		defer persistence.Close()
		callbackStarted := make(chan struct{})
		releaseCallback := make(chan struct{})
		deliveryDone := make(chan error, 1)
		go func() {
			deliveryDone <- persistence.WithPushDeliveryLease(
				ctx, delivery.ID, delivery.LeaseToken,
				func(callbackContext context.Context, leased domain.PushDelivery) error {
					if leased.ID != delivery.ID || leased.PushToken == "" {
						return errors.New("wrong push lease row")
					}
					if _, err := persistence.UserByID(callbackContext, user.ID); err != nil {
						return err
					}
					close(callbackStarted)
					select {
					case <-callbackContext.Done():
						return callbackContext.Err()
					case <-releaseCallback:
						return nil
					}
				},
			)
		}()
		<-callbackStarted
		deletionStarted := make(chan struct{})
		deletionDone := make(chan error, 1)
		go func() {
			close(deletionStarted)
			deletionDone <- persistence.DeleteAccount(ctx, user.ID)
		}()
		<-deletionStarted
		select {
		case err := <-deletionDone:
			t.Fatalf("erasure crossed active APNs callback: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		close(releaseCallback)
		if err := <-deliveryDone; err != nil {
			t.Fatal(err)
		}
		if err := <-deletionDone; err != nil {
			t.Fatal(err)
		}
		var count int
		if err := persistence.pool.QueryRow(ctx,
			`SELECT count(*) FROM push_deliveries WHERE id=$1`, delivery.ID,
		).Scan(&count); err != nil || count != 0 {
			t.Fatalf("erased push row count=%d err=%v", count, err)
		}
	})

	t.Run("erasure first", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		persistence, user, delivery := postgresPushErasureFixture(t, ctx, databaseURL)
		defer persistence.Close()
		if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
			t.Fatal(err)
		}
		called := false
		err := persistence.WithPushDeliveryLease(
			ctx, delivery.ID, delivery.LeaseToken,
			func(context.Context, domain.PushDelivery) error {
				called = true
				return nil
			},
		)
		if !errors.Is(err, domain.ErrNotFound) || called {
			t.Fatalf("push after erasure: called=%t err=%v", called, err)
		}
	})
}

func TestPostgresAccountErasureRemovesOnlyDeletedRecipientPush(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	deleted, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "A",
	})
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "Remaining",
	})
	if err != nil {
		t.Fatal(err)
	}
	deletedDevice, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: deleted.ID, Name: "deleted", Platform: "ios",
		PushToken: "deleted-" + uuid.NewString(), IdentityKey: "identity", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	remainingDevice, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: remaining.ID, Name: "remaining", Platform: "ios",
		PushToken: "remaining-" + uuid.NewString(), IdentityKey: "identity", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: remaining.ID, MemberIDs: []uuid.UUID{deleted.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	entity, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "note", ID: uuid.New(), CreatedBy: remaining.ID,
		Payload: []byte(`{"label":"A","amount":9.5}`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var sourceID int64
	if err := persistence.pool.QueryRow(ctx, `
		SELECT id FROM outbox_events
		WHERE aggregate_id=$1 AND topic='entity.updated' AND payload->>'id'=$2`,
		conversation.ID, entity.ID.String()).Scan(&sourceID); err != nil {
		t.Fatal(err)
	}
	inserted, err := persistence.EnqueuePushDeliveries(ctx, domain.PushDelivery{
		OutboxEventID: sourceID, ConversationID: conversation.ID, EntityID: entity.ID,
		NotificationID: uuid.NewString(), Title: "generic", Body: "generic", Kind: "activity",
	}, []uuid.UUID{deleted.ID, remaining.ID})
	if err != nil || inserted != 2 {
		t.Fatalf("enqueue push: inserted=%d err=%v", inserted, err)
	}
	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}
	var deletedCount, remainingCount, sourceCount int
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM push_deliveries WHERE outbox_event_id=$1 AND device_id=$2`,
		sourceID, deletedDevice.ID).Scan(&deletedCount); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM push_deliveries WHERE outbox_event_id=$1 AND device_id=$2`,
		sourceID, remainingDevice.ID).Scan(&remainingCount); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox_events WHERE id=$1`, sourceID,
	).Scan(&sourceCount); err != nil {
		t.Fatal(err)
	}
	if deletedCount != 0 || remainingCount != 1 || sourceCount != 1 {
		t.Fatalf("deleted_push=%d remaining_push=%d source=%d", deletedCount, remainingCount, sourceCount)
	}
}

func TestPostgresAccountErasureDropsStaleAffectedSourceAndCascadesPush(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	deleted, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "A",
	})
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "Remaining",
	})
	if err != nil {
		t.Fatal(err)
	}
	remainingDevice, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: remaining.ID, Name: "remaining", Platform: "ios",
		PushToken: "remaining-" + uuid.NewString(), IdentityKey: "identity",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: remaining.ID, MemberIDs: []uuid.UUID{deleted.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	entityID, settlementID := uuid.New(), uuid.New()
	entity, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "expense", ID: entityID, CreatedBy: remaining.ID,
		Payload: json.RawMessage(`{"payer":{"backendUserId":"` + deleted.ID.String() +
			`","displayName":"\u0041"},"settlementId":"` + settlementID.String() + `","amount":64.25}`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := entity.Version
	safePayload := json.RawMessage(`{"label":"A","settlementId":"` + settlementID.String() + `","amount":64.25}`)
	if _, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "expense", ID: entityID, CreatedBy: remaining.ID,
		Payload: safePayload,
	}, &expected); err != nil {
		t.Fatal(err)
	}
	var staleID, currentID int64
	var currentBytes json.RawMessage
	if err := persistence.pool.QueryRow(ctx, `
		SELECT id FROM outbox_events
		WHERE aggregate_id=$1 AND topic='entity.updated'
		  AND payload->>'id'=$2 AND payload->>'version'='1'`,
		conversation.ID, entityID.String()).Scan(&staleID); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx, `
		SELECT id,payload FROM outbox_events
		WHERE aggregate_id=$1 AND topic='entity.updated'
		  AND payload->>'id'=$2 AND payload->>'version'='2'`,
		conversation.ID, entityID.String()).Scan(&currentID, &currentBytes); err != nil {
		t.Fatal(err)
	}
	for _, sourceID := range []int64{staleID, currentID} {
		inserted, err := persistence.EnqueuePushDeliveries(ctx, domain.PushDelivery{
			OutboxEventID: sourceID, ConversationID: conversation.ID, EntityID: entityID,
			NotificationID: uuid.NewString(), Title: "generic", Body: "generic", Kind: "activity",
		}, []uuid.UUID{remaining.ID})
		if err != nil || inserted != 1 {
			t.Fatalf("enqueue source=%d inserted=%d err=%v", sourceID, inserted, err)
		}
	}

	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}
	var staleSourceCount, stalePushCount int
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox_events WHERE id=$1`, staleID,
	).Scan(&staleSourceCount); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM push_deliveries WHERE outbox_event_id=$1`, staleID,
	).Scan(&stalePushCount); err != nil {
		t.Fatal(err)
	}
	if staleSourceCount != 0 || stalePushCount != 0 {
		t.Fatalf("stale source=%d cascaded pushes=%d", staleSourceCount, stalePushCount)
	}
	var currentAfter json.RawMessage
	if err := persistence.pool.QueryRow(ctx,
		`SELECT payload FROM outbox_events WHERE id=$1`, currentID,
	).Scan(&currentAfter); err != nil {
		t.Fatal(err)
	}
	if string(currentAfter) != string(currentBytes) {
		t.Fatalf("safe current event changed:\nbefore=%s\nafter=%s", currentBytes, currentAfter)
	}
	var currentPushCount int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*) FROM push_deliveries
		WHERE outbox_event_id=$1 AND device_id=$2`, currentID, remainingDevice.ID,
	).Scan(&currentPushCount); err != nil || currentPushCount != 1 {
		t.Fatalf("safe current push count=%d err=%v", currentPushCount, err)
	}
	var retainedPayload json.RawMessage
	if err := persistence.pool.QueryRow(ctx, `
		SELECT payload FROM entities
		WHERE conversation_id=$1 AND kind='expense' AND id=$2`,
		conversation.ID, entityID).Scan(&retainedPayload); err != nil {
		t.Fatal(err)
	}
	var financial map[string]any
	if err := json.Unmarshal(retainedPayload, &financial); err != nil {
		t.Fatal(err)
	}
	if financial["label"] != "A" || financial["settlementId"] != settlementID.String() ||
		financial["amount"] != 64.25 {
		t.Fatalf("safe financial history changed: %s", retainedPayload)
	}
}

func TestPostgresAccountErasurePreservesSharedE2EEBytes(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	deleted, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "A",
	})
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "Remaining",
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: deleted.ID, Name: "sender", Platform: "ios",
		IdentityKey: "identity", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: remaining.ID, MemberIDs: []uuid.UUID{deleted.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := "A"
	envelope := []byte(`{"wrappedKey":"A","header":{"nonce":"A"}}`)
	message, _, err := persistence.CreateMessage(ctx, store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: conversation.ID,
		SenderID: deleted.ID, SenderDeviceID: device.ID, ContentType: "ciphertext",
		Ciphertext: ciphertext, Envelope: envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sourceID int64
	var before []byte
	if err := persistence.pool.QueryRow(ctx, `
		SELECT id,payload FROM outbox_events
		WHERE aggregate_id=$1 AND topic='message.created' AND payload->>'id'=$2`,
		conversation.ID, message.ID.String()).Scan(&sourceID, &before); err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err := persistence.pool.QueryRow(ctx,
		`SELECT payload FROM outbox_events WHERE id=$1`, sourceID,
	).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("E2EE outbox JSON changed:\nbefore=%s\nafter=%s", before, after)
	}
	messages, err := persistence.ListMessages(ctx, store.ListMessagesParams{
		ConversationID: conversation.ID, UserID: remaining.ID, Limit: 10,
	})
	if err != nil || len(messages) != 1 || messages[0].ID != message.ID {
		t.Fatalf("messages=%+v err=%v", messages, err)
	}
	if messages[0].Ciphertext != ciphertext || string(messages[0].Envelope) != string(envelope) {
		t.Fatalf("E2EE message changed: ciphertext=%q envelope=%s", messages[0].Ciphertext, messages[0].Envelope)
	}
}

func postgresRealtimeErasureFixture(
	t *testing.T,
	ctx context.Context,
	databaseURL string,
) (*Store, domain.User, domain.OutboxEvent) {
	t.Helper()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "Lease User",
	})
	if err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	var event domain.OutboxEvent
	err = persistence.pool.QueryRow(ctx, `
		UPDATE outbox_events
		SET locked_until=now()+interval '30 seconds',attempts=attempts+1
		WHERE aggregate_id=$1 AND topic='conversation.created' AND published_at IS NULL
		RETURNING id,topic,aggregate_id,payload,created_at,published_at,
		          available_at,locked_until,attempts`, conversation.ID).Scan(
		&event.ID, &event.Topic, &event.AggregateID, &event.Payload, &event.CreatedAt,
		&event.PublishedAt, &event.AvailableAt, &event.LockedUntil, &event.Attempts,
	)
	if err != nil {
		persistence.Close()
		t.Fatalf("claim exact realtime: %v", err)
	}
	return persistence, user, event
}

func postgresPushErasureFixture(
	t *testing.T,
	ctx context.Context,
	databaseURL string,
) (*Store, domain.User, domain.PushDelivery) {
	t.Helper()
	persistence, user, event := postgresRealtimeErasureFixture(t, ctx, databaseURL)
	if _, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: user.ID, Name: "iPhone", Platform: "ios",
		PushToken: "lease-" + uuid.NewString(), IdentityKey: "identity", CreatedAt: time.Now().UTC(),
	}); err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	inserted, err := persistence.EnqueuePushDeliveries(ctx, domain.PushDelivery{
		OutboxEventID: event.ID, ConversationID: event.AggregateID, EntityID: uuid.New(),
		NotificationID: uuid.NewString(), Title: "generic", Body: "generic", Kind: "activity",
	}, []uuid.UUID{user.ID})
	if err != nil || inserted != 1 {
		persistence.Close()
		t.Fatalf("enqueue push: inserted=%d err=%v", inserted, err)
	}
	leaseToken := uuid.New()
	var delivery domain.PushDelivery
	err = persistence.pool.QueryRow(ctx, `
		WITH claimed AS (
			UPDATE push_deliveries
			SET locked_until=now()+interval '2 minutes',lease_token=$2,
			    attempts=attempts+1,updated_at=now()
			WHERE outbox_event_id=$1 AND status='pending'
			RETURNING *
		)
		SELECT claimed.id,claimed.outbox_event_id,claimed.device_id,
		       device.user_id,COALESCE(device.push_token,''),
		       claimed.title,claimed.body,claimed.kind,claimed.conversation_id,
		       claimed.entity_id,claimed.notification_id,claimed.status,
		       claimed.attempts,claimed.next_attempt_at,claimed.lease_token,
		       claimed.locked_until,claimed.created_at,claimed.delivered_at,
		       claimed.dead_lettered_at,claimed.last_error_class
		FROM claimed JOIN devices AS device ON device.id=claimed.device_id`,
		event.ID, leaseToken).Scan(
		&delivery.ID, &delivery.OutboxEventID, &delivery.DeviceID,
		&delivery.UserID, &delivery.PushToken, &delivery.Title, &delivery.Body,
		&delivery.Kind, &delivery.ConversationID, &delivery.EntityID,
		&delivery.NotificationID, &delivery.Status, &delivery.Attempts,
		&delivery.NextAttemptAt, &delivery.LeaseToken, &delivery.LockedUntil,
		&delivery.CreatedAt, &delivery.DeliveredAt, &delivery.DeadLetteredAt,
		&delivery.LastErrorClass,
	)
	if err != nil {
		persistence.Close()
		t.Fatalf("claim exact push: %v", err)
	}
	return persistence, user, delivery
}
