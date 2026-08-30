package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/Akhilmadineni/clixor-backend/internal/push"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/google/uuid"
)

func TestMessagePushFansOutToEveryRecipientDeviceAndExcludesActor(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	message := domain.Message{
		ID: uuid.New(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
		Seq: 1, Ciphertext: "encrypted-content",
	}
	raw, _ := json.Marshal(message)
	recipients, err := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)
	if err != nil {
		t.Fatal(err)
	}

	if err := fixture.relay.enqueuePush(fixture.ctx, domain.OutboxEvent{
		ID: 101, Topic: "message.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); err != nil {
		t.Fatal(err)
	}
	fixture.relay.flushPush(fixture.ctx)

	if len(fixture.push.calls) != len(fixture.recipientDevices) {
		t.Fatalf("push calls = %d, want %d", len(fixture.push.calls), len(fixture.recipientDevices))
	}
	seen := map[string]bool{}
	for _, call := range fixture.push.calls {
		seen[call.token] = true
		if call.title != genericPushTitle || call.body != genericPushBody {
			t.Fatalf("unexpected copy: title=%q body=%q", call.title, call.body)
		}
		if len(call.data) != 1 || call.data["type"] != genericPushKind {
			t.Fatalf("unexpected client data: %#v", call.data)
		}
	}
	for _, device := range fixture.recipientDevices {
		if !seen[device.PushToken] {
			t.Fatalf("recipient device %s was not notified", device.ID)
		}
	}
	for _, device := range append(fixture.actorDevices, fixture.outsiderDevices...) {
		if seen[device.PushToken] {
			t.Fatalf("non-recipient device %s received a push", device.ID)
		}
	}
}

func TestDisabledPushProviderLeavesDurableDeliveriesPending(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	message := domain.Message{
		ID: uuid.New(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
		Seq: 1, Ciphertext: "encrypted-content",
	}
	raw, _ := json.Marshal(message)
	recipients, err := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.relay.enqueuePush(fixture.ctx, domain.OutboxEvent{
		ID: 109, Topic: "message.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); err != nil {
		t.Fatal(err)
	}
	fixture.relay.push = push.Disabled{}
	fixture.relay.flushPush(fixture.ctx)

	pending, err := fixture.store.LockPushDeliveryBatch(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != len(fixture.recipientDevices) {
		t.Fatalf("pending deliveries = %d, want %d", len(pending), len(fixture.recipientDevices))
	}
	if fixture.push.callCount() != 0 {
		t.Fatal("disabled push provider was called")
	}
}

func TestReassignedPushTokenNeverReceivesPreviousAccountMetadata(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	message := domain.Message{
		ID: uuid.New(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
		Seq: 1, Ciphertext: "encrypted-content",
	}
	raw, _ := json.Marshal(message)
	recipients, err := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.relay.enqueuePush(fixture.ctx, domain.OutboxEvent{
		ID: 106, Topic: "message.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); err != nil {
		t.Fatal(err)
	}
	claimed, err := fixture.store.LockPushDeliveryBatch(fixture.ctx, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim delivery: items=%d error=%v", len(claimed), err)
	}

	// Simulate account switching after the worker copied the token but before
	// APNs accepted the request. The old delivery may still race through, so its
	// visible copy and routing data must be account-agnostic.
	reassigned := fixture.outsiderDevices[0]
	reassigned.PushToken = claimed[0].PushToken
	if _, err := fixture.store.UpsertDevice(fixture.ctx, reassigned); err != nil {
		t.Fatal(err)
	}
	fixture.relay.deliverPush(fixture.ctx, claimed[0])
	if got := fixture.push.callCount(); got != 1 {
		t.Fatalf("push calls = %d, want 1", got)
	}
	call := fixture.push.calls[0]
	if call.title != genericPushTitle || call.body != genericPushBody {
		t.Fatalf("reassigned token received account metadata: title=%q body=%q", call.title, call.body)
	}
	if len(call.data) != 1 || call.data["type"] != genericPushKind {
		t.Fatalf("reassigned token received routing metadata: %#v", call.data)
	}
}

func TestInvalidAPNSTokenIsPruned(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	invalid := fixture.recipientDevices[0]
	fixture.push.errors = map[string]error{
		invalid.PushToken: &push.DeliveryError{StatusCode: 410, Reason: "Unregistered"},
	}
	message := domain.Message{
		ID: uuid.New(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
	}
	raw, _ := json.Marshal(message)
	recipients, _ := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)
	if err := fixture.relay.enqueuePush(fixture.ctx, domain.OutboxEvent{
		ID: 102, Topic: "message.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); err != nil {
		t.Fatal(err)
	}
	fixture.relay.flushPush(fixture.ctx)

	device, err := fixture.store.Device(fixture.ctx, fixture.recipient.ID, invalid.ID)
	if err != nil {
		t.Fatal(err)
	}
	if device.PushToken != "" {
		t.Fatalf("invalid token was not cleared: %q", device.PushToken)
	}
	valid := fixture.recipientDevices[1]
	device, err = fixture.store.Device(fixture.ctx, fixture.recipient.ID, valid.ID)
	if err != nil {
		t.Fatal(err)
	}
	if device.PushToken != valid.PushToken {
		t.Fatalf("valid token changed: %q", device.PushToken)
	}
}

func TestExpenseAndTaskPushesOnlyFireOnCreate(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	recipients, _ := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)

	expense := domain.Entity{
		ConversationID: fixture.conversation.ID, Kind: "expense", ID: uuid.New(),
		Version: 1, CreatedBy: fixture.actor.ID,
		Payload: json.RawMessage(`{"description":"Dinner","amount":40}`),
	}
	notification := notificationForEntity(t, fixture, expense, recipients)
	if notification.kind != "expense" || notification.title != "Group 1" ||
		notification.body != "Akhil added Dinner ($40.00)" {
		t.Fatalf("unexpected expense notification: %#v", notification)
	}

	task := domain.Entity{
		ConversationID: fixture.conversation.ID, Kind: "task", ID: uuid.New(),
		Version: 1, CreatedBy: fixture.actor.ID,
		Payload: json.RawMessage(`{"title":"Book the hotel"}`),
	}
	notification = notificationForEntity(t, fixture, task, recipients)
	if notification.kind != "task" || notification.body != "Akhil created a task: Book the hotel" {
		t.Fatalf("unexpected task notification: %#v", notification)
	}

	expense.Version = 2
	raw, _ := json.Marshal(expense)
	if _, ok, err := fixture.relay.notificationFor(fixture.ctx, domain.OutboxEvent{
		Topic: "entity.updated", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); err != nil || ok {
		t.Fatal("entity updates after create must not generate pushes")
	}
}

func TestSubscriptionCreateSendsOneNotificationAndSuppressesInitialCharge(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Subscriptions"}`))
	recipients, _ := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)
	raw, _ := json.Marshal(fixture.conversation)
	notification, ok, err := fixture.relay.notificationFor(fixture.ctx, domain.OutboxEvent{
		Topic: "conversation.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("subscription conversation did not generate a notification")
	}
	if notification.kind != "subscription" || notification.title != "Subscription" ||
		notification.body != "Akhil added Group 1" {
		t.Fatalf("unexpected subscription notification: %#v", notification)
	}

	initialCharge := domain.Entity{
		ConversationID: fixture.conversation.ID, Kind: "expense", ID: uuid.New(),
		Version: 1, CreatedBy: fixture.actor.ID,
		CreatedAt: fixture.conversation.CreatedAt.Add(time.Second),
		Payload:   json.RawMessage(`{"description":"Group 1 – Subscription","amount":24}`),
	}
	raw, _ = json.Marshal(initialCharge)
	if _, ok, err := fixture.relay.notificationFor(fixture.ctx, domain.OutboxEvent{
		Topic: "entity.updated", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); err != nil || ok {
		t.Fatal("initial subscription charge would duplicate the create notification")
	}

	initialCharge.ID = uuid.New()
	initialCharge.CreatedAt = fixture.conversation.CreatedAt.Add(11 * time.Minute)
	notification = notificationForEntity(t, fixture, initialCharge, recipients)
	if notification.kind != "expense" {
		t.Fatalf("later subscription expense kind = %q", notification.kind)
	}
}

func TestPersonalMediaDeletionRetriesUntilObjectStoreSucceeds(t *testing.T) {
	ctx := context.Background()
	persistence := memory.New()
	user := createUser(t, persistence, "media-delete@example.com", "Delete Media")
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	object := domain.MediaObject{
		ID: uuid.New(), OwnerID: user.ID, ConversationID: conversation.ID,
		ObjectKey: "private/delete-me", ContentType: "image/jpeg", ByteSize: 1,
	}
	if _, err := persistence.CreateMedia(ctx, object); err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
		t.Fatal(err)
	}

	mediaRecorder := &recordingMedia{deleteErr: errors.New("minio temporarily unavailable")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	relay := New(persistence, nil, &recordingPush{}, mediaRecorder, logger)
	relay.flush(ctx)
	events, err := persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(mediaRecorder.deleted) != 1 {
		t.Fatalf("failed deletion was not retained for retry: events=%+v calls=%+v", events, mediaRecorder.deleted)
	}

	mediaRecorder.deleteErr = nil
	relay.flush(ctx)
	events, err = persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 || len(mediaRecorder.deleted) != 2 {
		t.Fatalf("successful deletion was not acknowledged: events=%+v calls=%+v", events, mediaRecorder.deleted)
	}
}

func TestTransientPushRetriesDurablyWithoutRepublishingRealtime(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	initial, err := fixture.store.LockOutboxBatch(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	initialIDs := make([]int64, 0, len(initial))
	for _, event := range initial {
		initialIDs = append(initialIDs, event.ID)
	}
	if err := fixture.store.MarkOutboxPublished(fixture.ctx, initialIDs); err != nil {
		t.Fatal(err)
	}
	message, _, err := fixture.store.CreateMessage(fixture.ctx, store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
		ContentType: "text", Ciphertext: "encrypted",
	})
	if err != nil {
		t.Fatal(err)
	}
	transient := errors.New("APNs network unavailable")
	fixture.push.errors = map[string]error{}
	for _, device := range fixture.recipientDevices {
		fixture.push.errors[device.PushToken] = transient
	}
	bus := &countingBus{}
	fixture.relay.bus = bus
	fixture.relay.policy = PushRetryPolicy{
		BatchSize: 100, WorkerConcurrency: 100, MaxAttempts: 3, BaseDelay: 0, MaxDelay: 0,
		DeliveredRetention: time.Hour, DeadLetterRetention: 24 * time.Hour,
	}

	fixture.relay.flush(fixture.ctx)
	fixture.relay.flushPush(fixture.ctx)
	if bus.publishCount.Load() != 1 {
		t.Fatalf("realtime publishes after first attempt = %d, want 1", bus.publishCount.Load())
	}
	if got := len(fixture.push.calls); got != len(fixture.recipientDevices) {
		t.Fatalf("first APNs calls = %d, want %d", got, len(fixture.recipientDevices))
	}
	remaining, err := fixture.store.LockOutboxBatch(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("generic outbox retained solely for APNs retry: %+v", remaining)
	}

	fixture.push.errors = nil
	fixture.relay.flush(fixture.ctx)
	fixture.relay.flushPush(fixture.ctx)
	if bus.publishCount.Load() != 1 {
		t.Fatalf("APNs retry republished realtime %d times", bus.publishCount.Load())
	}
	if got := len(fixture.push.calls); got != 2*len(fixture.recipientDevices) {
		t.Fatalf("APNs calls after durable retry = %d, want %d", got, 2*len(fixture.recipientDevices))
	}
	for _, call := range fixture.push.calls[len(fixture.recipientDevices):] {
		if call.notificationID != message.ID.String() {
			t.Fatalf("retry notification ID = %q, want %s", call.notificationID, message.ID)
		}
	}
}

func TestPermanentConversationMissSkipsPushWithoutPoisoningOutbox(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	drainFixtureOutbox(t, fixture)
	if _, _, err := fixture.store.CreateMessage(fixture.ctx, store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
		ContentType: "text", Ciphertext: "encrypted",
	}); err != nil {
		t.Fatal(err)
	}
	lookup := &conversationLookupStore{Store: fixture.store, err: domain.ErrNotFound}
	bus := &countingBus{}
	fixture.relay.store = lookup
	fixture.relay.bus = bus
	fixture.relay.flush(fixture.ctx)
	if got := bus.publishCount.Load(); got != 1 {
		t.Fatalf("realtime publishes = %d, want 1", got)
	}
	remaining, err := fixture.store.LockOutboxBatch(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("permanently missing conversation poisoned outbox: %+v", remaining)
	}
}

func TestTransientConversationLookupRetainsOutboxForRetry(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	drainFixtureOutbox(t, fixture)
	if _, _, err := fixture.store.CreateMessage(fixture.ctx, store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
		ContentType: "text", Ciphertext: "encrypted",
	}); err != nil {
		t.Fatal(err)
	}
	lookup := &conversationLookupStore{Store: fixture.store, err: errors.New("database unavailable")}
	bus := &countingBus{}
	fixture.relay.store = lookup
	fixture.relay.bus = bus
	fixture.relay.flush(fixture.ctx)
	if got := bus.publishCount.Load(); got != 0 {
		t.Fatalf("transient lookup published realtime %d times", got)
	}
	remaining, err := fixture.store.LockOutboxBatch(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Fatalf("transient lookup did not retain outbox: %+v", remaining)
	}
	lookup.err = nil
	fixture.relay.flush(fixture.ctx)
	if got := bus.publishCount.Load(); got != 1 {
		t.Fatalf("recovered lookup publishes = %d, want 1", got)
	}
}

func TestPushIdempotencyStateIsNotPrunedBeforeRealtimeAck(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	drainFixtureOutbox(t, fixture)
	if _, _, err := fixture.store.CreateMessage(fixture.ctx, store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
		ContentType: "text", Ciphertext: "encrypted",
	}); err != nil {
		t.Fatal(err)
	}
	fixture.relay.bus = &countingBus{err: errors.New("NATS unavailable")}
	fixture.relay.flush(fixture.ctx)
	fixture.relay.flushPush(fixture.ctx)
	firstCalls := fixture.push.callCount()
	if firstCalls != len(fixture.recipientDevices) {
		t.Fatalf("initial APNs calls = %d, want %d", firstCalls, len(fixture.recipientDevices))
	}
	deleted, err := fixture.store.PrunePushDeliveries(
		fixture.ctx, time.Now().Add(time.Hour), time.Now().Add(time.Hour),
		store.MaxRetentionPruneBatchSize,
	)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("pruned %d delivery rows before realtime ack", deleted)
	}
	fixture.relay.flush(fixture.ctx)
	fixture.relay.flushPush(fixture.ctx)
	if got := fixture.push.callCount(); got != firstCalls {
		t.Fatalf("NATS retry duplicated APNs delivery: calls=%d want=%d", got, firstCalls)
	}
}

func TestRetentionPrunesPushRowsBeforeOutboxUsingLongestWindow(t *testing.T) {
	now := time.Date(2026, time.August, 26, 20, 0, 0, 0, time.UTC)
	recorder := &retentionRecordingStore{Store: memory.New(), pushDeleted: 3, outboxDeleted: 2}
	policy := DefaultPushRetryPolicy()
	policy.DeliveredRetention = 7 * 24 * time.Hour
	policy.DeadLetterRetention = 30 * 24 * time.Hour
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	relay := NewWithPushRetryPolicy(
		recorder, nil, &recordingPush{}, media.Unavailable{}, logger, policy,
	)
	relay.now = func() time.Time { return now }
	relay.lastPrune = now.Add(-time.Hour)

	relay.pruneRetention(context.Background())
	if len(recorder.calls) != 2 || recorder.calls[0] != "push" || recorder.calls[1] != "outbox" {
		t.Fatalf("retention call order = %v, want [push outbox]", recorder.calls)
	}
	if want := now.Add(-policy.DeliveredRetention); !recorder.deliveredBefore.Equal(want) {
		t.Fatalf("delivered cutoff = %s, want %s", recorder.deliveredBefore, want)
	}
	if want := now.Add(-policy.DeadLetterRetention); !recorder.deadLetterBefore.Equal(want) {
		t.Fatalf("dead-letter cutoff = %s, want %s", recorder.deadLetterBefore, want)
	}
	if want := now.Add(-policy.DeadLetterRetention); !recorder.publishedBefore.Equal(want) {
		t.Fatalf("outbox cutoff = %s, want longest retention %s", recorder.publishedBefore, want)
	}
	if recorder.pushLimit != store.MaxRetentionPruneBatchSize ||
		recorder.outboxLimit != store.MaxRetentionPruneBatchSize {
		t.Fatalf("retention limits = push:%d outbox:%d", recorder.pushLimit, recorder.outboxLimit)
	}

	relay.pruneRetention(context.Background())
	if len(recorder.calls) != 2 {
		t.Fatalf("hourly retention guard made extra calls: %v", recorder.calls)
	}
}

func TestPermanentPushFailureDeadLettersAndStopsRetrying(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	fixture.push.errors = map[string]error{}
	for _, device := range fixture.recipientDevices {
		fixture.push.errors[device.PushToken] = &push.DeliveryError{StatusCode: 400, Reason: "PayloadEmpty"}
	}
	message := domain.Message{
		ID: uuid.New(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
	}
	raw, _ := json.Marshal(message)
	recipients, _ := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)
	if err := fixture.relay.enqueuePush(fixture.ctx, domain.OutboxEvent{
		ID: 103, Topic: "message.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); err != nil {
		t.Fatal(err)
	}
	fixture.relay.flushPush(fixture.ctx)
	fixture.relay.flushPush(fixture.ctx)
	if got := len(fixture.push.calls); got != len(fixture.recipientDevices) {
		t.Fatalf("permanent failures were retried: calls=%d want=%d", got, len(fixture.recipientDevices))
	}
}

func TestTransientPushDeadLettersAfterBoundedAttempts(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	fixture.relay.policy = PushRetryPolicy{
		BatchSize: 100, WorkerConcurrency: 100, MaxAttempts: 2,
		BaseDelay: 0, MaxDelay: 0, DeliveredRetention: time.Hour,
		DeadLetterRetention: 24 * time.Hour,
	}
	fixture.push.errors = map[string]error{}
	for _, device := range fixture.recipientDevices {
		fixture.push.errors[device.PushToken] = errors.New("connection reset")
	}
	message := domain.Message{
		ID: uuid.New(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
	}
	raw, _ := json.Marshal(message)
	recipients, _ := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)
	if err := fixture.relay.enqueuePush(fixture.ctx, domain.OutboxEvent{
		ID: 105, Topic: "message.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); err != nil {
		t.Fatal(err)
	}
	fixture.relay.flushPush(fixture.ctx)
	fixture.relay.flushPush(fixture.ctx)
	fixture.relay.flushPush(fixture.ctx)
	if got, want := fixture.push.callCount(), 2*len(fixture.recipientDevices); got != want {
		t.Fatalf("bounded transient calls = %d, want %d", got, want)
	}
}

func TestConcurrentPushWorkersClaimEachDeliveryOnce(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	message := domain.Message{
		ID: uuid.New(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
	}
	raw, _ := json.Marshal(message)
	recipients, _ := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)
	if err := fixture.relay.enqueuePush(fixture.ctx, domain.OutboxEvent{
		ID: 104, Topic: "message.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); err != nil {
		t.Fatal(err)
	}
	secondWorker := New(fixture.store, nil, fixture.push, media.Unavailable{}, fixture.relay.logger)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); fixture.relay.flushPush(fixture.ctx) }()
	go func() { defer workers.Done(); secondWorker.flushPush(fixture.ctx) }()
	workers.Wait()
	if got := fixture.push.callCount(); got != len(fixture.recipientDevices) {
		t.Fatalf("concurrent worker calls = %d, want %d", got, len(fixture.recipientDevices))
	}
}

func TestBlockedAPNSWorkerDoesNotBlockRealtimeOutbox(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	initial, err := fixture.store.LockOutboxBatch(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	initialIDs := make([]int64, 0, len(initial))
	for _, event := range initial {
		initialIDs = append(initialIDs, event.ID)
	}
	if err := fixture.store.MarkOutboxPublished(fixture.ctx, initialIDs); err != nil {
		t.Fatal(err)
	}
	bus := &countingBus{}
	blocked := &blockingPush{started: make(chan struct{}), release: make(chan struct{})}
	fixture.relay.bus = bus
	fixture.relay.push = blocked
	createMessage := func() {
		if _, _, err := fixture.store.CreateMessage(fixture.ctx, store.CreateMessageParams{
			ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: fixture.conversation.ID,
			SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
			ContentType: "text", Ciphertext: "encrypted",
		}); err != nil {
			t.Fatal(err)
		}
	}
	createMessage()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(blocked.release)
	done := make(chan struct{})
	go func() {
		defer close(done)
		fixture.relay.Run(ctx)
	}()
	select {
	case <-blocked.started:
	case <-time.After(2 * time.Second):
		t.Fatal("push worker did not start")
	}
	createMessage()
	deadline := time.Now().Add(2 * time.Second)
	for bus.publishCount.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := bus.publishCount.Load(); got != 2 {
		t.Fatalf("realtime publishes while APNs blocked = %d, want 2", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not stop")
	}
}

func notificationForEntity(
	t *testing.T,
	fixture *relayFixture,
	entity domain.Entity,
	recipients []uuid.UUID,
) activityNotification {
	t.Helper()
	raw, _ := json.Marshal(entity)
	notification, ok, err := fixture.relay.notificationFor(fixture.ctx, domain.OutboxEvent{
		Topic: "entity.updated", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("entity did not generate a notification")
	}
	return notification
}

func drainFixtureOutbox(t *testing.T, fixture *relayFixture) {
	t.Helper()
	events, err := fixture.store.LockOutboxBatch(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.ID)
	}
	if err := fixture.store.MarkOutboxPublished(fixture.ctx, ids); err != nil {
		t.Fatal(err)
	}
}

type relayFixture struct {
	ctx              context.Context
	store            *memory.Store
	relay            *Relay
	push             *recordingPush
	actor            domain.User
	recipient        domain.User
	conversation     domain.Conversation
	actorDevices     []domain.Device
	recipientDevices []domain.Device
	outsiderDevices  []domain.Device
}

func newRelayFixture(t *testing.T, metadata json.RawMessage) *relayFixture {
	t.Helper()
	ctx := context.Background()
	persistence := memory.New()
	actor := createUser(t, persistence, "actor@example.com", "Akhil")
	recipient := createUser(t, persistence, "recipient@example.com", "Bailey")
	outsider := createUser(t, persistence, "outsider@example.com", "Casey")
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Group 1", Metadata: metadata,
		CreatedBy: actor.ID, MemberIDs: []uuid.UUID{recipient.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	actorDevices := []domain.Device{
		createDevice(t, persistence, actor.ID, "aa"),
		createDevice(t, persistence, actor.ID, "ab"),
	}
	recipientDevices := []domain.Device{
		createDevice(t, persistence, recipient.ID, "ba"),
		createDevice(t, persistence, recipient.ID, "bb"),
	}
	outsiderDevices := []domain.Device{createDevice(t, persistence, outsider.ID, "ca")}
	recorder := &recordingPush{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &relayFixture{
		ctx: ctx, store: persistence, relay: New(persistence, nil, recorder, media.Unavailable{}, logger), push: recorder,
		actor: actor, recipient: recipient, conversation: conversation,
		actorDevices: actorDevices, recipientDevices: recipientDevices, outsiderDevices: outsiderDevices,
	}
}

func createUser(t *testing.T, persistence *memory.Store, email, displayName string) domain.User {
	t.Helper()
	user, err := persistence.CreateUser(context.Background(), store.CreateUserParams{
		Email: email, DisplayName: displayName,
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func createDevice(t *testing.T, persistence *memory.Store, userID uuid.UUID, token string) domain.Device {
	t.Helper()
	device, err := persistence.UpsertDevice(context.Background(), domain.Device{
		ID: uuid.New(), UserID: userID, Name: "iPhone", Platform: "ios", PushToken: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

type pushCall struct {
	token, title, body, notificationID string
	data                               map[string]string
}

type recordingPush struct {
	mu     sync.Mutex
	calls  []pushCall
	errors map[string]error
}

func (r *recordingPush) Send(
	_ context.Context,
	token, title, body string,
	data map[string]string,
	notificationID string,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	copyData := make(map[string]string, len(data))
	for key, value := range data {
		copyData[key] = value
	}
	r.calls = append(r.calls, pushCall{
		token: token, title: title, body: body, data: copyData, notificationID: notificationID,
	})
	return r.errors[token]
}

func (r *recordingPush) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (*recordingPush) Close() {}

type blockingPush struct {
	startedOnce sync.Once
	started     chan struct{}
	release     chan struct{}
}

func (b *blockingPush) Send(
	ctx context.Context,
	_ string, _, _ string,
	_ map[string]string,
	_ string,
) error {
	b.startedOnce.Do(func() { close(b.started) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.release:
		return nil
	}
}

func (*blockingPush) Close() {}

type conversationLookupStore struct {
	store.Store
	err error
}

func (s *conversationLookupStore) Conversation(
	ctx context.Context,
	conversationID, userID uuid.UUID,
) (domain.Conversation, error) {
	if s.err != nil {
		return domain.Conversation{}, s.err
	}
	return s.Store.Conversation(ctx, conversationID, userID)
}

type retentionRecordingStore struct {
	store.Store
	calls                             []string
	deliveredBefore, deadLetterBefore time.Time
	publishedBefore                   time.Time
	pushLimit, outboxLimit            int
	pushDeleted, outboxDeleted        int64
}

func (s *retentionRecordingStore) PrunePushDeliveries(
	_ context.Context,
	deliveredBefore, deadLetterBefore time.Time,
	limit int,
) (int64, error) {
	s.calls = append(s.calls, "push")
	s.deliveredBefore = deliveredBefore
	s.deadLetterBefore = deadLetterBefore
	s.pushLimit = limit
	return s.pushDeleted, nil
}

func (s *retentionRecordingStore) PrunePublishedOutbox(
	_ context.Context,
	publishedBefore time.Time,
	limit int,
) (int64, error) {
	s.calls = append(s.calls, "outbox")
	s.publishedBefore = publishedBefore
	s.outboxLimit = limit
	return s.outboxDeleted, nil
}

type countingBus struct {
	publishCount atomic.Int32
	err          error
}

func (*countingBus) Ping(context.Context) error { return nil }

func (b *countingBus) Publish(context.Context, []uuid.UUID, domain.RealtimeEvent) error {
	b.publishCount.Add(1)
	return b.err
}

func (*countingBus) Subscribe(context.Context, uuid.UUID) (events.Subscription, error) {
	return nil, errors.New("not implemented")
}

func (*countingBus) Close() {}

type recordingMedia struct {
	deleted   []string
	deleteErr error
}

func (*recordingMedia) UploadURL(context.Context, string, string, int64, time.Duration) (*url.URL, error) {
	return nil, media.ErrUnavailable
}

func (*recordingMedia) DownloadURL(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, media.ErrUnavailable
}

func (*recordingMedia) Verify(context.Context, string, int64, string) error {
	return media.ErrUnavailable
}

func (r *recordingMedia) Delete(_ context.Context, objectKey string) error {
	r.deleted = append(r.deleted, objectKey)
	return r.deleteErr
}

func (*recordingMedia) Close() {}
