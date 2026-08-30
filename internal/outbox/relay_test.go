package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
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
	created, err := persistence.CreateMedia(ctx, object, store.DefaultMediaReservationLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
		t.Fatal(err)
	}

	mediaRecorder := &recordingMedia{deleteErr: errors.New("minio temporarily unavailable")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	relay := New(persistence, nil, &recordingPush{}, mediaRecorder, logger)
	relay.flushMediaDeletes(ctx)
	if len(mediaRecorder.deleted) != 0 {
		t.Fatalf("object deletion ran before in-flight upload grace elapsed: %v", mediaRecorder.deleted)
	}
	relay.now = func() time.Time { return created.ExpiresAt.UTC().Add(store.MediaDeleteGrace + time.Second) }
	queued, err := persistence.LockOutboxBatch(ctx, 100)
	if err != nil || len(queued) != 1 {
		t.Fatalf("inspect queued deletion: events=%+v error=%v", queued, err)
	}
	if err := persistence.ReleaseOutboxEvent(ctx, queued[0].ID, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	relay.flushMediaDeletes(ctx)
	events, err := persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(mediaRecorder.deleted) != 2 {
		t.Fatalf("failed deletion was not retained for retry: events=%+v calls=%+v", events, mediaRecorder.deleted)
	}

	mediaRecorder.deleteErr = nil
	if err := persistence.ReleaseOutboxEvent(ctx, events[0].ID, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	relay.flushMediaDeletes(ctx)
	events, err = persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 || len(mediaRecorder.deleted) != 4 {
		t.Fatalf("successful deletion was not acknowledged: events=%+v calls=%+v", events, mediaRecorder.deleted)
	}
}

func TestBlockedMediaDeleteDoesNotDelayRealtimePublishing(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	drainFixtureOutbox(t, fixture)
	object := domain.MediaObject{
		ID: uuid.New(), OwnerID: fixture.actor.ID, ConversationID: fixture.conversation.ID,
		ObjectKey: "private/blocked-delete", ContentType: "application/octet-stream", ByteSize: 3,
		CiphertextSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	created, err := fixture.store.CreateMedia(
		fixture.ctx, object, store.DefaultMediaReservationLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.DeleteMedia(fixture.ctx, created.ID, fixture.actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.CreateMessage(fixture.ctx, store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
		ContentType: "text", Ciphertext: "encrypted",
	}); err != nil {
		t.Fatal(err)
	}
	queued, err := fixture.store.LockOutboxBatch(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var deleteID int64
	for _, event := range queued {
		if event.Topic == "media.delete" {
			deleteID = event.ID
		}
	}
	if deleteID == 0 {
		t.Fatal("media deletion was not durably queued")
	}
	if err := fixture.store.ReleaseOutboxEvent(
		fixture.ctx, deleteID, time.Now().UTC().Add(-time.Second),
	); err != nil {
		t.Fatal(err)
	}
	blocked := &blockingDeleteMedia{
		entered: make(chan struct{}, 1), release: make(chan struct{}),
	}
	bus := &countingBus{}
	fixture.relay.media = blocked
	fixture.relay.bus = bus
	fixture.relay.mediaDeleteTimeout = 2 * time.Second
	fixture.relay.now = func() time.Time {
		return created.UploadValidUntil.Add(store.MediaDeleteGrace + time.Second)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fixture.relay.flushMediaDeletes(fixture.ctx)
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("media deletion did not start")
	}
	fixture.relay.flush(fixture.ctx)
	if got := bus.publishCount.Load(); got != 1 {
		t.Fatalf("realtime publishes while object deletion blocked=%d, want 1", got)
	}
	close(blocked.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("media deletion did not finish after release")
	}
}

func TestTopicSpecificOutboxClaimsIsolateMediaDeletion(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Roommates"}`))
	drainFixtureOutbox(t, fixture)
	object := domain.MediaObject{
		ID: uuid.New(), OwnerID: fixture.actor.ID, ConversationID: fixture.conversation.ID,
		ObjectKey: "private/topic-isolation", ContentType: "application/octet-stream", ByteSize: 3,
		CiphertextSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	created, err := fixture.store.CreateMedia(
		fixture.ctx, object, store.DefaultMediaReservationLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.DeleteMedia(fixture.ctx, created.ID, fixture.actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.CreateMessage(fixture.ctx, store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: fixture.conversation.ID,
		SenderID: fixture.actor.ID, SenderDeviceID: fixture.actorDevices[0].ID,
		ContentType: "text", Ciphertext: "encrypted",
	}); err != nil {
		t.Fatal(err)
	}
	inspection, err := fixture.store.LockOutboxBatch(fixture.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var mediaDeleteID int64
	for _, event := range inspection {
		if event.Topic == "media.delete" {
			mediaDeleteID = event.ID
		}
	}
	if mediaDeleteID == 0 {
		t.Fatal("missing media.delete event")
	}
	if err := fixture.store.ReleaseOutboxEvent(
		fixture.ctx, mediaDeleteID, time.Now().UTC().Add(-time.Second),
	); err != nil {
		t.Fatal(err)
	}
	realtime, err := fixture.store.LockRealtimeOutboxBatch(fixture.ctx, 100)
	if err != nil || len(realtime) != 1 || realtime[0].Topic == "media.delete" {
		t.Fatalf("realtime claim crossed topic boundary: events=%+v error=%v", realtime, err)
	}
	deletions, err := fixture.store.LockMediaDeleteOutboxBatch(fixture.ctx, 100)
	if err != nil || len(deletions) != 1 || deletions[0].Topic != "media.delete" {
		t.Fatalf("media-delete claim crossed topic boundary: events=%+v error=%v", deletions, err)
	}
}

func TestMediaDeleteUsesBoundedConcurrencyAndPerObjectTimeout(t *testing.T) {
	recorder := &concurrentDeleteMedia{delay: 25 * time.Millisecond}
	relay := New(
		memory.New(), nil, &recordingPush{}, recorder,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	relay.mediaDeleteTimeout = time.Second
	keys := make([]string, 12)
	for index := range keys {
		keys[index] = "private/bounded-" + strconv.Itoa(index)
	}
	payload, _ := json.Marshal(store.NewMediaDeletePayloadAt(keys, time.Now().UTC().Add(-time.Second)))
	if err := relay.deleteMedia(context.Background(), domain.OutboxEvent{Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if maximum := recorder.maximum.Load(); maximum < 2 || maximum > mediaDeleteConcurrency {
		t.Fatalf("delete concurrency=%d, want 2..%d", maximum, mediaDeleteConcurrency)
	}

	blocked := &blockingDeleteMedia{entered: make(chan struct{}, 1), release: make(chan struct{})}
	relay.media = blocked
	relay.mediaDeleteTimeout = 20 * time.Millisecond
	payload, _ = json.Marshal(store.NewMediaDeletePayloadAt(
		[]string{"private/timeout"}, time.Now().UTC().Add(-time.Second),
	))
	started := time.Now()
	err := relay.deleteMedia(context.Background(), domain.OutboxEvent{Payload: payload})
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("blocked delete error=%v duration=%s", err, time.Since(started))
	}
}

func TestRejectedUploadIsDeletedFromRealMinIOAfterURLExpiryGrace(t *testing.T) {
	endpoint := os.Getenv("TEST_MINIO_ENDPOINT")
	accessKey := os.Getenv("TEST_MINIO_ACCESS_KEY")
	secretKey := os.Getenv("TEST_MINIO_SECRET_KEY")
	if endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skip("TEST_MINIO_ENDPOINT, TEST_MINIO_ACCESS_KEY, and TEST_MINIO_SECRET_KEY are not configured")
	}
	useTLS, err := strconv.ParseBool(testEnvOr("TEST_MINIO_USE_TLS", "false"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	mediaService, err := media.NewS3(
		ctx, endpoint, endpoint, accessKey, secretKey,
		testEnvOr("TEST_MINIO_BUCKET", "clustr-media-integration"), useTLS, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer mediaService.Close()

	persistence := memory.New()
	defer persistence.Close()
	user := createUser(t, persistence, "minio-reject-"+uuid.NewString()+"@example.com", "MinIO Reject")
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	initialIDs := make([]int64, 0, len(initial))
	for _, event := range initial {
		initialIDs = append(initialIDs, event.ID)
	}
	if err := persistence.MarkOutboxPublished(ctx, initialIDs); err != nil {
		t.Fatal(err)
	}

	const digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	object := domain.MediaObject{
		ID: uuid.New(), OwnerID: user.ID, ConversationID: conversation.ID,
		ObjectKey: "rejection/" + uuid.NewString(), ContentType: "application/octet-stream",
		ByteSize: 3, CiphertextSHA256: digest,
	}
	created, err := persistence.CreateMedia(ctx, object, store.DefaultMediaReservationLimits())
	if err != nil {
		t.Fatal(err)
	}
	upload, err := mediaService.PrepareUpload(
		ctx, created.ObjectKey, created.ContentType, created.ByteSize,
		created.CiphertextSHA256, 5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, upload.Method, upload.URL.String(), bytes.NewReader([]byte("abc")))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range upload.Headers {
		request.Header.Set(name, value)
	}
	request.ContentLength = 3
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("upload status=%d", response.StatusCode)
	}
	if _, err := persistence.RejectPendingMedia(ctx, created.ID, user.ID); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	relay := New(persistence, nil, &recordingPush{}, mediaService, logger)
	deletePayload, err := json.Marshal(store.NewMediaDeletePayloadAt(
		[]string{created.ObjectKey}, created.UploadValidUntil.Add(store.MediaDeleteGrace),
	))
	if err != nil {
		t.Fatal(err)
	}
	deleteEvent := domain.OutboxEvent{ID: 1, Topic: "media.delete", Payload: deletePayload}
	relay.now = func() time.Time { return created.ExpiresAt.UTC().Add(store.MediaDeleteGrace - time.Second) }
	if err := relay.deleteMedia(ctx, deleteEvent); !errors.Is(err, errMediaDeleteNotDue) {
		t.Fatalf("pre-deadline delete error=%v", err)
	}
	if err := mediaService.Verify(ctx, created.ObjectKey, 3, digest, created.ContentType); err != nil {
		t.Fatalf("object deleted before URL expiry grace: %v", err)
	}
	relay.now = func() time.Time { return created.ExpiresAt.UTC().Add(store.MediaDeleteGrace + time.Second) }
	if err := relay.deleteMedia(ctx, deleteEvent); err != nil {
		t.Fatal(err)
	}
	if err := mediaService.Verify(ctx, created.ObjectKey, 3, digest, created.ContentType); !media.IsDefinitiveVerificationFailure(err) {
		t.Fatalf("rejected object survived deletion grace: %v", err)
	}
}

func testEnvOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
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
	if err := fixture.store.ReleaseOutboxEvent(
		fixture.ctx, remaining[0].ID, time.Now().UTC().Add(-time.Second),
	); err != nil {
		t.Fatal(err)
	}
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

func TestRetentionDrainsMultipleBatchesAndSchedulesOneMinuteCatchUp(t *testing.T) {
	now := time.Date(2026, time.August, 26, 21, 0, 0, 0, time.UTC)
	recorder := &retentionRecordingStore{
		Store:         memory.New(),
		pushResults:   []int64{1000, 1000, 37},
		outboxResults: []int64{1000, 12},
	}
	relay := New(
		recorder, nil, &recordingPush{}, media.Unavailable{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	relay.now = func() time.Time { return now }
	relay.lastPrune = now.Add(-retentionInterval)
	relay.pruneRetention(context.Background())
	want := []string{"push", "push", "push", "outbox", "outbox"}
	if len(recorder.calls) != len(want) {
		t.Fatalf("multi-batch retention calls=%v want=%v", recorder.calls, want)
	}
	for index := range want {
		if recorder.calls[index] != want[index] {
			t.Fatalf("multi-batch retention calls=%v want=%v", recorder.calls, want)
		}
	}

	recorder.calls = nil
	recorder.pushResults = make([]int64, retentionMaxBatches)
	for index := range recorder.pushResults {
		recorder.pushResults[index] = store.MaxRetentionPruneBatchSize
	}
	recorder.outboxResults = []int64{0}
	now = now.Add(retentionInterval)
	relay.pruneRetention(context.Background())
	if len(recorder.calls) != retentionMaxBatches {
		t.Fatalf("bounded drain calls=%d want=%d", len(recorder.calls), retentionMaxBatches)
	}
	for _, call := range recorder.calls {
		if call != "push" {
			t.Fatalf("parent outbox pruned before child backlog drained: %v", recorder.calls)
		}
	}
	callsAfterBudget := len(recorder.calls)
	now = now.Add(retentionCatchUpInterval - time.Second)
	relay.pruneRetention(context.Background())
	if len(recorder.calls) != callsAfterBudget {
		t.Fatalf("catch-up ran before one minute: %d -> %d", callsAfterBudget, len(recorder.calls))
	}
	now = now.Add(time.Second)
	recorder.pushResults = []int64{0}
	recorder.outboxResults = []int64{0}
	relay.pruneRetention(context.Background())
	if len(recorder.calls) != callsAfterBudget+2 ||
		recorder.calls[len(recorder.calls)-2] != "push" || recorder.calls[len(recorder.calls)-1] != "outbox" {
		t.Fatalf("one-minute catch-up did not resume child-first drain: %v", recorder.calls)
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
	pushResults, outboxResults        []int64
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
	if len(s.pushResults) > 0 {
		deleted := s.pushResults[0]
		s.pushResults = s.pushResults[1:]
		return deleted, nil
	}
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
	if len(s.outboxResults) > 0 {
		deleted := s.outboxResults[0]
		s.outboxResults = s.outboxResults[1:]
		return deleted, nil
	}
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

func (*countingBus) RegisterSessionOwner(context.Context, uuid.UUID, uuid.UUID, events.SessionFence) (events.SessionOwner, error) {
	return nil, errors.New("not implemented")
}

func (*countingBus) FenceSessions(context.Context, uuid.UUID, *uuid.UUID) (events.SessionFenceTicket, error) {
	return nil, nil
}

func (*countingBus) Close() {}

type recordingMedia struct {
	mu        sync.Mutex
	deleted   []string
	deleteErr error
}

func (*recordingMedia) PrepareUpload(context.Context, string, string, int64, string, time.Duration) (media.UploadInstructions, error) {
	return media.UploadInstructions{}, media.ErrUnavailable
}

func (*recordingMedia) DownloadURL(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, media.ErrUnavailable
}

func (*recordingMedia) FinalizeUpload(context.Context, string, string, int64, string, string) (string, error) {
	return "", media.ErrUnavailable
}

func (r *recordingMedia) Delete(_ context.Context, objectKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted = append(r.deleted, objectKey)
	return r.deleteErr
}

func (*recordingMedia) Close() {}

type blockingDeleteMedia struct {
	entered chan struct{}
	release chan struct{}
}

func (*blockingDeleteMedia) PrepareUpload(context.Context, string, string, int64, string, time.Duration) (media.UploadInstructions, error) {
	return media.UploadInstructions{}, media.ErrUnavailable
}

func (*blockingDeleteMedia) DownloadURL(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, media.ErrUnavailable
}

func (*blockingDeleteMedia) FinalizeUpload(context.Context, string, string, int64, string, string) (string, error) {
	return "", media.ErrUnavailable
}

func (m *blockingDeleteMedia) Delete(ctx context.Context, _ string) error {
	select {
	case m.entered <- struct{}{}:
	default:
	}
	select {
	case <-m.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*blockingDeleteMedia) Close() {}

type concurrentDeleteMedia struct {
	active  atomic.Int32
	maximum atomic.Int32
	delay   time.Duration
}

func (*concurrentDeleteMedia) PrepareUpload(context.Context, string, string, int64, string, time.Duration) (media.UploadInstructions, error) {
	return media.UploadInstructions{}, media.ErrUnavailable
}

func (*concurrentDeleteMedia) DownloadURL(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, media.ErrUnavailable
}

func (*concurrentDeleteMedia) FinalizeUpload(context.Context, string, string, int64, string, string) (string, error) {
	return "", media.ErrUnavailable
}

func (m *concurrentDeleteMedia) Delete(ctx context.Context, _ string) error {
	current := m.active.Add(1)
	defer m.active.Add(-1)
	for {
		maximum := m.maximum.Load()
		if current <= maximum || m.maximum.CompareAndSwap(maximum, current) {
			break
		}
	}
	timer := time.NewTimer(m.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*concurrentDeleteMedia) Close() {}
