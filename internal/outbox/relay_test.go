package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
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

	fixture.relay.sendPush(fixture.ctx, domain.OutboxEvent{
		Topic: "message.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients)

	if len(fixture.push.calls) != len(fixture.recipientDevices) {
		t.Fatalf("push calls = %d, want %d", len(fixture.push.calls), len(fixture.recipientDevices))
	}
	seen := map[string]bool{}
	for _, call := range fixture.push.calls {
		seen[call.token] = true
		if call.title != "Group 1" || call.body != "Akhil sent a message" {
			t.Fatalf("unexpected copy: title=%q body=%q", call.title, call.body)
		}
		if call.data["type"] != "message" ||
			call.data["groupId"] != fixture.conversation.ID.String() ||
			call.data["entityId"] != message.ID.String() {
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
	fixture.relay.sendPush(fixture.ctx, domain.OutboxEvent{
		Topic: "message.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients)

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
	if _, ok := fixture.relay.notificationFor(fixture.ctx, domain.OutboxEvent{
		Topic: "entity.updated", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); ok {
		t.Fatal("entity updates after create must not generate pushes")
	}
}

func TestSubscriptionCreateSendsOneNotificationAndSuppressesInitialCharge(t *testing.T) {
	fixture := newRelayFixture(t, json.RawMessage(`{"type":"Subscriptions"}`))
	recipients, _ := fixture.store.ConversationMemberIDs(fixture.ctx, fixture.conversation.ID)
	raw, _ := json.Marshal(fixture.conversation)
	notification, ok := fixture.relay.notificationFor(fixture.ctx, domain.OutboxEvent{
		Topic: "conversation.created", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients)
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
	if _, ok := fixture.relay.notificationFor(fixture.ctx, domain.OutboxEvent{
		Topic: "entity.updated", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients); ok {
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

func notificationForEntity(
	t *testing.T,
	fixture *relayFixture,
	entity domain.Entity,
	recipients []uuid.UUID,
) activityNotification {
	t.Helper()
	raw, _ := json.Marshal(entity)
	notification, ok := fixture.relay.notificationFor(fixture.ctx, domain.OutboxEvent{
		Topic: "entity.updated", AggregateID: fixture.conversation.ID, Payload: raw,
	}, recipients)
	if !ok {
		t.Fatal("entity did not generate a notification")
	}
	return notification
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
	calls  []pushCall
	errors map[string]error
}

func (r *recordingPush) Send(
	_ context.Context,
	token, title, body string,
	data map[string]string,
	notificationID string,
) error {
	copyData := make(map[string]string, len(data))
	for key, value := range data {
		copyData[key] = value
	}
	r.calls = append(r.calls, pushCall{
		token: token, title: title, body: body, data: copyData, notificationID: notificationID,
	})
	return r.errors[token]
}

func (*recordingPush) Close() {}

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

func (*recordingMedia) Verify(context.Context, string, int64) error { return media.ErrUnavailable }

func (r *recordingMedia) Delete(_ context.Context, objectKey string) error {
	r.deleted = append(r.deleted, objectKey)
	return r.deleteErr
}

func (*recordingMedia) Close() {}
