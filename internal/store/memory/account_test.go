package memory

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestUpdateUserProfileMergesSparsePatches(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	t.Cleanup(persistence.Close)
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "profile-merge@example.com", DisplayName: "Original", PasswordHash: "hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err = persistence.UpdateUserProfile(ctx, user.ID, json.RawMessage(
		`{"display_name":"Merged","username":"@merge_user","bio":"first"}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	user, err = persistence.UpdateUserProfile(ctx, user.ID, json.RawMessage(
		`{"bio":"second","auto_settle_settings":{"enabled":true}}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err := json.Unmarshal(user.Profile, &profile); err != nil {
		t.Fatal(err)
	}
	if profile["username"] != "@merge_user" || profile["display_name"] != "Merged" ||
		profile["bio"] != "second" {
		t.Fatalf("sparse update replaced unrelated fields: %s", user.Profile)
	}
	users, err := persistence.UsersByUsernames(ctx, []string{"@merge_user"})
	if err != nil || len(users) != 1 {
		t.Fatalf("username index was not preserved: users=%+v err=%v", users, err)
	}
	if _, err := persistence.UpdateUserProfile(ctx, user.ID, json.RawMessage(`{"username":null}`)); err != nil {
		t.Fatal(err)
	}
	users, err = persistence.UsersByUsernames(ctx, []string{"@merge_user"})
	if err != nil || len(users) != 0 {
		t.Fatalf("cleared username remained indexed: users=%+v err=%v", users, err)
	}
}

func TestDeleteAccountErasesPrivateStateAndQueuesPersonalMediaDeletion(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "erase@example.com", Phone: "+13125550177", DisplayName: "Erase Me",
		PasswordHash: "secret-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err = persistence.UpdateUserProfile(ctx, user.ID, json.RawMessage(`{
		"display_name":"Erase Me","username":"@erase_me","bio":"private"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.LinkExternalIdentity(ctx, "apple", "apple-subject", user.ID, user.Email); err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: user.ID, Name: "Private iPhone", Platform: "ios",
		PushToken: "push-secret", IdentityKey: "identity-secret",
		SignedPreKey: json.RawMessage(`{"key":"signed-secret"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.PutOneTimePreKeys(ctx, device.ID, []domain.OneTimePreKey{{
		KeyID: 1, PublicKey: "one-time-secret",
	}}); err != nil {
		t.Fatal(err)
	}
	session := domain.Session{
		ID: uuid.New(), UserID: user.ID, DeviceID: device.ID,
		RefreshTokenHash: []byte("refresh-secret"), CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := persistence.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	resetChallenge := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: user.ID, CodeHash: []byte("reset-secret"),
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute), CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreatePasswordResetChallenge(ctx, resetChallenge); err != nil {
		t.Fatal(err)
	}
	personal, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Private", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	mediaObject := domain.MediaObject{
		ID: uuid.New(), OwnerID: user.ID, ConversationID: personal.ID,
		ObjectKey: "users/erase/private-object", ContentType: "image/jpeg", ByteSize: 42,
	}
	if _, err := persistence.CreateMedia(ctx, mediaObject, store.DefaultMediaReservationLimits()); err != nil {
		t.Fatal(err)
	}

	if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := persistence.passwordResets[resetChallenge.ID]; ok {
		t.Fatal("password reset challenge remained after account deletion")
	}
	for label, lookup := range map[string]func() error{
		"email": func() error { _, err := persistence.UserByEmail(ctx, user.Email); return err },
		"phone": func() error { _, err := persistence.UserByPhone(ctx, user.Phone); return err },
		"apple": func() error {
			_, err := persistence.UserByExternalIdentity(ctx, "apple", "apple-subject")
			return err
		},
	} {
		if err := lookup(); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("%s lookup returned %v, want not found", label, err)
		}
	}
	users, err := persistence.UsersByUsernames(ctx, []string{"@erase_me"})
	if err != nil || len(users) != 0 {
		t.Fatalf("username remained discoverable: users=%+v err=%v", users, err)
	}
	active, err := persistence.SessionActive(ctx, session.ID, user.ID, device.ID)
	if err != nil || active {
		t.Fatalf("session remained active: active=%t err=%v", active, err)
	}
	if _, err := persistence.UserByID(ctx, user.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted user ID returned %v, want not found", err)
	}
	anonymizedDevice, err := persistence.Device(ctx, user.ID, device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if anonymizedDevice.Name != "Deleted device" || anonymizedDevice.PushToken != "" ||
		anonymizedDevice.IdentityKey != "" || len(anonymizedDevice.SignedPreKey) != 0 {
		t.Fatalf("device secrets remained: %+v", anonymizedDevice)
	}
	if _, err := persistence.Media(ctx, mediaObject.ID, user.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("personal media row returned %v, want not found", err)
	}
	events, err := persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var deletion store.MediaDeletePayload
	found := false
	for _, event := range events {
		if event.Topic == "media.delete" {
			found = true
			if err := json.Unmarshal(event.Payload, &deletion); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found || len(deletion.ObjectKeys) != 2 || deletion.ObjectKeys[0] != mediaObject.ObjectKey ||
		deletion.ObjectKeys[1] != "published/"+mediaObject.ObjectKey {
		t.Fatalf("durable media deletion was not queued: %+v", events)
	}
}

func TestDeleteAccountSanitizesLiveAndReplayableChoreCreatorPII(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	deleted, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "rotation-delete@example.com", Phone: "+13125550991",
		DisplayName: "Rotation Delete", PasswordHash: "hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err = persistence.UpdateUserProfile(ctx, deleted.ID, json.RawMessage(
		`{"username":"@rotation_delete","display_name":"Rotation Delete"}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "Remaining",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: deleted.ID, MemberIDs: []uuid.UUID{remaining.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	choreID, operationID, financialID := uuid.New(), uuid.New(), uuid.New()
	base := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` +
		conversation.ID.String() + `","createdBy":"` + deleted.ID.String() +
		`","assignedTo":"` + remaining.ID.String() + `"}`)
	chore, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "chore", ID: choreID,
		CreatedBy: deleted.ID, Payload: base,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotated := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` +
		conversation.ID.String() + `","createdBy":"` + deleted.ID.String() +
		`","assignedTo":"` + remaining.ID.String() +
		`","creatorName":"Rotation Delete","createdByDisplayName":"Rotation Delete",` +
		`"description":"Rotation Delete (@rotation_delete) rotation-delete@example.com +13125550991",` +
		`"financialId":"` + financialID.String() + `","amount":73.25}`)
	feed := json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` +
		conversation.ID.String() + `","createdBy":"` + deleted.ID.String() +
		`","relatedId":"` + choreID.String() + `","type":"note",` +
		`"creatorDisplayName":"Rotation Delete","createdByName":"Rotation Delete",` +
		`"description":"Rotation Delete <rotation-delete@example.com> @rotation_delete +13125550991",` +
		`"financialId":"` + financialID.String() + `","amount":73.25}`)
	digest := sha256.Sum256(append(append([]byte(nil), rotated...), feed...))
	if _, err := persistence.RotateChore(ctx, store.RotateChoreParams{
		OperationID: operationID, ConversationID: conversation.ID, ChoreID: choreID,
		ActorID: deleted.ID, ExpectedChoreVersion: chore.Version,
		ChorePayload: rotated, FeedPayload: feed, RequestHash: digest[:],
	}); err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}

	chores, err := persistence.ListEntities(
		ctx, conversation.ID, remaining.ID, "chore", time.Time{}, 10,
	)
	if err != nil || len(chores) != 1 {
		t.Fatalf("live chore missing: chores=%+v err=%v", chores, err)
	}
	feeds, err := persistence.ListEntities(
		ctx, conversation.ID, remaining.ID, "feed_item", time.Time{}, 10,
	)
	if err != nil || len(feeds) != 1 {
		t.Fatalf("live feed missing: feeds=%+v err=%v", feeds, err)
	}
	persistence.mu.RLock()
	operation, retained := persistence.choreRotations[operationID]
	persistence.mu.RUnlock()
	if !retained || operation.ExpiresAt.Before(time.Now().Add(89*24*time.Hour)) {
		t.Fatalf("90-day rotation replay row was not retained: %+v", operation)
	}
	replayJSON, err := json.Marshal(operation.Result)
	if err != nil {
		t.Fatal(err)
	}
	for label, raw := range map[string][]byte{
		"live chore":      chores[0].Payload,
		"live feed":       feeds[0].Payload,
		"rotation replay": replayJSON,
	} {
		text := string(raw)
		for _, forbidden := range []string{
			"Rotation Delete", "rotation-delete@example.com", "@rotation_delete", "+13125550991",
		} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
				t.Fatalf("%s retained %q: %s", label, forbidden, text)
			}
		}
		for _, retainedValue := range []string{deleted.ID.String(), financialID.String(), `"amount":73.25`} {
			if !strings.Contains(text, retainedValue) {
				t.Fatalf("%s removed shared value %q: %s", label, retainedValue, text)
			}
		}
	}
}

func TestDeleteAccountDropsSanitizedEntityOutboxAndPreservesUnrelatedEvent(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	deleted, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "outbox-delete@example.com", DisplayName: "A",
	})
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "outbox-remaining@example.com", DisplayName: "Remaining",
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
	sanitizedID, unrelatedID, settlementID := uuid.New(), uuid.New(), uuid.New()
	if _, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "note", ID: sanitizedID,
		CreatedBy: remaining.ID, Payload: json.RawMessage(`{"payer":{"backendUserId":"` +
			deleted.ID.String() + `","displayName":"\u0041"},"settlementId":"` +
			settlementID.String() + `","amount":42.75}`),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "note", ID: unrelatedID,
		CreatedBy: remaining.ID, Payload: json.RawMessage(`{"description":"A remains unrelated","amount":7}`),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}
	foundSanitized, foundUnrelated := false, false
	for _, event := range persistence.outbox {
		var entity domain.Entity
		if json.Unmarshal(event.Payload, &entity) != nil {
			continue
		}
		if entity.ID == sanitizedID {
			foundSanitized = true
			text := string(event.Payload)
			if strings.Contains(text, `"displayName":"A"`) ||
				!strings.Contains(text, settlementID.String()) || !strings.Contains(text, `"amount":42.75`) {
				t.Fatalf("sanitized event lost history or retained escaped name: %s", text)
			}
		}
		if entity.ID == unrelatedID {
			foundUnrelated = true
			if !strings.Contains(string(event.Payload), "A remains unrelated") {
				t.Fatalf("common-name collision corrupted unrelated event: %s", event.Payload)
			}
		}
	}
	if !foundSanitized {
		t.Fatal("sanitized replacement event is missing")
	}
	if !foundUnrelated {
		t.Fatal("unrelated shared-conversation event was removed")
	}
}

func TestDeleteAccountNeverMutatesSharedE2EECiphertextOrEnvelope(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	deleted, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "e2ee-delete@example.com", DisplayName: "A",
	})
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "e2ee-remaining@example.com", DisplayName: "Remaining",
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
	envelope := json.RawMessage(`{"wrappedKey":"A","header":{"nonce":"A"}}`)
	message, _, err := persistence.CreateMessage(ctx, store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: conversation.ID,
		SenderID: deleted.ID, SenderDeviceID: device.ID, ContentType: "ciphertext",
		Ciphertext: ciphertext, Envelope: envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	var eventID int64
	var before json.RawMessage
	for _, event := range persistence.outbox {
		if event.Topic == "message.created" {
			eventID = event.ID
			before = append(json.RawMessage(nil), event.Payload...)
		}
	}
	if eventID == 0 {
		t.Fatal("message outbox event is missing")
	}
	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}
	var after json.RawMessage
	for _, event := range persistence.outbox {
		if event.ID == eventID {
			after = event.Payload
		}
	}
	if string(after) != string(before) {
		t.Fatalf("E2EE outbox bytes changed during erasure:\nbefore=%s\nafter=%s", before, after)
	}
	messages, err := persistence.ListMessages(ctx, store.ListMessagesParams{
		ConversationID: conversation.ID, UserID: remaining.ID, Limit: 10,
	})
	if err != nil || len(messages) != 1 || messages[0].ID != message.ID {
		t.Fatalf("retained messages=%+v err=%v", messages, err)
	}
	if messages[0].Ciphertext != ciphertext || string(messages[0].Envelope) != string(envelope) {
		t.Fatalf("E2EE message bytes changed: ciphertext=%q envelope=%s", messages[0].Ciphertext, messages[0].Envelope)
	}
}

func TestDeleteAccountDropsStaleAffectedVersionAndPreservesSafeCurrentEventAndPush(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	deleted, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "stale-delete@example.com", DisplayName: "A",
	})
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "stale-remaining@example.com", DisplayName: "Remaining",
	})
	if err != nil {
		t.Fatal(err)
	}
	deletedDevice, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: deleted.ID, Name: "deleted", Platform: "ios",
		PushToken: "deleted-token", IdentityKey: "deleted-identity", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	remainingDevice, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: remaining.ID, Name: "remaining", Platform: "ios",
		PushToken: "remaining-token", IdentityKey: "remaining-identity", CreatedAt: time.Now().UTC(),
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
	var staleEvent, currentEvent domain.OutboxEvent
	for _, event := range persistence.outbox {
		if event.Topic != "entity.updated" {
			continue
		}
		var version domain.Entity
		if json.Unmarshal(event.Payload, &version) != nil || version.ID != entityID {
			continue
		}
		switch version.Version {
		case 1:
			staleEvent = event
		case 2:
			currentEvent = event
		}
	}
	if staleEvent.ID == 0 || currentEvent.ID == 0 {
		t.Fatalf("entity versions missing: stale=%+v current=%+v", staleEvent, currentEvent)
	}
	for _, event := range []domain.OutboxEvent{staleEvent, currentEvent} {
		inserted, err := persistence.EnqueuePushDeliveries(ctx, domain.PushDelivery{
			OutboxEventID: event.ID, ConversationID: conversation.ID, EntityID: entityID,
			NotificationID: uuid.NewString(), Title: "generic", Body: "generic", Kind: "activity",
		}, []uuid.UUID{deleted.ID, remaining.ID})
		if err != nil || inserted != 2 {
			t.Fatalf("enqueue event=%d inserted=%d err=%v", event.ID, inserted, err)
		}
	}
	currentBytes := append(json.RawMessage(nil), currentEvent.Payload...)
	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}
	seenCurrent := false
	for _, event := range persistence.outbox {
		if event.ID == staleEvent.ID {
			t.Fatal("stale identity-bearing entity version survived")
		}
		if event.ID == currentEvent.ID {
			seenCurrent = true
			if string(event.Payload) != string(currentBytes) {
				t.Fatalf("safe current event changed:\nbefore=%s\nafter=%s", currentBytes, event.Payload)
			}
		}
	}
	if !seenCurrent {
		t.Fatal("safe current entity event was removed")
	}
	for _, delivery := range persistence.pushDeliveries {
		if delivery.OutboxEventID == staleEvent.ID || delivery.DeviceID == deletedDevice.ID {
			t.Fatalf("stale/deleted-recipient push survived: %+v", delivery)
		}
		if delivery.OutboxEventID == currentEvent.ID && delivery.DeviceID != remainingDevice.ID {
			t.Fatalf("unexpected current-event push: %+v", delivery)
		}
	}
	key := conversation.ID.String() + ":expense:" + entityID.String()
	retained := persistence.entities[key]
	if string(retained.Payload) != string(safePayload) || !strings.Contains(string(retained.Payload), settlementID.String()) {
		t.Fatalf("safe financial entity changed: %s", retained.Payload)
	}
}
