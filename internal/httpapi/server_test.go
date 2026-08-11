package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/appleauth"
	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/Akhilmadineni/clixor-backend/internal/presence"
	"github.com/Akhilmadineni/clixor-backend/internal/ratelimit"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/Akhilmadineni/clixor-backend/internal/verification"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type testClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func TestMessagingLifecycleAndIsolation(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	alice := registerTestUser(t, server.URL, "alice@example.com")
	bob := registerTestUser(t, server.URL, "bob@example.com")
	eve := registerTestUser(t, server.URL, "eve@example.com")

	var conversation domain.Conversation
	alice.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "direct", "member_ids": []uuid.UUID{bob.user.ID},
	}, http.StatusCreated, &conversation)
	var duplicateConversation domain.Conversation
	bob.client.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "direct", "member_ids": []uuid.UUID{alice.user.ID},
	}, http.StatusCreated, &duplicateConversation)
	if duplicateConversation.ID != conversation.ID {
		t.Fatalf("direct conversation was duplicated: %s != %s", duplicateConversation.ID, conversation.ID)
	}

	var listed domain.Page[domain.Conversation]
	bob.client.do(t, http.MethodGet, "/v1/conversations/", nil, http.StatusOK, &listed)
	if len(listed.Items) != 1 || listed.Items[0].ID != conversation.ID {
		t.Fatalf("bob did not receive conversation: %+v", listed.Items)
	}
	eve.client.do(t, http.MethodGet, "/v1/conversations/"+conversation.ID.String(),
		nil, http.StatusForbidden, nil)

	body := map[string]any{
		"client_message_id": uuid.NewString(),
		"content_type":      "text",
		"ciphertext":        base64.StdEncoding.EncodeToString([]byte("opaque encrypted bytes")),
		"envelope":          map[string]any{"protocol": "signal-v1", "counter": 1},
	}
	var first domain.Message
	alice.do(t, http.MethodPost, "/v1/conversations/"+conversation.ID.String()+"/messages",
		body, http.StatusCreated, &first)
	var duplicate domain.Message
	alice.do(t, http.MethodPost, "/v1/conversations/"+conversation.ID.String()+"/messages",
		body, http.StatusCreated, &duplicate)
	if first.ID != duplicate.ID || first.Seq != duplicate.Seq || first.Seq != 1 {
		t.Fatalf("idempotent retry created a second message: first=%+v duplicate=%+v", first, duplicate)
	}

	var messages domain.Page[domain.Message]
	bob.client.do(t, http.MethodGet,
		"/v1/conversations/"+conversation.ID.String()+"/messages?after_seq=0",
		nil, http.StatusOK, &messages)
	if len(messages.Items) != 1 || messages.Items[0].Ciphertext != body["ciphertext"] {
		t.Fatalf("unexpected message replay: %+v", messages.Items)
	}

	bob.client.do(t, http.MethodPut, "/v1/conversations/"+conversation.ID.String()+"/receipt",
		map[string]any{"delivered_seq": 1, "read_seq": 1}, http.StatusOK, nil)
	bob.client.do(t, http.MethodPut, "/v1/conversations/"+conversation.ID.String()+"/receipt",
		map[string]any{"delivered_seq": 0, "read_seq": 0}, http.StatusConflict, nil)
	bob.client.do(t, http.MethodPut, "/v1/conversations/"+conversation.ID.String()+"/receipt",
		map[string]any{"delivered_seq": 2, "read_seq": 2}, http.StatusUnprocessableEntity, nil)
	var receipts domain.Page[domain.Receipt]
	alice.do(t, http.MethodGet, "/v1/conversations/"+conversation.ID.String()+"/receipts",
		nil, http.StatusOK, &receipts)
	if len(receipts.Items) != 1 || receipts.Items[0].UserID != bob.user.ID {
		t.Fatalf("receipt replay returned unexpected state: %+v", receipts.Items)
	}

	entityID := uuid.New()
	var entity domain.Entity
	alice.do(t, http.MethodPut,
		"/v1/conversations/"+conversation.ID.String()+"/entities/task/"+entityID.String()+"?expected_version=0",
		map[string]any{"title": "Encrypted group task metadata"}, http.StatusOK, &entity)
	if entity.Version != 1 {
		t.Fatalf("unexpected entity version: %+v", entity)
	}
	alice.do(t, http.MethodPut,
		"/v1/conversations/"+conversation.ID.String()+"/entities/task/"+entityID.String()+"?expected_version=0",
		map[string]any{"title": "stale overwrite"}, http.StatusConflict, nil)
	alice.do(t, http.MethodDelete,
		"/v1/conversations/"+conversation.ID.String()+"/entities/task/"+entityID.String()+"?expected_version=1",
		nil, http.StatusNoContent, nil)
	var entities domain.Page[domain.Entity]
	bob.client.do(t, http.MethodGet,
		"/v1/conversations/"+conversation.ID.String()+"/entities/task",
		nil, http.StatusOK, &entities)
	if len(entities.Items) != 1 || entities.Items[0].DeletedAt == nil || entities.Items[0].Version != 2 {
		t.Fatalf("entity tombstone did not replay: %+v", entities.Items)
	}
}

func TestRealtimeMessageDelivery(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	alice := registerTestUser(t, server.URL, "realtime-alice@example.com")
	bob := registerTestUser(t, server.URL, "realtime-bob@example.com")

	var conversation domain.Conversation
	alice.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "direct", "member_ids": []uuid.UUID{bob.user.ID},
	}, http.StatusCreated, &conversation)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/realtime"
	headers := http.Header{"Authorization": []string{"Bearer " + bob.client.token}}
	socket, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hello domain.RealtimeEvent
	if err := socket.ReadJSON(&hello); err != nil || hello.Type != "session.ready" {
		t.Fatalf("missing realtime hello: event=%+v err=%v", hello, err)
	}

	alice.do(t, http.MethodPost, "/v1/conversations/"+conversation.ID.String()+"/messages",
		map[string]any{
			"client_message_id": uuid.NewString(),
			"content_type":      "text",
			"ciphertext":        base64.StdEncoding.EncodeToString([]byte("encrypted")),
		}, http.StatusCreated, nil)

	var event domain.RealtimeEvent
	if err := socket.ReadJSON(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "message.created" || event.Seq != 1 || event.ConversationID == nil ||
		*event.ConversationID != conversation.ID {
		t.Fatalf("unexpected realtime event: %+v", event)
	}
}

func TestGroupMembershipInvariantsAndOwnershipTransfer(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	alice := registerTestUser(t, server.URL, "group-owner@example.com")
	bob := registerTestUser(t, server.URL, "group-member@example.com")
	eve := registerTestUser(t, server.URL, "group-invitee@example.com")

	alice.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "direct", "member_ids": []uuid.UUID{alice.user.ID},
	}, http.StatusUnprocessableEntity, nil)

	var direct domain.Conversation
	alice.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "direct", "member_ids": []uuid.UUID{bob.user.ID},
	}, http.StatusCreated, &direct)
	alice.do(t, http.MethodPost, "/v1/conversations/"+direct.ID.String()+"/members", map[string]any{
		"user_id": eve.user.ID, "role": "member",
	}, http.StatusUnprocessableEntity, nil)

	var group domain.Conversation
	alice.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "Trip", "member_ids": []uuid.UUID{bob.user.ID},
	}, http.StatusCreated, &group)
	bob.client.do(t, http.MethodPost, "/v1/conversations/"+group.ID.String()+"/members", map[string]any{
		"user_id": eve.user.ID, "role": "member",
	}, http.StatusForbidden, nil)
	alice.do(t, http.MethodPost, "/v1/conversations/"+group.ID.String()+"/members", map[string]any{
		"user_id": eve.user.ID, "role": "member",
	}, http.StatusNoContent, nil)
	bob.client.do(t, http.MethodDelete,
		"/v1/conversations/"+group.ID.String()+"/members/"+alice.user.ID.String(),
		nil, http.StatusForbidden, nil)
	alice.do(t, http.MethodPut, "/v1/conversations/"+group.ID.String()+"/owner", map[string]any{
		"user_id": bob.user.ID,
	}, http.StatusNoContent, nil)
	bob.client.do(t, http.MethodDelete,
		"/v1/conversations/"+group.ID.String()+"/members/"+alice.user.ID.String(),
		nil, http.StatusNoContent, nil)
	alice.do(t, http.MethodGet, "/v1/conversations/"+group.ID.String(),
		nil, http.StatusForbidden, nil)
}

func TestRefreshTokenRotation(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	user := registerTestUser(t, server.URL, "refresh@example.com")

	var refreshed auth.TokenPair
	user.client.do(t, http.MethodPost, "/v1/auth/refresh",
		map[string]any{"refresh_token": user.tokens.RefreshToken}, http.StatusOK, &refreshed)
	if refreshed.RefreshToken == user.tokens.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	user.client.do(t, http.MethodPost, "/v1/auth/refresh",
		map[string]any{"refresh_token": user.tokens.RefreshToken}, http.StatusUnauthorized, nil)
	user.client.do(t, http.MethodPost, "/v1/auth/refresh",
		map[string]any{"refresh_token": refreshed.RefreshToken}, http.StatusUnauthorized, nil)
}

func TestRegistrationAllocatesAccountBoundDeviceIdentity(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	reusedInstallationID := uuid.New()

	register := func(email string) authResponse {
		t.Helper()
		var response authResponse
		client.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
			"email": email, "password": "very-secure-test-password", "display_name": email,
			"device_id": reusedInstallationID, "device_name": "Test iPhone", "platform": "ios",
		}, http.StatusCreated, &response)
		return response
	}

	first := register("device-owner-a@example.com")
	second := register("device-owner-b@example.com")
	if first.Device.ID == reusedInstallationID || second.Device.ID == reusedInstallationID {
		t.Fatal("registration accepted a client device ID that may belong to another account")
	}
	if first.Device.ID == second.Device.ID {
		t.Fatal("separate accounts received the same device identity")
	}
}

func TestLogoutImmediatelyRevokesAccessSession(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	user := registerTestUser(t, server.URL, "logout@example.com")
	user.client.do(t, http.MethodPost, "/v1/auth/logout", map[string]any{},
		http.StatusNoContent, nil)
	user.client.do(t, http.MethodGet, "/v1/me", nil, http.StatusUnauthorized, nil)
}

func TestPhoneVerificationCreatesAndReusesAccount(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	client.do(t, http.MethodPost, "/v1/auth/phone/start",
		map[string]any{"phone": "+13125550123"}, http.StatusAccepted, nil)

	var first authResponse
	client.do(t, http.MethodPost, "/v1/auth/phone/verify", map[string]any{
		"phone": "+13125550123", "code": "000000", "device_name": "iPhone", "platform": "ios",
	}, http.StatusOK, &first)
	var second authResponse
	client.do(t, http.MethodPost, "/v1/auth/phone/verify", map[string]any{
		"phone": "+13125550123", "code": "000000", "device_name": "iPad", "platform": "ios",
	}, http.StatusOK, &second)
	if first.User.ID != second.User.ID {
		t.Fatalf("phone verification created duplicate users: %s != %s", first.User.ID, second.User.ID)
	}
	client.do(t, http.MethodPost, "/v1/auth/phone/verify", map[string]any{
		"phone": "+13125550123", "code": "999999", "device_name": "iPhone", "platform": "ios",
	}, http.StatusUnauthorized, nil)
}

func TestPhoneVerificationRateLimitReturnsRetryAfter(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServerWithVerifier(t, retryingVerifier{retryAfter: 91 * time.Second})
	payload, err := json.Marshal(map[string]string{"phone": "+13125550123"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(server.URL+"/v1/auth/phone/start", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "91" {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d retry-after=%q body=%s", response.StatusCode, response.Header.Get("Retry-After"), body)
	}
}

func TestPhoneLookupInvitesAndConversationLifecycle(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	owner := registerTestUser(t, server.URL, "invite-owner@example.com")
	phoneClient := testClient{baseURL: server.URL, client: http.DefaultClient}

	var registered authResponse
	phoneClient.do(t, http.MethodPost, "/v1/auth/phone/verify", map[string]any{
		"phone": "+13125550130", "code": "000000", "device_name": "iPhone", "platform": "ios",
	}, http.StatusOK, &registered)
	registeredClient := phoneClient
	registeredClient.token = registered.Tokens.AccessToken

	var lookup domain.Page[domain.User]
	owner.do(t, http.MethodPost, "/v1/users/lookup", map[string]any{
		"phones": []string{"+13125550130", "+13125550131"},
	}, http.StatusOK, &lookup)
	if len(lookup.Items) != 1 || lookup.Items[0].ID != registered.User.ID {
		t.Fatalf("exact phone lookup returned unexpected users: %+v", lookup.Items)
	}

	var group domain.Conversation
	owner.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "NAS group",
		"member_phones": []string{"+13125550130", "+13125550131"},
	}, http.StatusCreated, &group)

	var registeredGroups domain.Page[domain.Conversation]
	registeredClient.do(t, http.MethodGet, "/v1/conversations/", nil, http.StatusOK, &registeredGroups)
	if len(registeredGroups.Items) != 1 || registeredGroups.Items[0].ID != group.ID {
		t.Fatalf("registered phone was not added atomically: %+v", registeredGroups.Items)
	}

	var invited authResponse
	phoneClient.do(t, http.MethodPost, "/v1/auth/phone/verify", map[string]any{
		"phone": "+13125550131", "code": "000000", "device_name": "iPhone", "platform": "ios",
	}, http.StatusOK, &invited)
	invitedClient := phoneClient
	invitedClient.token = invited.Tokens.AccessToken
	var invitedGroups domain.Page[domain.Conversation]
	invitedClient.do(t, http.MethodGet, "/v1/conversations/", nil, http.StatusOK, &invitedGroups)
	if len(invitedGroups.Items) != 1 || invitedGroups.Items[0].ID != group.ID {
		t.Fatalf("verified phone did not claim its invitation: %+v", invitedGroups.Items)
	}

	registeredClient.do(t, http.MethodPatch, "/v1/conversations/"+group.ID.String(),
		map[string]any{"title": "member overwrite"}, http.StatusForbidden, nil)
	var updated domain.Conversation
	owner.do(t, http.MethodPatch, "/v1/conversations/"+group.ID.String(),
		map[string]any{"title": "Updated title"}, http.StatusOK, &updated)
	if updated.Title != "Updated title" {
		t.Fatalf("conversation title was not updated: %+v", updated)
	}
	registeredClient.do(t, http.MethodDelete, "/v1/conversations/"+group.ID.String(),
		nil, http.StatusForbidden, nil)
	owner.do(t, http.MethodDelete, "/v1/conversations/"+group.ID.String(),
		nil, http.StatusNoContent, nil)
	invitedClient.do(t, http.MethodGet, "/v1/conversations/"+group.ID.String(),
		nil, http.StatusNotFound, nil)
}

func TestProfileCannotMutateVerifiedIdentity(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	user := registerTestUser(t, server.URL, "profile-identity@example.com")
	user.client.do(t, http.MethodPatch, "/v1/me",
		map[string]any{"phone": "+13125550124"}, http.StatusUnprocessableEntity, nil)

	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	var verified authResponse
	client.do(t, http.MethodPost, "/v1/auth/phone/verify", map[string]any{
		"phone": "+13125550124", "code": "000000", "device_name": "iPhone", "platform": "ios",
	}, http.StatusOK, &verified)
	if verified.User.ID == user.user.ID {
		t.Fatal("unverified profile mutation linked a phone identity")
	}
}

func TestMultiDevicePreKeyClaimAndDeviceIsolation(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	alice := registerTestUser(t, server.URL, "prekeys@example.com")

	var second authResponse
	loginClient := testClient{baseURL: server.URL, client: http.DefaultClient}
	loginClient.do(t, http.MethodPost, "/v1/auth/login", map[string]any{
		"email": "prekeys@example.com", "password": "very-secure-test-password",
		"device_name": "Test iPad", "platform": "ios",
	}, http.StatusOK, &second)
	secondClient := loginClient
	secondClient.token = second.Tokens.AccessToken

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
	signature := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 64))
	configure := func(client testClient, deviceID uuid.UUID, keyID uint32) {
		client.do(t, http.MethodPut, "/v1/devices/"+deviceID.String(), map[string]any{
			"name": "Linked iOS device", "platform": "ios", "identity_key": key,
			"signed_prekey": map[string]any{
				"key_id": keyID, "public_key": key, "signature": signature,
			},
		}, http.StatusOK, nil)
		client.do(t, http.MethodPut, "/v1/devices/"+deviceID.String()+"/prekeys", map[string]any{
			"keys": []map[string]any{{"key_id": keyID, "public_key": key}},
		}, http.StatusNoContent, nil)
	}
	configure(alice.client, alice.device.ID, 1)
	configure(secondClient, second.Device.ID, 2)

	alice.client.do(t, http.MethodPut, "/v1/devices/"+second.Device.ID.String(), map[string]any{
		"name": "wrong device", "platform": "ios",
	}, http.StatusForbidden, nil)

	bob := registerTestUser(t, server.URL, "prekey-caller@example.com")
	var firstClaim struct {
		Devices []domain.PreKeyBundle `json:"devices"`
	}
	bob.client.do(t, http.MethodPost, "/v1/users/"+alice.user.ID.String()+"/prekeys:claim",
		nil, http.StatusOK, &firstClaim)
	if len(firstClaim.Devices) != 2 {
		t.Fatalf("expected two device bundles, received %d", len(firstClaim.Devices))
	}
	for _, bundle := range firstClaim.Devices {
		if bundle.OneTimePreKey == nil {
			t.Fatalf("device %s did not atomically claim a one-time prekey", bundle.DeviceID)
		}
	}

	var secondClaim struct {
		Devices []domain.PreKeyBundle `json:"devices"`
	}
	bob.client.do(t, http.MethodPost, "/v1/users/"+alice.user.ID.String()+"/prekeys:claim",
		nil, http.StatusOK, &secondClaim)
	for _, bundle := range secondClaim.Devices {
		if bundle.OneTimePreKey != nil {
			t.Fatalf("one-time prekey for device %s was reused", bundle.DeviceID)
		}
	}
}

type registeredUser struct {
	user   domain.User
	device domain.Device
	tokens auth.TokenPair
	client testClient
}

func newTestHTTPServer(t *testing.T) *httptest.Server {
	return newTestHTTPServerWithVerifier(t, verification.Development{Code: "000000"})
}

type retryingVerifier struct{ retryAfter time.Duration }

func (r retryingVerifier) Send(context.Context, string) error {
	return &verification.RetryError{Kind: verification.ErrRateLimited, RetryAfter: r.retryAfter}
}

func (retryingVerifier) Check(context.Context, string, string) error {
	return verification.ErrInvalidCode
}

func newTestHTTPServerWithVerifier(t *testing.T, verifier verification.Service) *httptest.Server {
	t.Helper()
	persistence := memory.New()
	bus := events.NewMemoryBus()
	t.Cleanup(func() {
		bus.Close()
		persistence.Close()
	})
	tokens := auth.NewTokenManager("test", strings.Repeat("s", 48), 15*time.Minute, 30*24*time.Hour, persistence)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(
		persistence, tokens, bus, ratelimit.NewMemory(), media.Unavailable{},
		verifier, appleauth.Unavailable{}, presence.NewMemory(), "", logger,
	).Router())
	t.Cleanup(server.Close)
	return server
}

func registerTestUser(t *testing.T, baseURL, email string) registeredUser {
	t.Helper()
	var response authResponse
	client := testClient{baseURL: baseURL, client: http.DefaultClient}
	client.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": email, "password": "very-secure-test-password", "display_name": email,
		"device_name": "Test iPhone", "platform": "ios",
	}, http.StatusCreated, &response)
	client.token = response.Tokens.AccessToken
	return registeredUser{
		user: response.User, device: response.Device, tokens: response.Tokens, client: client,
	}
}

func (c testClient) do(t *testing.T, method, path string, body any, expected int, destination any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, c.baseURL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	if response.StatusCode != expected {
		t.Fatalf("%s %s: expected %d, got %d: %s", method, path, expected, response.StatusCode, payload)
	}
	if destination != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, destination); err != nil {
			t.Fatalf("decode response: %v: %s", err, payload)
		}
	}
}

func (u registeredUser) do(t *testing.T, method, path string, body any, expected int, destination any) {
	t.Helper()
	u.client.do(t, method, path, body, expected, destination)
}
