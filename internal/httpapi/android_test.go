package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

func TestAndroidAuthDevicesAndCrossPlatformChat(t *testing.T) {
	s := newTestHTTPServer(t)
	c := testClient{baseURL: s.URL, client: http.DefaultClient}
	var android authResponse
	c.do(t, "POST", "/v1/auth/register", map[string]any{"email": "android@example.com", "password": "very-secure-test-password", "platform": "android"}, 201, &android)
	if android.Device.Platform != "android" || android.Device.Name != "Android" {
		t.Fatalf("wrong Android identity: %+v", android.Device)
	}
	c.token = android.Tokens.AccessToken
	c.do(t, "PUT", "/v1/devices/"+android.Device.ID.String(), map[string]any{"name": "Pixel", "platform": "android", "push_token": "AbC:opaque_FCM-token-123", "identity_key": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "signed_prekey": map[string]any{"key_id": 1, "public_key": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "signature": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 64))}}, 200, nil)
	c.do(t, "PUT", "/v1/devices/"+android.Device.ID.String(), map[string]any{"name": "fake iOS", "platform": "ios"}, 409, nil)
	c.do(t, "PUT", "/v1/devices/"+uuid.NewString(), map[string]any{"name": "Other", "platform": "android"}, 403, nil)
	ios := registerTestUser(t, s.URL, "ios-participant@example.com")
	var conversation domain.Conversation
	c.do(t, "POST", "/v1/conversations/", map[string]any{"kind": "direct", "member_ids": []uuid.UUID{ios.user.ID}}, 201, &conversation)
	socket, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(s.URL, "http")+"/v1/realtime", http.Header{"Authorization": []string{"Bearer " + c.token}})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetReadDeadline(time.Now().Add(10 * time.Second))
	var hello domain.RealtimeEvent
	if err = socket.ReadJSON(&hello); err != nil || hello.Type != "session.ready" {
		t.Fatalf("Android socket: %v %+v", err, hello)
	}
	var message domain.Message
	ios.do(t, "POST", "/v1/conversations/"+conversation.ID.String()+"/messages", map[string]any{"client_message_id": uuid.NewString(), "content_type": "text", "ciphertext": base64.StdEncoding.EncodeToString([]byte("opaque-ciphertext")), "envelope": testE2EEEnvelope(ios.device.ID)}, 201, &message)
	var event domain.RealtimeEvent
	for event.Type != "message.created" {
		if err = socket.ReadJSON(&event); err != nil {
			t.Fatal(err)
		}
	}
	var page domain.Page[domain.Message]
	c.do(t, "GET", "/v1/conversations/"+conversation.ID.String()+"/messages", nil, 200, &page)
	if len(page.Items) != 1 || page.Items[0].ID != message.ID {
		t.Fatal("Android did not read iOS message")
	}
	var login authResponse
	testClient{baseURL: s.URL, client: http.DefaultClient}.do(t, "POST", "/v1/auth/login", map[string]any{"email": "android@example.com", "password": "very-secure-test-password", "platform": "android", "device_id": android.Device.ID}, 200, &login)
	if login.Device.ID != android.Device.ID || login.Device.Platform != "android" {
		t.Fatal("Android session did not reuse its identity")
	}
	c.token = login.Tokens.AccessToken
	var refreshed auth.TokenPair
	c.do(t, "POST", "/v1/auth/refresh", map[string]any{"refresh_token": login.Tokens.RefreshToken}, 200, &refreshed)
	if refreshed.RefreshToken == login.Tokens.RefreshToken {
		t.Fatal("Android refresh token did not rotate")
	}
	c.token = refreshed.AccessToken
	c.do(t, "GET", "/v1/me", nil, 200, nil)
	c.do(t, "POST", "/v1/auth/logout", map[string]any{}, 204, nil)
	c.do(t, "GET", "/v1/me", nil, 401, nil)
	c.do(t, "POST", "/v1/auth/refresh", map[string]any{"refresh_token": refreshed.RefreshToken}, 401, nil)
}

func TestPlatformPushTokenValidation(t *testing.T) {
	for _, token := range []string{"AbC:opaque_FCM-token", "a", ""} {
		if !validPlatformPushToken("android", token) {
			t.Fatal("valid Android token rejected")
		}
	}
	for _, token := range []string{"line\nbreak", "space here", strings.Repeat("a", 2049), "é"} {
		if validPlatformPushToken("android", token) {
			t.Fatal("invalid Android token accepted")
		}
	}
	if validPlatformPushToken("ios", "AbC:opaque_FCM-token") || !validPlatformPushToken("ios", "AABB0011") || validDeviceInfo("", "windows") {
		t.Fatal("iOS/platform validation regressed")
	}
}

func TestAndroidAppLinksFailClosedUntilIdentityExists(t *testing.T) {
	s := &Server{}
	request := httptest.NewRequest("GET", "/.well-known/assetlinks.json", nil)
	w := httptest.NewRecorder()
	s.androidAssetLinks(w, request)
	if w.Code != 200 || w.Body.String() != "[]" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("unconfigured association grants authority")
	}
	fingerprint := strings.Repeat("AB:", 31) + "AB"
	if err := s.ConfigureAndroidLinks("com.example.clixor", []string{fingerprint}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.androidAssetLinks(w, request)
	var entries []map[string]any
	if json.Unmarshal(w.Body.Bytes(), &entries) != nil || len(entries) != 1 {
		t.Fatal("invalid assetlinks document")
	}
	for _, p := range []string{"", "bad/package", "https://evil.example"} {
		if s.ConfigureAndroidLinks(p, []string{fingerprint}) == nil {
			t.Fatal("bad package accepted")
		}
	}
	if s.ConfigureAndroidLinks("com.example.clixor", []string{"not-a-fingerprint"}) == nil {
		t.Fatal("bad signing fingerprint accepted")
	}
}
