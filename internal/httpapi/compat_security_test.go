package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

func TestAuthoritativeACLProjectsLegacyMembersAndRejectsStaleMetadata(t *testing.T) {
	server := newTestHTTPServer(t)
	owner := registerTestUser(t, server.URL, "acl-owner@example.com")
	member := registerTestUser(t, server.URL, "acl-member@example.com")
	added := registerTestUser(t, server.URL, "acl-added@example.com")
	invitee := registerTestUser(t, server.URL, "acl-invitee@example.com")

	member.do(t, http.MethodPatch, "/v1/me", map[string]any{
		"display_name": "Public Member", "username": "@public_member",
		"avatar_color": "#123456", "contact_email": "private-member@example.com",
		"contact_phone": "+13125550999",
	}, http.StatusOK, nil)
	ownerLocalID := uuid.NewString()
	memberLocalID := uuid.NewString()
	pendingLocalID := uuid.NewString()
	var group domain.Conversation
	owner.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "Authoritative ACL", "member_ids": []uuid.UUID{member.user.ID},
		"metadata": map[string]any{
			"custom": "preserved",
			"members": []map[string]any{
				{"id": ownerLocalID, "backendUserId": owner.user.ID, "name": "Owner local", "avatarColor": "#111111"},
				{
					"id": memberLocalID, "backendUserId": member.user.ID,
					"name": "Spoofed Member", "username": "@spoofed", "avatarColor": "#222222",
					"email": "metadata-secret@example.com", "phone": "+13125550111",
					"profileImageData": "private-image-blob", "private": map[string]any{"token": "secret"},
				},
				{"id": uuid.NewString(), "backendUserId": added.user.ID, "name": "Stale user", "avatarColor": "#333333"},
				{"id": pendingLocalID, "name": "Pending contact", "phone": "+13125550000", "avatarColor": "#444444"},
			},
		},
	}, http.StatusCreated, &group)
	assertProjectedMember(t, group.Metadata, owner.user.ID, ownerLocalID, true)
	assertProjectedMember(t, group.Metadata, member.user.ID, memberLocalID, true)
	assertProjectedMember(t, group.Metadata, added.user.ID, "", false)
	if bytes.Contains(group.Metadata, []byte(pendingLocalID)) {
		t.Fatalf("private contact-only member was shared: %s", group.Metadata)
	}
	for _, forbidden := range []string{
		"Spoofed Member", "@spoofed", "metadata-secret@example.com", "+13125550111",
		"private-image-blob", `"private"`, "+13125550000",
	} {
		if bytes.Contains(group.Metadata, []byte(forbidden)) {
			t.Fatalf("conversation metadata leaked/spoofed %q: %s", forbidden, group.Metadata)
		}
	}
	for _, authoritative := range []string{"Public Member", "@public_member", "#123456"} {
		if !bytes.Contains(group.Metadata, []byte(authoritative)) {
			t.Fatalf("conversation metadata omitted authoritative public identity %q: %s", authoritative, group.Metadata)
		}
	}

	added.do(t, http.MethodGet, "/v1/conversations/"+group.ID.String(), nil, http.StatusNotFound, nil)
	added.do(t, http.MethodGet, "/v1/conversations/"+uuid.NewString(), nil, http.StatusNotFound, nil)
	member.do(t, http.MethodPost, "/v1/conversations/"+group.ID.String()+"/members", map[string]any{
		"user_id": invitee.user.ID, "role": "member",
	}, http.StatusForbidden, nil)
	owner.do(t, http.MethodPost, "/v1/conversations/"+group.ID.String()+"/members", map[string]any{
		"user_id": added.user.ID, "role": "member",
	}, http.StatusNoContent, nil)
	added.do(t, http.MethodGet, "/v1/conversations/"+group.ID.String(), nil, http.StatusOK, nil)

	memberBody := authenticatedRawRequest(
		t, owner.client, http.MethodGet,
		"/v1/conversations/"+group.ID.String()+"/members", nil, http.StatusOK,
	)
	for _, forbidden := range []string{"private-member@example.com", "+13125550999", `"email"`, `"phone"`} {
		if bytes.Contains(memberBody, []byte(forbidden)) {
			t.Fatalf("member directory leaked %q: %s", forbidden, memberBody)
		}
	}
	for _, required := range []string{"Public Member", "@public_member", member.user.ID.String()} {
		if !bytes.Contains(memberBody, []byte(required)) {
			t.Fatalf("member directory omitted %q: %s", required, memberBody)
		}
	}

	owner.do(t, http.MethodDelete,
		"/v1/conversations/"+group.ID.String()+"/members/"+added.user.ID.String(),
		nil, http.StatusNoContent, nil)
	added.do(t, http.MethodGet, "/v1/conversations/"+group.ID.String(), nil, http.StatusNotFound, nil)
	owner.do(t, http.MethodPatch, "/v1/conversations/"+group.ID.String(), map[string]any{
		"metadata": map[string]any{"members": []map[string]any{{
			"id": uuid.NewString(), "backendUserId": added.user.ID,
			"name": "Stale replay", "role": "owner", "avatarColor": "#FFFFFF",
		}}},
	}, http.StatusOK, &group)
	assertProjectedMember(t, group.Metadata, added.user.ID, added.user.ID.String(), true)
	if bytes.Contains(group.Metadata, []byte("Stale replay")) || bytes.Contains(group.Metadata, []byte(`"role"`)) {
		t.Fatalf("client fabricated tombstone fields survived: %s", group.Metadata)
	}
	added.do(t, http.MethodGet, "/v1/conversations/"+group.ID.String(), nil, http.StatusNotFound, nil)

	var created conversationInviteCreationResponse
	owner.do(t, http.MethodPost, "/v1/conversations/"+group.ID.String()+"/invites",
		nil, http.StatusCreated, &created)
	var accepted domain.ConversationInviteAcceptance
	invitee.do(t, http.MethodPost, "/v1/invites/accept", map[string]any{
		"token": created.Token,
	}, http.StatusOK, &accepted)
	if !accepted.Joined {
		t.Fatal("invite acceptance did not add ACL membership")
	}
	assertProjectedMember(t, accepted.Conversation.Metadata, invitee.user.ID, invitee.user.ID.String(), true)
	invitee.do(t, http.MethodGet, "/v1/conversations/"+group.ID.String(), nil, http.StatusOK, nil)
}

func TestUsernameDiscoveryNeverReturnsEmailOrPhone(t *testing.T) {
	server := newTestHTTPServer(t)
	searcher := registerTestUser(t, server.URL, "directory-searcher@example.com")
	target := registerTestUser(t, server.URL, "directory-target@example.com")
	target.do(t, http.MethodPatch, "/v1/me", map[string]any{
		"display_name": "Directory Target", "username": "@directory_target",
		"contact_email": "profile-secret@example.com", "contact_phone": "+13125550888",
	}, http.StatusOK, nil)

	for _, request := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/v1/users/search?q=directory_tar&limit=20", nil},
		{http.MethodPost, "/v1/users/lookup", map[string]any{"usernames": []string{"@directory_target"}}},
	} {
		body := authenticatedRawRequest(t, searcher.client, request.method, request.path, request.body, http.StatusOK)
		if !bytes.Contains(body, []byte(target.user.ID.String())) ||
			!bytes.Contains(body, []byte("@directory_target")) {
			t.Fatalf("directory response omitted public identity: %s", body)
		}
		for _, forbidden := range []string{
			target.user.Email, "profile-secret@example.com", "+13125550888", `"email"`, `"contact_email"`, `"contact_phone"`,
		} {
			if bytes.Contains(body, []byte(forbidden)) {
				t.Fatalf("username directory leaked %q: %s", forbidden, body)
			}
		}
	}
}

func TestRealtimeSocketClosesBeforePostLogoutEvent(t *testing.T) {
	server := newTestHTTPServer(t)
	sender := registerTestUser(t, server.URL, "socket-sender@example.com")
	revoked := registerTestUser(t, server.URL, "socket-revoked@example.com")
	var conversation domain.Conversation
	sender.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "direct", "member_ids": []uuid.UUID{revoked.user.ID},
	}, http.StatusCreated, &conversation)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/realtime"
	socket, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{
		"Authorization": []string{"Bearer " + revoked.client.token},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hello domain.RealtimeEvent
	if err := socket.ReadJSON(&hello); err != nil || hello.Type != "session.ready" {
		t.Fatalf("missing realtime hello: event=%+v err=%v", hello, err)
	}
	revoked.do(t, http.MethodPost, "/v1/auth/logout", nil, http.StatusNoContent, nil)
	sender.do(t, http.MethodPost, "/v1/conversations/"+conversation.ID.String()+"/messages", map[string]any{
		"client_message_id": uuid.NewString(), "content_type": "text",
		"ciphertext": base64.StdEncoding.EncodeToString([]byte("must not be delivered")),
		"envelope":   testE2EEEnvelope(sender.device.ID),
	}, http.StatusCreated, nil)
	var event domain.RealtimeEvent
	if err := socket.ReadJSON(&event); err == nil {
		t.Fatalf("revoked socket received post-logout event: %+v", event)
	}
}

func TestDeleteAccountImmediatelyClosesRealtimeSocket(t *testing.T) {
	server := newTestHTTPServer(t)
	deleted := registerTestUser(t, server.URL, "socket-delete@example.com")
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/realtime"
	socket, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{
		"Authorization": []string{"Bearer " + deleted.client.token},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hello domain.RealtimeEvent
	if err := socket.ReadJSON(&hello); err != nil || hello.Type != "session.ready" {
		t.Fatalf("missing realtime hello: event=%+v err=%v", hello, err)
	}
	deleted.do(t, http.MethodDelete, "/v1/me", nil, http.StatusNoContent, nil)
	var event domain.RealtimeEvent
	if err := socket.ReadJSON(&event); err == nil {
		t.Fatalf("account-deleted socket remained readable: %+v", event)
	}
}

func authenticatedRawRequest(
	t *testing.T,
	client testClient,
	method string,
	path string,
	body any,
	expected int,
) []byte {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, client.baseURL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != expected {
		t.Fatalf("%s %s returned %d, want %d: %s", method, path, response.StatusCode, expected, responseBody)
	}
	return responseBody
}

func assertProjectedMember(
	t *testing.T,
	metadata json.RawMessage,
	backendUserID uuid.UUID,
	localID string,
	want bool,
) {
	t.Helper()
	var root struct {
		Members []struct {
			ID            string `json:"id"`
			BackendUserID string `json:"backendUserId"`
		} `json:"members"`
	}
	if err := json.Unmarshal(metadata, &root); err != nil {
		t.Fatalf("decode projected members: %v: %s", err, metadata)
	}
	for _, member := range root.Members {
		if member.BackendUserID != backendUserID.String() {
			continue
		}
		if !want {
			t.Fatalf("unexpected member %s remained projected: %s", backendUserID, metadata)
		}
		if localID != "" && member.ID != localID {
			t.Fatalf("member %s local id=%q, want %q: %s", backendUserID, member.ID, localID, metadata)
		}
		return
	}
	if want {
		t.Fatalf("member %s missing from projection: %s", backendUserID, metadata)
	}
}
