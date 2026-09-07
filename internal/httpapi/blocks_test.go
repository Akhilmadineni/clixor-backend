package httpapi

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

func TestBlockingFiltersHistoryAndRealtimeWithoutRemovingSharedGroup(t *testing.T) {
	server := newTestHTTPServer(t)
	alice := registerTestUser(t, server.URL, "block-alice@example.com")
	bob := registerTestUser(t, server.URL, "block-bob@example.com")
	carol := registerTestUser(t, server.URL, "block-carol@example.com")
	var group domain.Conversation
	alice.do(t, "POST", "/v1/conversations/", map[string]any{"kind": "group", "title": "Blocking fixture", "member_ids": []uuid.UUID{bob.user.ID, carol.user.ID}}, 201, &group)
	path := "/v1/conversations/" + group.ID.String() + "/messages"
	send := func(user registeredUser) {
		user.do(t, "POST", path, map[string]any{"client_message_id": uuid.NewString(), "content_type": "text", "ciphertext": base64.StdEncoding.EncodeToString([]byte("test ciphertext")), "envelope": testE2EEEnvelope(user.device.ID)}, 201, nil)
	}
	send(carol)
	send(alice)
	send(alice)
	bob.do(t, "PUT", "/v1/me/blocks/"+alice.user.ID.String(), nil, 204, nil)
	bob.do(t, "PUT", "/v1/me/blocks/"+bob.user.ID.String(), nil, 422, nil)
	var blocks domain.Page[uuid.UUID]
	bob.do(t, "GET", "/v1/me/blocks", nil, 200, &blocks)
	if len(blocks.Items) != 1 || blocks.Items[0] != alice.user.ID {
		t.Fatal("incorrect own block list")
	}
	carol.do(t, "GET", "/v1/me/blocks", nil, 200, &blocks)
	if len(blocks.Items) != 0 {
		t.Fatal("another account's blocks leaked")
	}
	for _, query := range []string{"?limit=1", "?after_seq=0&limit=1", "?before_seq=4&limit=1"} {
		var page domain.Page[domain.Message]
		bob.do(t, "GET", path+query, nil, 200, &page)
		if len(page.Items) != 1 || page.Items[0].SenderID != carol.user.ID {
			t.Fatalf("blocked messages consumed pagination: %s %+v", query, page)
		}
	}
	var page domain.Page[domain.Message]
	carol.do(t, "GET", path, nil, 200, &page)
	if len(page.Items) != 3 {
		t.Fatal("block removed another group member's history")
	}
	alice.do(t, "POST", "/v1/conversations/", map[string]any{"kind": "direct", "member_ids": []uuid.UUID{bob.user.ID}}, 403, nil)
	socket, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime", http.Header{"Authorization": []string{"Bearer " + bob.client.token}})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
	var event domain.RealtimeEvent
	if err = socket.ReadJSON(&event); err != nil || event.Type != "session.ready" {
		t.Fatalf("socket ready: %v", err)
	}
	send(alice)
	send(carol)
	for {
		if err = socket.ReadJSON(&event); err != nil {
			t.Fatal(err)
		}
		if event.Type == "message.created" {
			if communicationActor(event) != carol.user.ID {
				t.Fatal("blocked sender reached realtime recipient")
			}
			break
		}
	}
	bob.do(t, "DELETE", "/v1/me/blocks/"+alice.user.ID.String(), nil, 204, nil)
	bob.do(t, "GET", path, nil, 200, &page)
	if len(page.Items) != 5 {
		t.Fatal("unblock did not restore accessible history")
	}
}
