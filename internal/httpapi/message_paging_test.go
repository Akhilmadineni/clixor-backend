package httpapi

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func TestMessagePagingSupportsLatestHistoryAndCatchUp(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	user := registerTestUser(t, server.URL, "message-paging@example.com")
	var conversation domain.Conversation
	user.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "Paging",
	}, http.StatusCreated, &conversation)
	messagePath := "/v1/conversations/" + conversation.ID.String() + "/messages"
	for sequence := 1; sequence <= 6; sequence++ {
		user.do(t, http.MethodPost, messagePath, map[string]any{
			"client_message_id": uuid.NewString(),
			"content_type":      "text",
			"ciphertext":        base64.StdEncoding.EncodeToString([]byte{byte(sequence)}),
			"envelope":          testE2EEEnvelope(user.device.ID),
		}, http.StatusCreated, nil)
	}

	assertMessagePage(t, user.client, messagePath+"?limit=3", []int64{4, 5, 6}, "4")
	assertMessagePage(t, user.client, messagePath+"?before_seq=4&limit=2", []int64{2, 3}, "2")
	assertMessagePage(t, user.client, messagePath+"?before_seq=2&limit=2", []int64{1}, "")
	assertMessagePage(t, user.client, messagePath+"?after_seq=2&limit=2", []int64{3, 4}, "4")
	assertMessagePage(t, user.client, messagePath+"?after_seq=4", []int64{5, 6}, "")

	for _, query := range []string{
		"?before_seq=4&after_seq=2",
		"?before_seq=0",
		"?after_seq=-1",
		"?before_seq=not-a-number",
		"?after_seq=not-a-number",
		"?limit=0",
		"?limit=501",
		"?limit=not-a-number",
	} {
		user.do(t, http.MethodGet, messagePath+query, nil, http.StatusUnprocessableEntity, nil)
	}
}

func assertMessagePage(
	t *testing.T,
	client testClient,
	path string,
	wantSequences []int64,
	wantNext string,
) {
	t.Helper()
	var page domain.Page[domain.Message]
	client.do(t, http.MethodGet, path, nil, http.StatusOK, &page)
	if len(page.Items) != len(wantSequences) {
		t.Fatalf("%s returned %d messages, want %d: %+v", path, len(page.Items), len(wantSequences), page)
	}
	for index, want := range wantSequences {
		if page.Items[index].Seq != want {
			t.Fatalf("%s item %d has seq %d, want %d", path, index, page.Items[index].Seq, want)
		}
	}
	if page.NextCursor != wantNext {
		t.Fatalf("%s next_cursor = %q, want %q", path, page.NextCursor, wantNext)
	}
}
