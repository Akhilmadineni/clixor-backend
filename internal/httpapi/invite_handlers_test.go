package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

type conversationInviteCreationResponse struct {
	Token  string                    `json:"token"`
	Invite domain.ConversationInvite `json:"invite"`
}

func TestSecureConversationInviteHTTPContract(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	owner := registerTestUser(t, server.URL, "link-owner@example.com")
	admin := registerTestUser(t, server.URL, "link-admin@example.com")
	member := registerTestUser(t, server.URL, "link-member@example.com")
	firstJoiner := registerTestUser(t, server.URL, "link-first@example.com")
	secondJoiner := registerTestUser(t, server.URL, "link-second@example.com")

	var group domain.Conversation
	owner.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "Invite-only trip",
		"member_ids": []uuid.UUID{admin.user.ID, member.user.ID},
		"metadata":   map[string]any{"private_note": "must not be previewed"},
	}, http.StatusCreated, &group)
	owner.do(t, http.MethodPost, "/v1/conversations/"+group.ID.String()+"/members", map[string]any{
		"user_id": admin.user.ID, "role": "admin",
	}, http.StatusNoContent, nil)

	unauthenticated := testClient{baseURL: server.URL, client: http.DefaultClient}
	unauthenticated.do(t, http.MethodPost, "/v1/conversations/"+group.ID.String()+"/invites",
		nil, http.StatusUnauthorized, nil)
	member.do(t, http.MethodPost, "/v1/conversations/"+group.ID.String()+"/invites",
		nil, http.StatusForbidden, nil)

	var direct domain.Conversation
	owner.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "direct", "member_ids": []uuid.UUID{admin.user.ID},
	}, http.StatusCreated, &direct)
	owner.do(t, http.MethodPost, "/v1/conversations/"+direct.ID.String()+"/invites",
		nil, http.StatusUnprocessableEntity, nil)

	invitePath := "/v1/conversations/" + group.ID.String() + "/invites"
	for _, invalid := range []map[string]any{
		{"expires_in_seconds": 299},
		{"expires_in_seconds": 2592001},
		{"expires_in_seconds": int64(^uint64(0) >> 1)},
		{"max_uses": 0},
		{"max_uses": 1001},
	} {
		owner.do(t, http.MethodPost, invitePath, invalid, http.StatusUnprocessableEntity, nil)
	}

	started := time.Now().UTC()
	var defaultInvite conversationInviteCreationResponse
	owner.do(t, http.MethodPost, invitePath, nil, http.StatusCreated, &defaultInvite)
	if defaultInvite.Invite.MaxUses != 25 || defaultInvite.Invite.Uses != 0 ||
		defaultInvite.Invite.ExpiresAt.Before(started.Add(7*24*time.Hour-time.Minute)) ||
		defaultInvite.Invite.ExpiresAt.After(started.Add(7*24*time.Hour+time.Minute)) {
		t.Fatalf("secure defaults were not applied: %+v", defaultInvite.Invite)
	}
	if defaultInvite.Token == "" || defaultInvite.Token == group.ID.String() ||
		!strings.HasPrefix(defaultInvite.Token, conversationInviteTokenPrefix) {
		t.Fatalf("invalid raw invite token %q", defaultInvite.Token)
	}
	if hash, ok := conversationInviteTokenHash(defaultInvite.Token); !ok || len(hash) != 32 {
		t.Fatalf("token does not contain 256 bits of canonical entropy: valid=%t hash=%x", ok, hash)
	}
	member.do(t, http.MethodDelete,
		invitePath+"/"+defaultInvite.Invite.ID.String(), nil, http.StatusForbidden, nil)
	admin.do(t, http.MethodDelete,
		invitePath+"/"+defaultInvite.Invite.ID.String(), nil, http.StatusNoContent, nil)
	firstJoiner.do(t, http.MethodPost, "/v1/invites/preview",
		map[string]any{"token": defaultInvite.Token}, http.StatusGone, nil)

	var active conversationInviteCreationResponse
	admin.do(t, http.MethodPost, invitePath, map[string]any{
		"expires_in_seconds": 300, "max_uses": 1,
	}, http.StatusCreated, &active)
	if active.Token == defaultInvite.Token {
		t.Fatal("two invites received the same bearer token")
	}
	unauthenticated.do(t, http.MethodPost, "/v1/invites/preview",
		map[string]any{"token": active.Token}, http.StatusUnauthorized, nil)
	unauthenticated.do(t, http.MethodPost, "/v1/invites/accept",
		map[string]any{"token": active.Token}, http.StatusUnauthorized, nil)

	var preview map[string]json.RawMessage
	firstJoiner.do(t, http.MethodPost, "/v1/invites/preview",
		map[string]any{"token": active.Token}, http.StatusOK, &preview)
	for _, privateField := range []string{"token", "conversation_id", "metadata", "created_by", "uses", "max_uses"} {
		if _, exposed := preview[privateField]; exposed {
			t.Fatalf("privacy-safe preview exposed %q: %s", privateField, mustJSON(t, preview))
		}
	}
	if string(preview["title"]) != `"Invite-only trip"` || string(preview["already_member"]) != "false" {
		t.Fatalf("unexpected preview: %s", mustJSON(t, preview))
	}

	guessed := mutateInviteToken(active.Token)
	firstJoiner.do(t, http.MethodPost, "/v1/invites/preview",
		map[string]any{"token": guessed}, http.StatusNotFound, nil)
	firstJoiner.do(t, http.MethodPost, "/v1/invites/preview",
		map[string]any{"token": "not-a-token"}, http.StatusNotFound, nil)
	firstJoiner.do(t, http.MethodPost, "/v1/invites/preview",
		map[string]any{"token": active.Token, "unexpected": true}, http.StatusBadRequest, nil)
	firstJoiner.do(t, http.MethodGet, "/v1/invites/"+active.Token,
		nil, http.StatusNotFound, nil)

	var accepted domain.ConversationInviteAcceptance
	firstJoiner.do(t, http.MethodPost, "/v1/invites/accept",
		map[string]any{"token": active.Token}, http.StatusOK, &accepted)
	if !accepted.Joined || accepted.Conversation.ID != group.ID {
		t.Fatalf("invite did not join the conversation: %+v", accepted)
	}
	var retried domain.ConversationInviteAcceptance
	firstJoiner.do(t, http.MethodPost, "/v1/invites/accept",
		map[string]any{"token": active.Token}, http.StatusOK, &retried)
	if retried.Joined || retried.Conversation.ID != group.ID {
		t.Fatalf("invite retry was not idempotent: %+v", retried)
	}
	var exhaustedMemberPreview map[string]json.RawMessage
	firstJoiner.do(t, http.MethodPost, "/v1/invites/preview",
		map[string]any{"token": active.Token}, http.StatusOK, &exhaustedMemberPreview)
	if string(exhaustedMemberPreview["already_member"]) != "true" {
		t.Fatalf("exhausted invite hid existing membership: %s", mustJSON(t, exhaustedMemberPreview))
	}
	secondJoiner.do(t, http.MethodPost, "/v1/invites/preview",
		map[string]any{"token": active.Token}, http.StatusGone, nil)
	secondJoiner.do(t, http.MethodPost, "/v1/invites/accept",
		map[string]any{"token": active.Token}, http.StatusGone, nil)
	admin.do(t, http.MethodDelete, invitePath+"/"+active.Invite.ID.String(),
		nil, http.StatusNoContent, nil)
	var revokedRetry domain.ConversationInviteAcceptance
	firstJoiner.do(t, http.MethodPost, "/v1/invites/accept",
		map[string]any{"token": active.Token}, http.StatusOK, &revokedRetry)
	if revokedRetry.Joined || revokedRetry.Conversation.ID != group.ID {
		t.Fatalf("authorized revoked-token retry was not idempotent: %+v", revokedRetry)
	}
	var revokedMemberPreview map[string]json.RawMessage
	firstJoiner.do(t, http.MethodPost, "/v1/invites/preview",
		map[string]any{"token": active.Token}, http.StatusOK, &revokedMemberPreview)
	if string(revokedMemberPreview["already_member"]) != "true" {
		t.Fatalf("revoked invite hid existing membership: %s", mustJSON(t, revokedMemberPreview))
	}

	for _, fixedPath := range []string{"/v1/invites/preview", "/v1/invites/accept"} {
		if strings.Contains(fixedPath, active.Token) {
			t.Fatalf("invite bearer leaked into request path %q", fixedPath)
		}
	}
}

func mutateInviteToken(token string) string {
	index := len(conversationInviteTokenPrefix)
	replacement := byte('A')
	if token[index] == replacement {
		replacement = 'B'
	}
	return token[:index] + string(replacement) + token[index+1:]
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
