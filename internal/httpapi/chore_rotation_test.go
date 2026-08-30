package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func TestRotationPayloadBindingsRejectCrossResourceAndNonDeterministicFeed(t *testing.T) {
	conversationID, choreID, operationID := uuid.New(), uuid.New(), uuid.New()
	chore := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + conversationID.String() + `"}`)
	feed := json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + conversationID.String() + `","relatedId":"` + choreID.String() + `","type":"note"}`)
	if !rotationPayloadBindings(chore, feed, conversationID, choreID, operationID) {
		t.Fatal("valid bindings rejected")
	}
	for name, bad := range map[string]json.RawMessage{
		"foreign conversation": json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + uuid.NewString() + `","relatedId":"` + choreID.String() + `","type":"note"}`),
		"foreign chore":        json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + conversationID.String() + `","relatedId":"` + uuid.NewString() + `","type":"note"}`),
		"random feed id":       json.RawMessage(`{"id":"` + uuid.NewString() + `","groupId":"` + conversationID.String() + `","relatedId":"` + choreID.String() + `","type":"note"}`),
		"wrong type":           json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + conversationID.String() + `","relatedId":"` + choreID.String() + `","type":"expense"}`),
	} {
		if rotationPayloadBindings(chore, bad, conversationID, choreID, operationID) {
			t.Fatalf("accepted %s", name)
		}
	}
}

func TestRotateChoreHTTPContractAndReplayACL(t *testing.T) {
	server := newTestHTTPServer(t)
	owner := registerTestUser(t, server.URL, "rotation-http-owner@example.com")
	member := registerTestUser(t, server.URL, "rotation-http-member@example.com")
	outsider := registerTestUser(t, server.URL, "rotation-http-outsider@example.com")

	var conversation domain.Conversation
	owner.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "Atomic rotation", "member_ids": []uuid.UUID{member.user.ID},
	}, http.StatusCreated, &conversation)

	choreID := uuid.New()
	var chore domain.Entity
	owner.do(t, http.MethodPut,
		"/v1/conversations/"+conversation.ID.String()+"/entities/chore/"+choreID.String()+"?expected_version=0",
		map[string]any{
			"id": choreID, "groupId": conversation.ID, "createdBy": owner.user.ID,
			"assignedTo": owner.user.ID, "rotateOrder": []uuid.UUID{owner.user.ID, member.user.ID},
		}, http.StatusOK, &chore)

	rotationBody := func(operationID, targetChoreID uuid.UUID, expectedVersion int64, feedTitle string) map[string]any {
		return map[string]any{
			"operation_id":           operationID,
			"expected_chore_version": expectedVersion,
			"chore": map[string]any{
				"id": targetChoreID, "groupId": conversation.ID, "createdBy": owner.user.ID,
				"assignedTo": member.user.ID, "rotateOrder": []uuid.UUID{owner.user.ID, member.user.ID},
			},
			"feed_item": map[string]any{
				"id": operationID, "groupId": conversation.ID, "createdBy": member.user.ID,
				"relatedId": targetChoreID, "type": "note", "title": feedTitle,
			},
		}
	}
	type response struct {
		OperationID uuid.UUID     `json:"operation_id"`
		Chore       domain.Entity `json:"chore"`
		FeedItem    domain.Entity `json:"feed_item"`
	}
	path := "/v1/conversations/" + conversation.ID.String() + "/chores/" + choreID.String() + "/rotate"
	operationID := uuid.New()
	command := rotationBody(operationID, choreID, chore.Version, "rotated")
	var first response
	member.do(t, http.MethodPost, path, command, http.StatusOK, &first)
	if first.OperationID != operationID || first.Chore.Version != chore.Version+1 ||
		first.FeedItem.ID != operationID || first.FeedItem.Kind != "feed_item" {
		t.Fatalf("non-authoritative response: %+v", first)
	}

	var replay response
	member.do(t, http.MethodPost, path, command, http.StatusOK, &replay)
	if replay.OperationID != first.OperationID || replay.Chore.Version != first.Chore.Version ||
		replay.FeedItem.ID != first.FeedItem.ID {
		t.Fatalf("identical replay changed result: first=%+v replay=%+v", first, replay)
	}

	// A valid but different body cannot reuse a committed operation ID.
	member.do(t, http.MethodPost, path,
		rotationBody(operationID, choreID, chore.Version, "different command"),
		http.StatusConflict, nil)
	// A different operation cannot use the now-stale authoritative version.
	member.do(t, http.MethodPost, path,
		rotationBody(uuid.New(), choreID, chore.Version, "stale"),
		http.StatusConflict, nil)

	invalidBinding := rotationBody(uuid.New(), choreID, first.Chore.Version, "invalid binding")
	invalidBinding["feed_item"].(map[string]any)["type"] = "expense"
	member.do(t, http.MethodPost, path, invalidBinding, http.StatusBadRequest, nil)
	invalidParticipant := rotationBody(uuid.New(), choreID, first.Chore.Version, "invalid participant")
	invalidParticipant["chore"].(map[string]any)["assignedTo"] = outsider.user.ID
	member.do(t, http.MethodPost, path, invalidParticipant, http.StatusBadRequest, nil)

	missingChoreID := uuid.New()
	member.do(t, http.MethodPost,
		"/v1/conversations/"+conversation.ID.String()+"/chores/"+missingChoreID.String()+"/rotate",
		rotationBody(uuid.New(), missingChoreID, 1, "missing"), http.StatusNotFound, nil)

	tombstonedChoreID := uuid.New()
	var tombstoned domain.Entity
	owner.do(t, http.MethodPut,
		"/v1/conversations/"+conversation.ID.String()+"/entities/chore/"+tombstonedChoreID.String()+"?expected_version=0",
		map[string]any{
			"id": tombstonedChoreID, "groupId": conversation.ID,
			"assignedTo": owner.user.ID, "rotateOrder": []uuid.UUID{owner.user.ID, member.user.ID},
		}, http.StatusOK, &tombstoned)
	owner.do(t, http.MethodDelete,
		"/v1/conversations/"+conversation.ID.String()+"/entities/chore/"+tombstonedChoreID.String()+"?expected_version=1",
		nil, http.StatusNoContent, nil)
	member.do(t, http.MethodPost,
		"/v1/conversations/"+conversation.ID.String()+"/chores/"+tombstonedChoreID.String()+"/rotate",
		rotationBody(uuid.New(), tombstonedChoreID, tombstoned.Version, "tombstoned"),
		http.StatusNotFound, nil)

	outsider.do(t, http.MethodPost, path,
		rotationBody(uuid.New(), choreID, first.Chore.Version, "inactive"),
		http.StatusForbidden, nil)
	owner.do(t, http.MethodDelete,
		"/v1/conversations/"+conversation.ID.String()+"/members/"+member.user.ID.String(),
		nil, http.StatusNoContent, nil)
	member.do(t, http.MethodPost, path, command, http.StatusForbidden, nil)
	// The still-active owner learns only that this operation ID is bound to a
	// different actor/command, never the member's stored result.
	owner.do(t, http.MethodPost, path, command, http.StatusConflict, nil)
}
