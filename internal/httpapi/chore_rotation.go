package httpapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type rotateChoreRequest struct {
	OperationID          uuid.UUID       `json:"operation_id"`
	ExpectedChoreVersion int64           `json:"expected_chore_version"`
	Chore                json.RawMessage `json:"chore"`
	FeedItem             json.RawMessage `json:"feed_item"`
}

func (s *Server) rotateChore(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	choreID, err := uuid.Parse(chi.URLParam(r, "choreID"))
	if err != nil {
		writeRotateChoreError(w, domain.ErrInvalid)
		return
	}
	var req rotateChoreRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.OperationID == uuid.Nil || req.ExpectedChoreVersion < 1 || !rotationPayloadBindings(req.Chore, req.FeedItem, conversationID, choreID, req.OperationID) {
		writeRotateChoreError(w, domain.ErrInvalid)
		return
	}
	canonical, _ := json.Marshal(req)
	digest := sha256.Sum256(canonical)
	result, err := s.store.RotateChore(r.Context(), store.RotateChoreParams{OperationID: req.OperationID, ConversationID: conversationID, ChoreID: choreID, ActorID: id.UserID, ExpectedChoreVersion: req.ExpectedChoreVersion, ChorePayload: req.Chore, FeedPayload: req.FeedItem, RequestHash: digest[:]})
	if err != nil {
		writeRotateChoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Chore rotation was finalized as an additive client contract with HTTP 400
// for malformed or semantically invalid commands. Keep this mapping local so
// legacy endpoints that intentionally expose the API's historical 422 behavior
// are not changed.
func writeRotateChoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, domain.ErrInvalid) {
		writeError(w, http.StatusBadRequest, "invalid_input", "One or more fields are invalid.")
		return
	}
	writeDomainError(w, err)
}

func rotationPayloadBindings(chore, feed json.RawMessage, conversationID, choreID, operationID uuid.UUID) bool {
	var c struct {
		ID          uuid.UUID   `json:"id"`
		GroupID     uuid.UUID   `json:"groupId"`
		RotateOrder []uuid.UUID `json:"rotateOrder"`
		AssignedTo  *uuid.UUID  `json:"assignedTo"`
	}
	var f struct {
		ID        uuid.UUID  `json:"id"`
		GroupID   uuid.UUID  `json:"groupId"`
		RelatedID *uuid.UUID `json:"relatedId"`
		Type      string     `json:"type"`
	}
	if json.Unmarshal(chore, &c) != nil || json.Unmarshal(feed, &f) != nil {
		return false
	}
	return c.ID == choreID && c.GroupID == conversationID && f.ID == operationID && f.GroupID == conversationID && f.RelatedID != nil && *f.RelatedID == choreID && f.Type == "note"
}
