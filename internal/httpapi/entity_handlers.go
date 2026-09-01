package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

var allowedEntityKinds = map[string]struct{}{
	"profile": {}, "expense": {}, "task": {}, "file": {}, "chore": {},
	"feed_item": {}, "recurring_expense": {}, "settlement": {},
	"group_meta": {}, "payment_handles": {}, "trip_plan": {}, "trip_itinerary": {},
	"we_were_here": {}, "check_in": {},
}

func (s *Server) putEntity(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	kind := chi.URLParam(r, "kind")
	entityID, err := uuid.Parse(chi.URLParam(r, "entityID"))
	if err != nil || !validEntityKind(kind) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	var payload json.RawMessage
	if !decodeJSON(w, r, &payload) {
		return
	}
	expectedVersion, ok := requiredExpectedVersion(w, r)
	if !ok {
		return
	}
	entity, err := s.store.PutEntity(r.Context(), domain.Entity{
		ConversationID: conversationID, Kind: kind, ID: entityID,
		Payload: payload, CreatedBy: id.UserID,
	}, &expectedVersion)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entity)
}

func (s *Server) listEntities(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	kind := chi.URLParam(r, "kind")
	if !validEntityKind(kind) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	since := parseTime(r.URL.Query().Get("since"))
	limit := parseLimit(r.URL.Query().Get("limit"), 100, 1000)
	items, err := s.store.ListEntities(r.Context(), conversationID, id.UserID, kind, since, limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	next := ""
	if len(items) == limit {
		next = items[len(items)-1].UpdatedAt.Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.Entity]{Items: items, NextCursor: next})
}

func (s *Server) deleteEntity(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	kind := chi.URLParam(r, "kind")
	entityID, err := uuid.Parse(chi.URLParam(r, "entityID"))
	if err != nil || !validEntityKind(kind) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	expectedVersion, ok := requiredExpectedVersion(w, r)
	if !ok {
		return
	}
	_, err = s.store.DeleteEntity(
		r.Context(), conversationID, id.UserID, kind, entityID, &expectedVersion,
	)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validEntityKind(kind string) bool {
	_, ok := allowedEntityKinds[kind]
	return ok
}

func requiredExpectedVersion(w http.ResponseWriter, r *http.Request) (int64, bool) {
	value := r.URL.Query().Get("expected_version")
	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil || version < 0 {
		writeError(w, http.StatusUnprocessableEntity, "expected_version_required",
			"expected_version is required and must match the current entity version; use 0 when creating.")
		return 0, false
	}
	return version, true
}
