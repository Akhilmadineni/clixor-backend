package httpapi

import (
	"encoding/json"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"net/http"
)

func (s *Server) listBlocks(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	repo, err := s.complianceRepository()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	items, err := repo.Blocks(r.Context(), id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) setBlock(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	target, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil || target == id.UserID {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if r.Method == http.MethodPut {
		if _, err = s.store.UserByID(r.Context(), target); err != nil {
			writeDomainError(w, err)
			return
		}
	}
	repo, err := s.complianceRepository()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if err = repo.SetBlock(r.Context(), id.UserID, target, r.Method == http.MethodPut); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) communicationAllowed(w http.ResponseWriter, r *http.Request, a, b uuid.UUID) bool {
	repo, err := s.complianceRepository()
	if err != nil {
		writeDomainError(w, err)
		return false
	}
	blocked, err := repo.Blocked(r.Context(), a, b)
	if err != nil {
		writeDomainError(w, err)
		return false
	}
	if blocked {
		writeDomainError(w, domain.ErrForbidden)
		return false
	}
	return true
}
func communicationActor(event domain.RealtimeEvent) uuid.UUID {
	var body struct {
		SenderID uuid.UUID `json:"sender_id"`
		UserID   uuid.UUID `json:"user_id"`
	}
	if json.Unmarshal(event.Payload, &body) != nil {
		return uuid.Nil
	}
	if event.Type == "message.created" {
		return body.SenderID
	}
	if event.Type == "typing.changed" {
		return body.UserID
	}
	return uuid.Nil
}
