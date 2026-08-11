package httpapi

import (
	"net/http"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) getPresence(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	targetUserID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if targetUserID != id.UserID {
		shared, err := s.store.UsersShareConversation(r.Context(), id.UserID, targetUserID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		if !shared {
			writeDomainError(w, domain.ErrForbidden)
			return
		}
	}
	online, err := s.presence.IsOnline(r.Context(), targetUserID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "presence_unavailable", "Presence is temporarily unavailable.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"online": online})
}
