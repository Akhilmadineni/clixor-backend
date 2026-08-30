package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type accountDeletionCapabilityRequest struct {
	RecoveryToken string `json:"recovery_token"`
}

func accountDeletionTokenHash(value string) ([]byte, bool) {
	if len(value) != 43 || strings.Contains(value, "=") {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	digest := sha256.Sum256([]byte(value))
	return digest[:], true
}

func (s *Server) putAccountDeletionIntent(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	requestID, err := uuid.Parse(chi.URLParam(r, "requestID"))
	if err != nil || requestID == uuid.Nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	var request accountDeletionCapabilityRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	tokenHash, valid := accountDeletionTokenHash(request.RecoveryToken)
	if !valid {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if err := s.store.PutAccountDeletionIntent(r.Context(), domain.AccountDeletionIntent{
		RequestID: requestID, UserID: id.UserID, TokenHash: tokenHash,
	}); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) executeAccountDeletionIntent(w http.ResponseWriter, r *http.Request) {
	requestID, err := uuid.Parse(chi.URLParam(r, "requestID"))
	if err != nil || requestID == uuid.Nil {
		writeDomainError(w, domain.ErrNotFound)
		return
	}
	var request accountDeletionCapabilityRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	tokenHash, valid := accountDeletionTokenHash(request.RecoveryToken)
	if !valid {
		writeDomainError(w, domain.ErrNotFound)
		return
	}
	var ticket events.SessionFenceTicket
	err = s.store.ExecuteAccountDeletionIntent(
		r.Context(), requestID, tokenHash,
		func(userID uuid.UUID) error {
			var fenceErr error
			ticket, fenceErr = s.publishSessionRevocation(r.Context(), userID, nil)
			return fenceErr
		},
	)
	defer releaseSessionFence(ticket)
	if errors.Is(err, domain.ErrNotFound) {
		writeDomainError(w, domain.ErrNotFound)
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
