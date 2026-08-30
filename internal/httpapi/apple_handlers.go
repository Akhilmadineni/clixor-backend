package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Akhilmadineni/clixor-backend/internal/appleauth"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func (s *Server) verifyAppleIdentity(w http.ResponseWriter, r *http.Request) {
	var request struct {
		IdentityToken string    `json:"identity_token"`
		RawNonce      string    `json:"raw_nonce"`
		DisplayName   string    `json:"display_name,omitempty"`
		DeviceID      uuid.UUID `json:"device_id,omitempty"`
		DeviceName    string    `json:"device_name,omitempty"`
		Platform      string    `json:"platform,omitempty"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.IdentityToken) > 16<<10 || len(request.RawNonce) < 16 ||
		len(request.RawNonce) > 256 || len(request.DisplayName) > 100 ||
		!validDeviceInfo(request.DeviceName, request.Platform) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	identity, err := s.apple.Verify(r.Context(), request.IdentityToken, request.RawNonce)
	if err != nil {
		if errors.Is(err, appleauth.ErrUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "apple_auth_unavailable", "Sign in with Apple is temporarily unavailable.")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid_apple_identity", "The Apple identity could not be verified.")
		return
	}
	user, err := s.store.UserByExternalIdentity(r.Context(), "apple", identity.Subject)
	if errors.Is(err, domain.ErrNotFound) && identity.Email != "" {
		user, err = s.store.UserByEmail(r.Context(), identity.Email)
	}
	if errors.Is(err, domain.ErrNotFound) {
		user, err = s.store.CreateUser(r.Context(), store.CreateUserParams{
			Email: identity.Email, DisplayName: strings.TrimSpace(request.DisplayName),
		})
		if errors.Is(err, domain.ErrConflict) && identity.Email != "" {
			user, err = s.store.UserByEmail(r.Context(), identity.Email)
		}
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if err := s.store.LinkExternalIdentity(r.Context(), "apple", identity.Subject, user.ID, identity.Email); err != nil {
		writeDomainError(w, err)
		return
	}
	device := newAuthDevice(user.ID, request.DeviceID, request.DeviceName, request.Platform)
	user, device, tokens, err := s.tokens.IssueWithDevice(r.Context(), user.ID, nil, device)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, authResponse{User: user, Device: device, Tokens: tokens})
}
