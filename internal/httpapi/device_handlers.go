package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) putPreKeys(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	deviceID, err := uuid.Parse(chi.URLParam(r, "deviceID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if deviceID != id.DeviceID {
		writeDomainError(w, domain.ErrForbidden)
		return
	}
	if _, err := s.store.Device(r.Context(), id.UserID, deviceID); err != nil {
		writeDomainError(w, err)
		return
	}
	var request struct {
		Keys []domain.OneTimePreKey `json:"keys"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.Keys) == 0 || len(request.Keys) > 1000 {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	seen := make(map[uint32]struct{}, len(request.Keys))
	for _, key := range request.Keys {
		if !validEncodedKey(key.PublicKey) {
			writeDomainError(w, domain.ErrInvalid)
			return
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			writeDomainError(w, domain.ErrInvalid)
			return
		}
		seen[key.KeyID] = struct{}{}
	}
	if err := s.store.PutOneTimePreKeys(r.Context(), deviceID, request.Keys); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) claimPreKey(w http.ResponseWriter, r *http.Request) {
	targetUserID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	bundles, err := s.store.ClaimPreKeys(r.Context(), targetUserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": bundles})
}

func validEncodedKey(value string) bool {
	if len(value) < 20 || len(value) > 1024 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	return err == nil && len(decoded) >= 16 && len(decoded) <= 512
}

func validSignedPreKey(value json.RawMessage) bool {
	var key struct {
		KeyID     uint32 `json:"key_id"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
	}
	if len(value) > 4096 || json.Unmarshal(value, &key) != nil {
		return false
	}
	return validEncodedKey(key.PublicKey) && validEncodedKey(key.Signature)
}
