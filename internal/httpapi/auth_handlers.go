package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type credentialsRequest struct {
	Email       string    `json:"email"`
	Password    string    `json:"password"`
	DisplayName string    `json:"display_name,omitempty"`
	DeviceID    uuid.UUID `json:"device_id,omitempty"`
	DeviceName  string    `json:"device_name"`
	Platform    string    `json:"platform"`
}

type authResponse struct {
	User   domain.User    `json:"user"`
	Device domain.Device  `json:"device"`
	Tokens auth.TokenPair `json:"tokens"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var request credentialsRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	if !validEmail(request.Email) || len(request.DisplayName) > 100 ||
		!validDeviceInfo(request.DeviceName, request.Platform) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	hash, err := auth.HashPassword(request.Password)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "weak_password", err.Error())
		return
	}
	user, err := s.store.CreateUser(r.Context(), store.CreateUserParams{
		Email: request.Email, DisplayName: strings.TrimSpace(request.DisplayName), PasswordHash: hash,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	// Device IDs are account-bound cryptographic identities. A new account must
	// never inherit an installation ID that may belong to a previously signed-in
	// account on the same phone.
	device, err := s.registerDevice(r, user.ID, uuid.Nil, request.DeviceName, request.Platform)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	tokens, err := s.tokens.Issue(r.Context(), user.ID, device.ID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, authResponse{User: user, Device: device, Tokens: tokens})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var request credentialsRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if !validDeviceInfo(request.DeviceName, request.Platform) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	if !validEmail(request.Email) || len(request.Password) < 10 || len(request.Password) > 256 {
		_ = auth.VerifyPassword(s.dummyHash, "invalid-credential-shape")
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The email or password is incorrect.")
		return
	}
	user, err := s.store.UserByEmail(r.Context(), request.Email)
	hash := s.dummyHash
	if err == nil {
		hash = user.PasswordHash
	}
	valid := auth.VerifyPassword(hash, request.Password)
	if err != nil || !valid {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The email or password is incorrect.")
		return
	}
	device, err := s.registerDevice(r, user.ID, request.DeviceID, request.DeviceName, request.Platform)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	tokens, err := s.tokens.Issue(r.Context(), user.ID, device.ID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, authResponse{User: user, Device: device, Tokens: tokens})
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	tokens, err := s.tokens.Refresh(r.Context(), request.RefreshToken)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	if err := s.store.RevokeSession(r.Context(), id.SessionID, id.UserID); err != nil &&
		!errors.Is(err, domain.ErrNotFound) {
		writeDomainError(w, err)
		return
	}
	if err := s.store.ClearDevicePushToken(r.Context(), id.UserID, id.DeviceID); err != nil &&
		!errors.Is(err, domain.ErrNotFound) {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	user, err := s.store.UserByID(r.Context(), id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	if err := s.store.DeleteAccount(r.Context(), id.UserID); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	var profile map[string]any
	if !decodeJSON(w, r, &profile) {
		return
	}
	for _, protected := range []string{"id", "email", "phone", "password", "password_hash"} {
		if _, present := profile[protected]; present {
			writeError(w, http.StatusUnprocessableEntity, "protected_field", "Identity fields require a verified account flow.")
			return
		}
	}
	if displayName, ok := profile["display_name"].(string); ok && len(strings.TrimSpace(displayName)) > 100 {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if avatarURL, ok := profile["avatar_url"].(string); ok && len(avatarURL) > 2048 {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if username, ok := profile["username"].(string); ok && strings.TrimSpace(username) != "" {
		normalized := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(username), "@"))
		if len(normalized) < 3 || len(normalized) > 30 {
			writeError(w, http.StatusUnprocessableEntity, "invalid_username", "Username must be 3–30 characters (letters, numbers, _ or .).")
			return
		}
	}
	user, err := s.store.UpdateUserProfile(r.Context(), id.UserID, rawJSON(profile))
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			writeError(w, http.StatusConflict, "username_taken", "That username is already taken.")
			return
		}
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	devices, err := s.store.ListDevices(r.Context(), id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.Device]{Items: devices})
}

func (s *Server) upsertDevice(w http.ResponseWriter, r *http.Request) {
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
	var request struct {
		Name         string          `json:"name"`
		Platform     string          `json:"platform"`
		PushToken    string          `json:"push_token,omitempty"`
		IdentityKey  string          `json:"identity_key,omitempty"`
		SignedPreKey json.RawMessage `json:"signed_prekey,omitempty"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	request.PushToken = strings.ToLower(strings.TrimSpace(request.PushToken))
	if strings.TrimSpace(request.Name) == "" || request.Platform != "ios" ||
		len(request.Name) > 100 || !validPushToken(request.PushToken) ||
		(request.IdentityKey != "" && !validEncodedKey(request.IdentityKey)) ||
		(len(request.SignedPreKey) > 0 && !validSignedPreKey(request.SignedPreKey)) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	device, err := s.store.UpsertDevice(r.Context(), domain.Device{
		ID: deviceID, UserID: id.UserID, Name: request.Name, Platform: request.Platform,
		PushToken: request.PushToken, IdentityKey: request.IdentityKey,
		SignedPreKey: request.SignedPreKey,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func validPushToken(token string) bool {
	if token == "" {
		return true
	}
	if len(token) > 512 || len(token)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

func (s *Server) registerDevice(r *http.Request, userID, deviceID uuid.UUID, name, platform string) (domain.Device, error) {
	if deviceID == uuid.Nil {
		deviceID = uuid.New()
	}
	if name == "" {
		name = "iPhone"
	}
	if platform == "" {
		platform = "ios"
	}
	return s.store.UpsertDevice(r.Context(), domain.Device{
		ID: deviceID, UserID: userID, Name: name, Platform: platform,
		CreatedAt: time.Now().UTC(),
	})
}

func validEmail(value string) bool {
	at := strings.LastIndex(value, "@")
	return at > 0 && at < len(value)-3 && strings.Contains(value[at:], ".") && len(value) <= 254
}

func validDeviceInfo(name, platform string) bool {
	return len(name) <= 100 && (platform == "" || platform == "ios")
}
