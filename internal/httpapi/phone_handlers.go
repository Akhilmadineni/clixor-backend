package httpapi

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/Akhilmadineni/clixor-backend/internal/verification"
	"github.com/google/uuid"
)

var e164Pattern = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

type phoneAuthRequest struct {
	Phone      string    `json:"phone"`
	Code       string    `json:"code,omitempty"`
	DeviceID   uuid.UUID `json:"device_id,omitempty"`
	DeviceName string    `json:"device_name,omitempty"`
	Platform   string    `json:"platform,omitempty"`
}

func (s *Server) startPhoneVerification(w http.ResponseWriter, r *http.Request) {
	var request phoneAuthRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Phone = strings.TrimSpace(request.Phone)
	if !e164Pattern.MatchString(request.Phone) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if err := s.verifier.Send(r.Context(), request.Phone); err != nil {
		if writeVerificationRetry(w, err) {
			return
		}
		if errors.Is(err, verification.ErrUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "verification_unavailable", "Phone verification is unavailable.")
			return
		}
		s.logger.Error("send_phone_verification", "error", err)
		writeError(w, http.StatusBadGateway, "verification_failed", "The verification message could not be sent.")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
}

func (s *Server) verifyPhone(w http.ResponseWriter, r *http.Request) {
	var request phoneAuthRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Phone = strings.TrimSpace(request.Phone)
	if !e164Pattern.MatchString(request.Phone) || len(request.Code) < 4 || len(request.Code) > 10 ||
		!validDeviceInfo(request.DeviceName, request.Platform) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if err := s.verifier.Check(r.Context(), request.Phone, request.Code); err != nil {
		if writeVerificationRetry(w, err) {
			return
		}
		if errors.Is(err, verification.ErrInvalidCode) || errors.Is(err, verification.ErrExpiredCode) {
			writeError(w, http.StatusUnauthorized, "invalid_code", "The verification code is invalid or expired.")
			return
		}
		if errors.Is(err, verification.ErrUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "verification_unavailable", "Phone verification is unavailable.")
			return
		}
		s.logger.Error("check_phone_verification", "error", err)
		writeError(w, http.StatusBadGateway, "verification_failed", "Phone verification is temporarily unavailable.")
		return
	}
	user, err := s.store.UserByPhone(r.Context(), request.Phone)
	if errors.Is(err, domain.ErrNotFound) {
		user, err = s.store.CreateUser(r.Context(), store.CreateUserParams{Phone: request.Phone})
		if errors.Is(err, domain.ErrConflict) {
			user, err = s.store.UserByPhone(r.Context(), request.Phone)
		}
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	device, err := s.registerDevice(r, user.ID, request.DeviceID, request.DeviceName, request.Platform)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if _, err := s.store.ClaimConversationInvites(r.Context(), user.ID, request.Phone); err != nil {
		s.logger.Error("claim_phone_invites", "error", err, "user_id", user.ID)
		writeError(w, http.StatusInternalServerError, "invite_claim_failed", "The account was verified, but its pending invitations could not be claimed.")
		return
	}
	tokens, err := s.tokens.Issue(r.Context(), user.ID, device.ID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, authResponse{User: user, Device: device, Tokens: tokens})
}

func writeVerificationRetry(w http.ResponseWriter, err error) bool {
	var retry *verification.RetryError
	if !errors.As(err, &retry) {
		return false
	}
	seconds := int64((retry.RetryAfter + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeError(w, http.StatusTooManyRequests, "verification_rate_limited", "Too many verification attempts. Please wait before trying again.")
	return true
}
