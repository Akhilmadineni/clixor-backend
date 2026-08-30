package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

const passwordResetResponseFloor = 500 * time.Millisecond

type passwordResetStartRequest struct {
	Email string `json:"email"`
}

type passwordResetStartResponse struct {
	ChallengeID string `json:"challenge_id"`
	ExpiresIn   int64  `json:"expires_in_seconds"`
	Message     string `json:"message"`
}

type passwordResetConfirmRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

func (s *Server) startPasswordReset(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if !s.passwordReset.Enabled || len(s.passwordReset.HMACSecret) < 32 {
		writeError(w, http.StatusServiceUnavailable, "password_reset_unavailable", "Password reset is temporarily unavailable.")
		return
	}
	var request passwordResetStartRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(request.Email))
	if !validEmail(email) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	challengeID := uuid.New()
	response := passwordResetStartResponse{
		ChallengeID: challengeID.String(),
		ExpiresIn:   int64(s.passwordReset.TTL / time.Second),
		Message:     "If this email belongs to a password account, a reset code will be sent.",
	}
	respond := func() {
		if remaining := passwordResetResponseFloor - time.Since(started); remaining > 0 {
			time.Sleep(remaining)
		}
		writeJSON(w, http.StatusAccepted, response)
	}

	limitKey := "password-reset-email:" + passwordResetEmailKey(s.passwordReset.HMACSecret, email)
	allowed, err := s.limiter.Allow(r.Context(), limitKey, 3, time.Hour)
	if err != nil {
		s.logger.Error("password_reset_rate_limiter_unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
		return
	}
	if !allowed {
		// The limiter is keyed from an HMAC of the normalized address regardless
		// of account existence, so a 429 does not enumerate users. Do not return a
		// fresh, unpersisted challenge ID here: clients would replace a still-usable
		// challenge with an impossible one and strand the reset flow.
		w.Header().Set("Retry-After", "3600")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many reset requests. Try again later.")
		return
	}

	code, err := generatePasswordResetCode(s.passwordReset.CodeLength)
	if err != nil {
		s.logger.Error("password_reset_code_generation_failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
		return
	}
	codeHash := passwordResetCodeHash(s.passwordReset.HMACSecret, challengeID, code)
	user, userErr := s.store.UserByEmail(r.Context(), email)
	if errors.Is(userErr, domain.ErrNotFound) || (userErr == nil && user.PasswordHash == "") {
		// Perform the same code/HMAC work but do not persist a challenge or send
		// mail for unknown and passwordless identities.
		respond()
		return
	}
	if userErr != nil {
		s.logger.Error("password_reset_user_lookup_failed", "error", userErr)
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
		return
	}
	now := time.Now().UTC()
	challenge := domain.PasswordResetChallenge{
		ID: challengeID, UserID: user.ID, CodeHash: codeHash,
		ExpiresAt: now.Add(s.passwordReset.TTL), CreatedAt: now,
	}
	if err := s.store.CreatePasswordResetChallenge(r.Context(), challenge); errors.Is(err, domain.ErrNotFound) {
		// Account deletion may win after the lookup. Preserve the same delayed,
		// generic response as an unknown or passwordless address.
		respond()
		return
	} else if err != nil {
		s.logger.Error("password_reset_challenge_create_failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
		return
	}
	if err := s.mailer.SendPasswordReset(r.Context(), user.Email, code, s.passwordReset.TTL); err != nil {
		s.logger.Error("password_reset_mail_queue_failed", "challenge_id", challengeID, "error", err)
		// A reset challenge is usable only after the mail transport accepts the
		// message. Remove it on queue failure so a later request can issue a fresh
		// code instead of leaving an active challenge the user never received. Use
		// a bounded context detached from the request because client cancellation
		// is itself a common reason for the mail submission to fail.
		cleanupContext, cleanupCancel := context.WithTimeout(
			context.WithoutCancel(r.Context()), 5*time.Second,
		)
		defer cleanupCancel()
		if cancelErr := s.store.CancelPasswordResetChallenge(cleanupContext, challengeID); cancelErr != nil {
			s.logger.Error(
				"password_reset_challenge_cancel_failed",
				"challenge_id", challengeID,
				"error", cancelErr,
			)
		}
	}
	respond()
}

func (s *Server) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	if !s.passwordReset.Enabled || len(s.passwordReset.HMACSecret) < 32 {
		writeError(w, http.StatusServiceUnavailable, "password_reset_unavailable", "Password reset is temporarily unavailable.")
		return
	}
	var request passwordResetConfirmRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	challengeID, err := uuid.Parse(strings.TrimSpace(request.ChallengeID))
	if err != nil || !validNumericCode(request.Code, s.passwordReset.CodeLength) {
		writeError(w, http.StatusBadRequest, "invalid_reset_code", "The reset code is invalid or expired.")
		return
	}
	newPasswordHash, err := auth.HashPassword(request.NewPassword)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "weak_password", err.Error())
		return
	}
	codeHash := passwordResetCodeHash(
		s.passwordReset.HMACSecret, challengeID, strings.TrimSpace(request.Code),
	)
	email, err := s.store.ConsumePasswordResetChallenge(
		r.Context(), challengeID, codeHash, newPasswordHash, s.passwordReset.MaxAttempts,
	)
	if errors.Is(err, domain.ErrUnauthenticated) || errors.Is(err, domain.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "invalid_reset_code", "The reset code is invalid or expired.")
		return
	}
	if err != nil {
		s.logger.Error("password_reset_consume_failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
		return
	}
	if email != "" {
		if err := s.mailer.SendPasswordChanged(r.Context(), email); err != nil {
			s.logger.Error("password_changed_mail_queue_failed", "error", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func generatePasswordResetCode(length int) (string, error) {
	limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", err
	}
	return leftPadDigits(value.String(), length), nil
}

func leftPadDigits(value string, length int) string {
	if len(value) >= length {
		return value
	}
	return strings.Repeat("0", length-len(value)) + value
}

func passwordResetCodeHash(secret string, challengeID uuid.UUID, code string) []byte {
	digest := hmac.New(sha256.New, []byte(secret))
	_, _ = digest.Write(challengeID[:])
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(code))
	return digest.Sum(nil)
}

func passwordResetEmailKey(secret, email string) string {
	digest := hmac.New(sha256.New, []byte(secret))
	_, _ = digest.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(digest.Sum(nil)[:16])
}

func validNumericCode(value string, length int) bool {
	value = strings.TrimSpace(value)
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
