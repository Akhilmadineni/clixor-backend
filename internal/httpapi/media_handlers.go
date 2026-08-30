package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type mediaUploadRequest struct {
	ByteSize         int64  `json:"byte_size"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	ContentType      string `json:"content_type"`
}

func (s *Server) createMediaUpload(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	if _, err := s.store.Conversation(r.Context(), conversationID, id.UserID); err != nil {
		writeDomainError(w, err)
		return
	}
	var request mediaUploadRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.ByteSize < 1 || request.ByteSize > s.mediaPolicy.ConversationMaxBytes || !validSHA256(request.CiphertextSHA256) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	request.CiphertextSHA256 = strings.ToLower(request.CiphertextSHA256)
	contentType := normalizedContentType(request.ContentType, "application/octet-stream")
	if contentType == "" {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	mediaID := uuid.New()
	objectKey := "conversations/" + conversationID.String() + "/" + mediaID.String()
	record, err := s.store.CreateMedia(r.Context(), domain.MediaObject{
		ID: mediaID, OwnerID: id.UserID, ConversationID: conversationID,
		ObjectKey: objectKey, ContentType: contentType,
		ByteSize: request.ByteSize, CiphertextSHA256: request.CiphertextSHA256,
	}, s.mediaPolicy.ReservationLimits)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.writeMediaUpload(w, r, record)
}

func (s *Server) createProfileMediaUpload(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	var request mediaUploadRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.ByteSize < 1 || request.ByteSize > s.mediaPolicy.ProfileMaxBytes || !validSHA256(request.CiphertextSHA256) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	request.CiphertextSHA256 = strings.ToLower(request.CiphertextSHA256)
	contentType := normalizedContentType(request.ContentType, "image/jpeg")
	if contentType != "image/jpeg" && contentType != "image/png" &&
		contentType != "image/heic" && contentType != "image/webp" {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	mediaID := uuid.New()
	record, err := s.store.CreateProfileMedia(r.Context(), domain.MediaObject{
		ID: mediaID, OwnerID: id.UserID,
		ObjectKey:   "users/" + id.UserID.String() + "/avatars/" + mediaID.String(),
		ContentType: contentType, ByteSize: request.ByteSize,
		CiphertextSHA256: request.CiphertextSHA256,
	}, s.mediaPolicy.ReservationLimits)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.writeMediaUpload(w, r, record)
}

func (s *Server) writeMediaUpload(w http.ResponseWriter, r *http.Request, record domain.MediaObject) {
	if record.ExpiresAt == nil {
		_, _ = s.store.RejectPendingMedia(r.Context(), record.ID, record.OwnerID)
		writeDomainError(w, errors.New("media reservation missing expiry"))
		return
	}
	expiresIn := time.Until(record.ExpiresAt.UTC()).Truncate(time.Second)
	if expiresIn < time.Second {
		_, _ = s.store.RejectPendingMedia(r.Context(), record.ID, record.OwnerID)
		writeError(w, http.StatusGone, "upload_expired", "The media upload reservation has expired.")
		return
	}
	upload, err := s.media.PrepareUpload(
		r.Context(), record.ObjectKey, record.ContentType, record.ByteSize,
		record.CiphertextSHA256, expiresIn,
	)
	if err != nil {
		_, _ = s.store.RejectPendingMedia(r.Context(), record.ID, record.OwnerID)
		if errors.Is(err, media.ErrUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "media_unavailable", "Media uploads are unavailable in this environment.")
			return
		}
		writeDomainError(w, err)
		return
	}
	if upload.URL == nil || upload.Method == "" || len(upload.Headers) == 0 {
		_, _ = s.store.RejectPendingMedia(r.Context(), record.ID, record.OwnerID)
		writeDomainError(w, errors.New("media provider returned incomplete upload instructions"))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"media": record,
		"upload": map[string]any{
			"method": upload.Method, "url": upload.URL.String(),
			"headers":    upload.Headers,
			"expires_at": record.ExpiresAt,
		},
	})
}

func (s *Server) completeMediaUpload(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	mediaID, err := uuid.Parse(chi.URLParam(r, "mediaID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	record, err := s.store.Media(r.Context(), mediaID, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if record.OwnerID != id.UserID {
		writeDomainError(w, domain.ErrForbidden)
		return
	}
	if record.Status == "ready" {
		writeJSON(w, http.StatusOK, record)
		return
	}
	select {
	case s.mediaVerifySlots <- struct{}{}:
		defer func() { <-s.mediaVerifySlots }()
	case <-r.Context().Done():
		writeError(w, http.StatusServiceUnavailable, "media_verification_unavailable",
			"Media verification capacity is temporarily unavailable. Retry completion before the upload expires.")
		return
	}
	leaseDuration := s.mediaPolicy.CompletionTimeout + 15*time.Second
	record, err = s.store.ClaimMediaVerification(r.Context(), mediaID, id.UserID, leaseDuration)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrConflict):
			w.Header().Set("Retry-After", "2")
			writeError(w, http.StatusConflict, "media_verification_in_progress",
				"This media upload is already being verified. Retry shortly.")
		case errors.Is(err, domain.ErrMediaExpired):
			_, _ = s.store.RejectPendingMedia(r.Context(), mediaID, id.UserID)
			writeError(w, http.StatusGone, "upload_expired", "The media upload reservation has expired.")
		default:
			writeDomainError(w, err)
		}
		return
	}
	if record.Status == "ready" {
		writeJSON(w, http.StatusOK, record)
		return
	}
	if record.VerificationLeaseToken == nil {
		s.logger.Error("media_verification_missing_fence", "media_id", mediaID)
		writeError(w, http.StatusServiceUnavailable, "media_verification_unavailable",
			"Media verification is temporarily unavailable. Retry completion before the upload expires.")
		return
	}
	leaseToken := *record.VerificationLeaseToken
	if err := s.media.Verify(
		r.Context(), record.ObjectKey, record.ByteSize,
		record.CiphertextSHA256, record.ContentType,
	); err != nil {
		if !media.IsDefinitiveVerificationFailure(err) {
			releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
			releaseErr := s.store.ReleaseMediaVerification(releaseCtx, mediaID, id.UserID, leaseToken)
			cancel()
			if releaseErr != nil && !errors.Is(releaseErr, domain.ErrConflict) {
				s.logger.Warn("release_media_verification_failed", "error", releaseErr, "media_id", mediaID)
			}
			s.logger.Warn("media_verification_unavailable", "error", err, "media_id", mediaID)
			writeError(w, http.StatusServiceUnavailable, "media_verification_unavailable",
				"Media verification is temporarily unavailable. Retry completion before the upload expires.")
			return
		}
		if _, cleanupErr := s.store.RejectMediaVerification(
			r.Context(), mediaID, id.UserID, leaseToken,
		); cleanupErr != nil {
			if errors.Is(cleanupErr, domain.ErrConflict) {
				if latest, lookupErr := s.store.Media(r.Context(), mediaID, id.UserID); lookupErr == nil && latest.Status == "ready" {
					writeJSON(w, http.StatusOK, latest)
					return
				}
				w.Header().Set("Retry-After", "2")
				writeError(w, http.StatusConflict, "media_verification_in_progress",
					"This media upload is already being verified. Retry shortly.")
				return
			}
			if !errors.Is(cleanupErr, domain.ErrNotFound) {
				s.logger.Error("reject_invalid_media_failed", "error", cleanupErr, "media_id", mediaID)
				writeDomainError(w, cleanupErr)
				return
			}
		}
		writeError(w, http.StatusUnprocessableEntity, "upload_incomplete", "The uploaded object does not match its declaration.")
		return
	}
	ready, err := s.store.MarkMediaReady(r.Context(), mediaID, id.UserID, leaseToken)
	if err != nil {
		if latest, lookupErr := s.store.Media(r.Context(), mediaID, id.UserID); lookupErr == nil && latest.Status == "ready" {
			writeJSON(w, http.StatusOK, latest)
			return
		}
		if record.ExpiresAt != nil && !record.ExpiresAt.After(time.Now().UTC()) {
			_, _ = s.store.RejectMediaVerification(r.Context(), mediaID, id.UserID, leaseToken)
			writeDomainError(w, domain.ErrMediaExpired)
			return
		}
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ready)
}

func (s *Server) deleteMedia(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	mediaID, err := uuid.Parse(chi.URLParam(r, "mediaID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	record, err := s.store.Media(r.Context(), mediaID, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if record.OwnerID != id.UserID {
		writeDomainError(w, domain.ErrForbidden)
		return
	}
	if _, err := s.store.DeleteMedia(r.Context(), mediaID, id.UserID); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) mediaDownload(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	mediaID, err := uuid.Parse(chi.URLParam(r, "mediaID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	record, err := s.store.Media(r.Context(), mediaID, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if record.Status != "ready" {
		writeError(w, http.StatusConflict, "media_not_ready", "The media object is not ready.")
		return
	}
	downloadURL, err := s.media.DownloadURL(r.Context(), record.ObjectKey, 15*time.Minute)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url": downloadURL.String(), "expires_at": time.Now().UTC().Add(15 * time.Minute),
	})
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func normalizedContentType(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	if value == "" {
		value = fallback
	}
	if len(value) > 100 || !strings.Contains(value, "/") {
		return ""
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') ||
			char == '/' || char == '-' || char == '+' || char == '.' {
			continue
		}
		return ""
	}
	return value
}
