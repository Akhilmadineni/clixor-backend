package httpapi

import (
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
	if request.ByteSize < 1 || request.ByteSize > 1<<30 || !validSHA256(request.CiphertextSHA256) {
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
	})
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
	if request.ByteSize < 1 || request.ByteSize > 20<<20 || !validSHA256(request.CiphertextSHA256) {
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
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.writeMediaUpload(w, r, record)
}

func (s *Server) writeMediaUpload(w http.ResponseWriter, r *http.Request, record domain.MediaObject) {
	uploadURL, err := s.media.UploadURL(
		r.Context(), record.ObjectKey, record.ContentType, record.ByteSize, 15*time.Minute,
	)
	if err != nil {
		_, _ = s.store.DeleteMedia(r.Context(), record.ID, record.OwnerID)
		if errors.Is(err, media.ErrUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "media_unavailable", "Media uploads are unavailable in this environment.")
			return
		}
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"media": record,
		"upload": map[string]any{
			"method": "PUT", "url": uploadURL.String(),
			"headers":    map[string]string{"Content-Type": record.ContentType},
			"expires_at": time.Now().UTC().Add(15 * time.Minute),
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
	expectedSHA256 := record.CiphertextSHA256
	if record.Scope == domain.MediaScopeConversation {
		// Production 05b allows 1 GiB conversation objects and gives completion
		// requests the ordinary short client deadline. Preserve the ad9 size-only
		// completion contract here; streaming a full object through the API would
		// time out otherwise. Profile media is bounded to 20 MiB and keeps exact
		// digest verification.
		expectedSHA256 = ""
	}
	if err := s.media.Verify(r.Context(), record.ObjectKey, record.ByteSize, expectedSHA256); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "upload_incomplete", "The uploaded object does not match its declaration.")
		return
	}
	record, err = s.store.MarkMediaReady(r.Context(), mediaID, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
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
