package httpapi

import (
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) createMediaUpload(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	if _, err := s.store.Conversation(r.Context(), conversationID, id.UserID); err != nil {
		writeDomainError(w, err)
		return
	}
	var request struct {
		ByteSize         int64  `json:"byte_size"`
		CiphertextSHA256 string `json:"ciphertext_sha256"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.ByteSize < 1 || request.ByteSize > 1<<30 || !validSHA256(request.CiphertextSHA256) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	mediaID := uuid.New()
	objectKey := "conversations/" + conversationID.String() + "/" + mediaID.String()
	record, err := s.store.CreateMedia(r.Context(), domain.MediaObject{
		ID: mediaID, OwnerID: id.UserID, ConversationID: conversationID,
		ObjectKey: objectKey, ContentType: "application/octet-stream",
		ByteSize: request.ByteSize, CiphertextSHA256: request.CiphertextSHA256,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	uploadURL, err := s.media.UploadURL(
		r.Context(), objectKey, record.ContentType, record.ByteSize, 15*time.Minute,
	)
	if err != nil {
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
			"headers":    map[string]string{"Content-Type": "application/octet-stream"},
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
	if err := s.media.Verify(r.Context(), record.ObjectKey, record.ByteSize); err != nil {
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
