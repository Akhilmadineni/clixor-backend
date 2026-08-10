package httpapi

import (
	"errors"
	"io"
	"net/http"

	"github.com/Akhilmadineni/clixor-backend/internal/verification"
)

func (s *Server) telnyxMessagingWebhook(w http.ResponseWriter, r *http.Request) {
	processor, ok := s.verifier.(verification.WebhookProcessor)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "The requested resource was not found.")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_webhook", "Invalid webhook.")
		return
	}
	if len(body) > 1<<20 {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "Webhook payload is too large.")
		return
	}
	err = processor.HandleWebhook(
		r.Context(), r.Header.Get("telnyx-signature-ed25519"),
		r.Header.Get("telnyx-timestamp"), body,
	)
	if errors.Is(err, verification.ErrInvalidWebhook) {
		writeError(w, http.StatusUnauthorized, "invalid_webhook", "Invalid webhook signature.")
		return
	}
	if err != nil {
		s.logger.Error("telnyx_webhook_failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please retry the webhook.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}
