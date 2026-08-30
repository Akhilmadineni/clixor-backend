package httpapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

const sessionRevokedEventType = "session.revoked"

type sessionRevocationPayload struct {
	SessionID *uuid.UUID `json:"session_id,omitempty"`
	All       bool       `json:"all,omitempty"`
}

// publishSessionRevocation is an acceleration signal only. Realtime delivery
// independently checks the durable session row before every event, so a dropped
// NATS/memory-bus message cannot extend a revoked session's access.
func (s *Server) publishSessionRevocation(
	ctx context.Context,
	userID uuid.UUID,
	sessionID *uuid.UUID,
) {
	payload := sessionRevocationPayload{SessionID: sessionID, All: sessionID == nil}
	encoded, _ := json.Marshal(payload)
	if err := s.bus.Publish(ctx, []uuid.UUID{userID}, domain.RealtimeEvent{
		ID:         uuid.NewString(),
		Type:       sessionRevokedEventType,
		Payload:    encoded,
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		s.logger.Warn("session_revocation_signal_failed", "user_id", userID, "error", err)
	}
}
