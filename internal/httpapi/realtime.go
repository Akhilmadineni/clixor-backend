package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var websocketUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		// Native clients do not send browser origins. Browser clients must be explicitly added later.
		return r.Header.Get("Origin") == ""
	},
}

func (s *Server) realtime(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFrom(r.Context())
	if !ok {
		writeDomainError(w, domain.ErrUnauthenticated)
		return
	}
	connection, err := websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	observability.WebsocketConnections.Inc()
	defer observability.WebsocketConnections.Dec()
	_ = s.presence.Online(r.Context(), id.UserID, id.DeviceID)
	defer s.presence.Offline(context.Background(), id.UserID, id.DeviceID)

	subscription, err := s.bus.Subscribe(r.Context(), id.UserID)
	if err != nil {
		_ = connection.WriteJSON(errorResponse{Error: errorBody{Code: "unavailable", Message: "Realtime delivery is unavailable."}})
		return
	}
	defer subscription.Close()

	connection.SetReadLimit(16 << 10)
	_ = connection.SetReadDeadline(time.Now().Add(70 * time.Second))
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(time.Now().Add(70 * time.Second))
	})

	hello, _ := json.Marshal(map[string]any{
		"user_id": id.UserID, "device_id": id.DeviceID, "heartbeat_seconds": 25,
	})
	if err := connection.WriteJSON(domain.RealtimeEvent{
		ID: uuid.NewString(), Type: "session.ready", Payload: hello, OccurredAt: time.Now().UTC(),
	}); err != nil {
		return
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		var lastTypingEvent time.Time
		for {
			var frame struct {
				Type           string     `json:"type"`
				ConversationID *uuid.UUID `json:"conversation_id,omitempty"`
				Active         bool       `json:"active,omitempty"`
			}
			if err := connection.ReadJSON(&frame); err != nil {
				return
			}
			if frame.Type == "ping" {
				_ = connection.WriteControl(websocket.PongMessage, nil, time.Now().Add(5*time.Second))
			} else if frame.Type == "typing" && frame.ConversationID != nil {
				if time.Since(lastTypingEvent) < 300*time.Millisecond {
					continue
				}
				lastTypingEvent = time.Now()
				members, err := s.store.ListConversationMembers(r.Context(), *frame.ConversationID, id.UserID)
				if err != nil {
					continue
				}
				recipients := make([]uuid.UUID, 0, len(members))
				for _, member := range members {
					if member.UserID != id.UserID {
						recipients = append(recipients, member.UserID)
					}
				}
				payload, _ := json.Marshal(map[string]any{
					"user_id": id.UserID, "device_id": id.DeviceID, "active": frame.Active,
				})
				_ = s.bus.Publish(r.Context(), recipients, domain.RealtimeEvent{
					ID: uuid.NewString(), Type: "typing.changed", ConversationID: frame.ConversationID,
					Payload: payload, OccurredAt: time.Now().UTC(),
				})
			}
		}
	}()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-readDone:
			return
		case <-ticker.C:
			_ = s.presence.Heartbeat(r.Context(), id.UserID, id.DeviceID)
			if err := connection.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				return
			}
		case event, open := <-subscription.Events():
			if !open {
				return
			}
			_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := connection.WriteJSON(event); err != nil {
				return
			}
		}
	}
}
