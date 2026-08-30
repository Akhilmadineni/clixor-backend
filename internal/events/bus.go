package events

import (
	"context"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

type Subscription interface {
	Events() <-chan domain.RealtimeEvent
	Close() error
}

// SessionOwner is a durable declaration that this process owns at least one
// realtime socket for the user. Closing it removes that declaration when the
// final local socket closes.
type SessionOwner interface {
	Valid() bool
	Close() error
}

type SessionFence func(sessionID *uuid.UUID)

type SessionFenceTicket interface {
	Release(context.Context) error
}

type Bus interface {
	Ping(context.Context) error
	Publish(context.Context, []uuid.UUID, domain.RealtimeEvent) error
	Subscribe(context.Context, uuid.UUID) (Subscription, error)
	RegisterSessionOwner(context.Context, uuid.UUID, uuid.UUID, SessionFence) (SessionOwner, error)
	FenceSessions(context.Context, uuid.UUID, *uuid.UUID) (SessionFenceTicket, error)
	Close()
}
