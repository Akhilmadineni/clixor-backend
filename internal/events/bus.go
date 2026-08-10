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

type Bus interface {
	Ping(context.Context) error
	Publish(context.Context, []uuid.UUID, domain.RealtimeEvent) error
	Subscribe(context.Context, uuid.UUID) (Subscription, error)
	Close()
}
