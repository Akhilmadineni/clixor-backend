package httpapi

import (
	"context"

	"github.com/google/uuid"
)

type identity struct {
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	SessionID uuid.UUID
}

type identityKey struct{}

func withIdentity(ctx context.Context, value identity) context.Context {
	return context.WithValue(ctx, identityKey{}, value)
}

func identityFrom(ctx context.Context) (identity, bool) {
	value, ok := ctx.Value(identityKey{}).(identity)
	return value, ok
}
