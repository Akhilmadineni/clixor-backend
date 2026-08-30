package mail

import (
	"context"
	"errors"
	"time"
)

var ErrUnavailable = errors.New("mail delivery unavailable")

// Service submits transactional messages to the private NAS mail queue. It
// deliberately exposes no generic arbitrary-message API.
type Service interface {
	SendPasswordReset(context.Context, string, string, time.Duration) error
	SendPasswordChanged(context.Context, string) error
}

type HealthChecker interface {
	Ping(context.Context) error
}

type Unavailable struct{}

func (Unavailable) SendPasswordReset(context.Context, string, string, time.Duration) error {
	return ErrUnavailable
}

func (Unavailable) SendPasswordChanged(context.Context, string) error {
	return ErrUnavailable
}
