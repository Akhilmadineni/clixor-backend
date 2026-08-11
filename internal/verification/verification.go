package verification

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnavailable    = errors.New("verification service unavailable")
	ErrInvalidCode    = errors.New("invalid verification code")
	ErrExpiredCode    = errors.New("verification code expired")
	ErrRateLimited    = errors.New("verification rate limited")
	ErrLocked         = errors.New("verification temporarily locked")
	ErrInvalidWebhook = errors.New("invalid verification webhook")
)

type Service interface {
	Send(context.Context, string) error
	Check(context.Context, string, string) error
}

// RetryError carries a safe delay to the HTTP layer without exposing a phone
// number, provider response, or internal Redis key.
type RetryError struct {
	Kind       error
	RetryAfter time.Duration
}

func (e *RetryError) Error() string { return e.Kind.Error() }
func (e *RetryError) Unwrap() error { return e.Kind }

type WebhookProcessor interface {
	HandleWebhook(context.Context, string, string, []byte) error
}

type HealthChecker interface {
	Ping(context.Context) error
}

type Closer interface {
	Close() error
}

type Unavailable struct{}

func (Unavailable) Send(context.Context, string) error          { return ErrUnavailable }
func (Unavailable) Check(context.Context, string, string) error { return ErrUnavailable }

type Development struct {
	Code string
}

func (Development) Send(context.Context, string) error { return nil }
func (d Development) Check(_ context.Context, _ string, code string) error {
	if code != d.Code {
		return ErrInvalidCode
	}
	return nil
}
