package media

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

var (
	ErrUnavailable          = errors.New("media service unavailable")
	ErrUploadMissing        = errors.New("uploaded media object is missing")
	ErrVerificationMismatch = errors.New("uploaded media object does not match its declaration")
)

// IsDefinitiveVerificationFailure reports whether retrying verification cannot
// make the current object valid. Network, timeout, and storage 5xx failures are
// deliberately not definitive: callers must retain the pending reservation so
// the client can retry completion.
func IsDefinitiveVerificationFailure(err error) bool {
	return errors.Is(err, ErrUploadMissing) || errors.Is(err, ErrVerificationMismatch)
}

// UploadInstructions are the provider-neutral instructions a client must use
// for a direct object upload. Headers contains every value the storage provider
// authenticates or needs in order to persist the declared checksum.
type UploadInstructions struct {
	Method  string
	URL     *url.URL
	Headers map[string]string
}

type Service interface {
	PrepareUpload(context.Context, string, string, int64, string, time.Duration) (UploadInstructions, error)
	DownloadURL(context.Context, string, time.Duration) (*url.URL, error)
	Verify(context.Context, string, int64, string, string) error
	Delete(context.Context, string) error
	Close()
}

type Unavailable struct{}

func (Unavailable) PrepareUpload(context.Context, string, string, int64, string, time.Duration) (UploadInstructions, error) {
	return UploadInstructions{}, ErrUnavailable
}
func (Unavailable) DownloadURL(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, ErrUnavailable
}
func (Unavailable) Verify(context.Context, string, int64, string, string) error {
	return ErrUnavailable
}
func (Unavailable) Delete(context.Context, string) error { return ErrUnavailable }
func (Unavailable) Close()                               {}

func instructions(uploadURL *url.URL, headers map[string]string) UploadInstructions {
	return UploadInstructions{Method: http.MethodPut, URL: uploadURL, Headers: headers}
}
