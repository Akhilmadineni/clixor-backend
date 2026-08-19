package media

import (
	"context"
	"errors"
	"net/url"
	"time"
)

var ErrUnavailable = errors.New("media service unavailable")

type Service interface {
	UploadURL(context.Context, string, string, int64, time.Duration) (*url.URL, error)
	DownloadURL(context.Context, string, time.Duration) (*url.URL, error)
	Verify(context.Context, string, int64) error
	Delete(context.Context, string) error
	Close()
}

type Unavailable struct{}

func (Unavailable) UploadURL(context.Context, string, string, int64, time.Duration) (*url.URL, error) {
	return nil, ErrUnavailable
}
func (Unavailable) DownloadURL(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, ErrUnavailable
}
func (Unavailable) Verify(context.Context, string, int64) error { return ErrUnavailable }
func (Unavailable) Delete(context.Context, string) error        { return ErrUnavailable }
func (Unavailable) Close()                                      {}
