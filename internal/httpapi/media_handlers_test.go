package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/appleauth"
	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	clustrmail "github.com/Akhilmadineni/clixor-backend/internal/mail"
	"github.com/Akhilmadineni/clixor-backend/internal/presence"
	"github.com/Akhilmadineni/clixor-backend/internal/ratelimit"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/Akhilmadineni/clixor-backend/internal/verification"
)

type testMediaService struct {
	verifyErr      error
	verifiedKey    string
	verifiedSize   int64
	verifiedSHA256 string
}

func (*testMediaService) UploadURL(_ context.Context, _ string, _ string, _ int64, _ time.Duration) (*url.URL, error) {
	return url.Parse("https://media.example/upload")
}

func (*testMediaService) DownloadURL(_ context.Context, _ string, _ time.Duration) (*url.URL, error) {
	return url.Parse("https://media.example/download")
}

func (m *testMediaService) Verify(_ context.Context, key string, size int64, sha256 string) error {
	m.verifiedKey, m.verifiedSize, m.verifiedSHA256 = key, size, sha256
	return m.verifyErr
}

func (*testMediaService) Delete(context.Context, string) error { return nil }
func (*testMediaService) Close()                               {}

func TestProfileMediaLifecycleIsUserScopedAndIntegrityChecked(t *testing.T) {
	t.Parallel()
	mediaService := &testMediaService{}
	server := newTestHTTPServerWithMedia(t, mediaService)
	alice := registerTestUser(t, server.URL, "avatar-alice@example.com")
	bob := registerTestUser(t, server.URL, "avatar-bob@example.com")
	const digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	var upload struct {
		Media  domain.MediaObject `json:"media"`
		Upload struct {
			Headers map[string]string `json:"headers"`
		} `json:"upload"`
	}
	alice.client.do(t, http.MethodPost, "/v1/me/avatar", map[string]any{
		"byte_size": 3, "ciphertext_sha256": digest, "content_type": "image/jpeg",
	}, http.StatusCreated, &upload)
	if upload.Media.Scope != domain.MediaScopeProfile || upload.Media.ConversationID != [16]byte{} {
		t.Fatalf("unexpected profile media: %+v", upload.Media)
	}
	if upload.Upload.Headers["Content-Type"] != "image/jpeg" {
		t.Fatalf("upload content type = %q", upload.Upload.Headers["Content-Type"])
	}
	bob.client.do(t, http.MethodGet, "/v1/media/"+upload.Media.ID.String()+"/download", nil, http.StatusForbidden, nil)

	var ready domain.MediaObject
	alice.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete", nil, http.StatusOK, &ready)
	if mediaService.verifiedSize != 3 || mediaService.verifiedSHA256 != digest || mediaService.verifiedKey == "" {
		t.Fatalf("integrity verification was not called with the declaration: %+v", mediaService)
	}
	var me domain.User
	alice.client.do(t, http.MethodGet, "/v1/me", nil, http.StatusOK, &me)
	if me.AvatarURL != "clustr-media://"+upload.Media.ID.String() || !strings.Contains(string(me.Profile), upload.Media.ID.String()) {
		t.Fatalf("completed avatar was not activated: %+v", me)
	}
	bob.client.do(t, http.MethodGet, "/v1/media/"+upload.Media.ID.String()+"/download", nil, http.StatusOK, nil)

	var replacement struct {
		Media domain.MediaObject `json:"media"`
	}
	alice.client.do(t, http.MethodPost, "/v1/me/avatar", map[string]any{
		"byte_size": 3, "ciphertext_sha256": digest, "content_type": "image/jpeg",
	}, http.StatusCreated, &replacement)
	alice.client.do(t, http.MethodPost, "/v1/media/"+replacement.Media.ID.String()+"/complete", nil, http.StatusOK, nil)
	bob.client.do(t, http.MethodGet, "/v1/media/"+upload.Media.ID.String()+"/download", nil, http.StatusNotFound, nil)
	bob.client.do(t, http.MethodDelete, "/v1/media/"+replacement.Media.ID.String(), nil, http.StatusForbidden, nil)
	alice.client.do(t, http.MethodDelete, "/v1/media/"+replacement.Media.ID.String(), nil, http.StatusNoContent, nil)
	alice.client.do(t, http.MethodGet, "/v1/media/"+replacement.Media.ID.String()+"/download", nil, http.StatusNotFound, nil)
}

func TestProfileMediaHashFailureDoesNotActivateAvatar(t *testing.T) {
	t.Parallel()
	mediaService := &testMediaService{verifyErr: errors.New("hash mismatch")}
	server := newTestHTTPServerWithMedia(t, mediaService)
	alice := registerTestUser(t, server.URL, "avatar-mismatch@example.com")
	const digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	var upload struct {
		Media domain.MediaObject `json:"media"`
	}
	alice.client.do(t, http.MethodPost, "/v1/me/avatar", map[string]any{
		"byte_size": 3, "ciphertext_sha256": digest,
	}, http.StatusCreated, &upload)
	alice.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete", nil, http.StatusUnprocessableEntity, nil)
	var me domain.User
	alice.client.do(t, http.MethodGet, "/v1/me", nil, http.StatusOK, &me)
	if me.AvatarURL != "" {
		t.Fatalf("failed upload became avatar: %+v", me)
	}
}

func newTestHTTPServerWithMedia(t *testing.T, mediaService *testMediaService) *httptest.Server {
	t.Helper()
	server, _ := newTestHTTPServerWithMediaStore(t, mediaService)
	return server
}

func newTestHTTPServerWithMediaStore(
	t *testing.T,
	mediaService *testMediaService,
) (*httptest.Server, *memory.Store) {
	t.Helper()
	persistence := memory.New()
	bus := events.NewMemoryBus()
	t.Cleanup(func() {
		bus.Close()
		persistence.Close()
	})
	tokens := auth.NewTokenManager("test", strings.Repeat("s", 48), 15*time.Minute, 30*24*time.Hour, persistence)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(
		persistence, tokens, bus, ratelimit.NewMemory(), mediaService,
		verification.Development{Code: "000000"}, appleauth.Unavailable{},
		presence.NewMemory(), clustrmail.Unavailable{}, PasswordResetPolicy{}, nil, "", logger,
	).Router())
	t.Cleanup(server.Close)
	return server, persistence
}
