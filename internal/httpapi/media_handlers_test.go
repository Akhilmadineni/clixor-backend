package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/appleauth"
	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	clustrmail "github.com/Akhilmadineni/clixor-backend/internal/mail"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/Akhilmadineni/clixor-backend/internal/presence"
	"github.com/Akhilmadineni/clixor-backend/internal/ratelimit"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/Akhilmadineni/clixor-backend/internal/verification"
	"github.com/google/uuid"
)

type testMediaService struct {
	verifyErr      error
	verifiedKey    string
	verifiedSize   int64
	verifiedSHA256 string
	verifiedType   string
	uploadHeaders  map[string]string
}

func (m *testMediaService) PrepareUpload(_ context.Context, _ string, contentType string, byteSize int64, _ string, _ time.Duration) (media.UploadInstructions, error) {
	uploadURL, err := url.Parse("https://media.example/upload")
	if err != nil {
		return media.UploadInstructions{}, err
	}
	headers := m.uploadHeaders
	if headers == nil {
		headers = map[string]string{
			"Content-Type": contentType, "Content-Length": strconv.FormatInt(byteSize, 10),
			"X-Amz-Checksum-Sha256": "test-checksum",
		}
	}
	return media.UploadInstructions{
		Method:  http.MethodPut,
		URL:     uploadURL,
		Headers: headers,
	}, nil
}

func (*testMediaService) DownloadURL(_ context.Context, _ string, _ time.Duration) (*url.URL, error) {
	return url.Parse("https://media.example/download")
}

func (m *testMediaService) Verify(_ context.Context, key string, size int64, sha256, contentType string) error {
	m.verifiedKey, m.verifiedSize, m.verifiedSHA256, m.verifiedType = key, size, sha256, contentType
	return m.verifyErr
}

func (*testMediaService) Delete(context.Context, string) error { return nil }
func (*testMediaService) Close()                               {}

func TestMediaUploadReturnsProviderNeutralInstructions(t *testing.T) {
	t.Parallel()
	mediaService := &testMediaService{uploadHeaders: map[string]string{
		"Content-Type": "image/jpeg", "Content-Length": "3",
		"opc-checksum-algorithm": "SHA256", "opc-content-sha256": "provider-digest",
	}}
	server := newTestHTTPServerWithMedia(t, mediaService)
	user := registerTestUser(t, server.URL, "provider-upload@example.com")
	var upload struct {
		Upload struct {
			Method  string            `json:"method"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		} `json:"upload"`
	}
	user.client.do(t, http.MethodPost, "/v1/me/avatar", map[string]any{
		"byte_size":         3,
		"ciphertext_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"content_type":      "image/jpeg",
	}, http.StatusCreated, &upload)
	if upload.Upload.Method != http.MethodPut || upload.Upload.URL != "https://media.example/upload" ||
		upload.Upload.Headers["opc-checksum-algorithm"] != "SHA256" ||
		upload.Upload.Headers["opc-content-sha256"] != "provider-digest" ||
		upload.Upload.Headers["X-Amz-Checksum-Sha256"] != "" {
		t.Fatalf("provider instructions were altered: %+v", upload.Upload)
	}
}

func TestConversationMediaPreservesProduction05bOneGiBMaximum(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServerWithMedia(t, &testMediaService{})
	alice := registerTestUser(t, server.URL, "conversation-media-one-gib@example.com")
	var conversation domain.Conversation
	alice.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "One GiB media contract",
	}, http.StatusCreated, &conversation)
	path := "/v1/conversations/" + conversation.ID.String() + "/media"
	request := map[string]any{
		"byte_size":         int64(1 << 30),
		"ciphertext_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"content_type":      "application/octet-stream",
	}
	alice.client.do(t, http.MethodPost, path, request, http.StatusCreated, nil)
	request["byte_size"] = int64(1<<30) + 1
	alice.client.do(t, http.MethodPost, path, request, http.StatusUnprocessableEntity, nil)
}

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
	if upload.Upload.Headers["Content-Length"] != "3" || upload.Upload.Headers["X-Amz-Checksum-Sha256"] == "" {
		t.Fatalf("upload declaration was not bound into required headers: %+v", upload.Upload.Headers)
	}
	bob.client.do(t, http.MethodGet, "/v1/media/"+upload.Media.ID.String()+"/download", nil, http.StatusForbidden, nil)

	var ready domain.MediaObject
	alice.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete", nil, http.StatusOK, &ready)
	alice.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete", nil, http.StatusOK, nil)
	if mediaService.verifiedSize != 3 || mediaService.verifiedSHA256 != digest ||
		mediaService.verifiedType != "image/jpeg" || mediaService.verifiedKey == "" {
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
	mediaService := &testMediaService{verifyErr: media.ErrVerificationMismatch}
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
	alice.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete", nil, http.StatusNotFound, nil)
	var me domain.User
	alice.client.do(t, http.MethodGet, "/v1/me", nil, http.StatusOK, &me)
	if me.AvatarURL != "" {
		t.Fatalf("failed upload became avatar: %+v", me)
	}
}

func TestTransientMediaVerificationFailureRetainsReservationForRetry(t *testing.T) {
	t.Parallel()
	mediaService := &testMediaService{verifyErr: media.ErrUnavailable}
	server := newTestHTTPServerWithMedia(t, mediaService)
	alice := registerTestUser(t, server.URL, "avatar-transient@example.com")
	const digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	var upload struct {
		Media domain.MediaObject `json:"media"`
	}
	alice.client.do(t, http.MethodPost, "/v1/me/avatar", map[string]any{
		"byte_size": 3, "ciphertext_sha256": digest,
	}, http.StatusCreated, &upload)
	alice.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete", nil,
		http.StatusServiceUnavailable, nil)
	mediaService.verifyErr = nil
	var ready domain.MediaObject
	alice.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete", nil,
		http.StatusOK, &ready)
	if ready.Status != "ready" {
		t.Fatalf("retry did not publish retained reservation: %+v", ready)
	}
}

func TestConcurrentCompletionRunsOneVerificationAndReadyIsIdempotent(t *testing.T) {
	mediaService := &blockingVerifyMedia{
		entered: make(chan struct{}, 1), release: make(chan struct{}),
	}
	policy := DefaultMediaPolicy()
	policy.VerificationConcurrency = 2
	server := newTestHTTPServerWithMediaPolicy(t, mediaService, policy)
	alice := registerTestUser(t, server.URL, "avatar-concurrent-complete@example.com")
	var upload struct {
		Media domain.MediaObject `json:"media"`
	}
	alice.client.do(t, http.MethodPost, "/v1/me/avatar", map[string]any{
		"byte_size":         3,
		"ciphertext_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"content_type":      "image/jpeg",
	}, http.StatusCreated, &upload)
	complete := func() (*http.Response, error) {
		request, err := http.NewRequest(
			http.MethodPost, server.URL+"/v1/media/"+upload.Media.ID.String()+"/complete", nil,
		)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+alice.tokens.AccessToken)
		return http.DefaultClient.Do(request)
	}
	firstResponse := make(chan *http.Response, 1)
	firstError := make(chan error, 1)
	go func() {
		response, err := complete()
		firstResponse <- response
		firstError <- err
	}()
	select {
	case <-mediaService.entered:
	case <-time.After(time.Second):
		t.Fatal("first verification did not start")
	}
	second, err := complete()
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusConflict || second.Header.Get("Retry-After") != "2" {
		t.Fatalf("concurrent completion status=%d retry-after=%q", second.StatusCode, second.Header.Get("Retry-After"))
	}
	close(mediaService.release)
	if err := <-firstError; err != nil {
		t.Fatal(err)
	}
	first := <-firstResponse
	io.Copy(io.Discard, first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("winning completion status=%d", first.StatusCode)
	}
	third, err := complete()
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, third.Body)
	third.Body.Close()
	if third.StatusCode != http.StatusOK || mediaService.calls.Load() != 1 {
		t.Fatalf("idempotent completion status=%d verification calls=%d", third.StatusCode, mediaService.calls.Load())
	}
}

func TestPendingMediaQuotaIsEnforcedBeforePresigning(t *testing.T) {
	t.Parallel()
	policy := DefaultMediaPolicy()
	policy.ReservationLimits.MaxPendingCountPerUser = 1
	server := newTestHTTPServerWithMediaPolicy(t, &testMediaService{}, policy)
	alice := registerTestUser(t, server.URL, "avatar-quota@example.com")
	request := map[string]any{
		"byte_size": 3, "ciphertext_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"content_type": "image/jpeg",
	}
	alice.client.do(t, http.MethodPost, "/v1/me/avatar", request, http.StatusCreated, nil)
	alice.client.do(t, http.MethodPost, "/v1/me/avatar", request, http.StatusTooManyRequests, nil)
}

func TestStoredMediaQuotaIsEnforcedAfterCompletion(t *testing.T) {
	t.Parallel()
	policy := DefaultMediaPolicy()
	policy.ReservationLimits.MaxPendingCountPerUser = 1
	policy.ReservationLimits.MaxPendingBytesPerUser = 3
	policy.ReservationLimits.MaxStoredCountPerUser = 1
	policy.ReservationLimits.MaxStoredBytesPerUser = 3
	server := newTestHTTPServerWithMediaPolicy(t, &testMediaService{}, policy)
	alice := registerTestUser(t, server.URL, "avatar-stored-quota@example.com")
	request := map[string]any{
		"byte_size": 3, "ciphertext_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"content_type": "image/jpeg",
	}
	var upload struct {
		Media domain.MediaObject `json:"media"`
	}
	alice.client.do(t, http.MethodPost, "/v1/me/avatar", request, http.StatusCreated, &upload)
	alice.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete", nil, http.StatusOK, nil)
	alice.client.do(t, http.MethodPost, "/v1/me/avatar", request, http.StatusTooManyRequests, nil)
}

func TestConversationMediaHasDedicatedIdentityRateLimit(t *testing.T) {
	t.Parallel()
	policy := DefaultMediaPolicy()
	policy.ReservationLimits.MaxPendingCountPerUser = 100
	policy.ReservationLimits.MaxPendingBytesPerUser = 1 << 20
	policy.ReservationLimits.MaxPendingCountConversation = 100
	policy.ReservationLimits.MaxPendingBytesConversation = 1 << 20
	server := newTestHTTPServerWithMediaPolicy(t, &testMediaService{}, policy)
	alice := registerTestUser(t, server.URL, "conversation-media-rate@example.com")
	var conversation domain.Conversation
	alice.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "Media rate limit",
	}, http.StatusCreated, &conversation)
	request := map[string]any{
		"byte_size":         3,
		"ciphertext_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"content_type":      "application/octet-stream",
	}
	path := "/v1/conversations/" + conversation.ID.String() + "/media"
	for index := 0; index < 60; index++ {
		alice.client.do(t, http.MethodPost, path, request, http.StatusCreated, nil)
	}
	alice.client.do(t, http.MethodPost, path, request, http.StatusTooManyRequests, nil)
}

func TestMediaUserRateLimitCannotBeMultipliedByDevices(t *testing.T) {
	t.Parallel()
	server := &Server{
		limiter: ratelimit.NewMemory(),
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := server.rateLimitUser("conversation-media-upload", 1, time.Hour)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) }),
	)
	userID := uuid.New()
	first := httptest.NewRequest(http.MethodPost, "/v1/conversations/id/media", nil)
	first = first.WithContext(withIdentity(first.Context(), identity{UserID: userID, DeviceID: uuid.New()}))
	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusCreated {
		t.Fatalf("first device status=%d", firstResponse.Code)
	}
	second := httptest.NewRequest(http.MethodPost, "/v1/conversations/id/media", nil)
	second = second.WithContext(withIdentity(second.Context(), identity{UserID: userID, DeviceID: uuid.New()}))
	secondResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondResponse, second)
	if secondResponse.Code != http.StatusTooManyRequests || secondResponse.Header().Get("Retry-After") != "3600" {
		t.Fatalf("second device status=%d retry-after=%q", secondResponse.Code, secondResponse.Header().Get("Retry-After"))
	}
}

func TestMediaCompletionRateLimitIsUserScopedAcrossDevices(t *testing.T) {
	server := &Server{
		limiter: ratelimit.NewMemory(),
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := server.rateLimitUser("media-complete", 1, time.Hour)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)
	userID := uuid.New()
	for index, expected := range []int{http.StatusOK, http.StatusTooManyRequests} {
		request := httptest.NewRequest(http.MethodPost, "/v1/media/id/complete", nil)
		request = request.WithContext(withIdentity(request.Context(), identity{
			UserID: userID, DeviceID: uuid.New(),
		}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != expected {
			t.Fatalf("request %d status=%d want=%d", index+1, response.Code, expected)
		}
	}
}

func newTestHTTPServerWithMedia(t *testing.T, mediaService media.Service) *httptest.Server {
	return newTestHTTPServerWithMediaPolicy(t, mediaService, DefaultMediaPolicy())
}

func newTestHTTPServerWithMediaPolicy(
	t *testing.T,
	mediaService media.Service,
	policy MediaPolicy,
) *httptest.Server {
	t.Helper()
	server, _ := newTestHTTPServerWithMediaStore(t, mediaService, policy)
	return server
}

func newTestHTTPServerWithMediaStore(
	t *testing.T,
	mediaService media.Service,
	policy MediaPolicy,
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
		presence.NewMemory(), clustrmail.Unavailable{}, PasswordResetPolicy{}, policy, nil, "", logger,
	).Router())
	t.Cleanup(server.Close)
	return server, persistence
}

type blockingVerifyMedia struct {
	testMediaService
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (m *blockingVerifyMedia) Verify(
	ctx context.Context,
	_ string,
	_ int64,
	_, _ string,
) error {
	m.calls.Add(1)
	select {
	case m.entered <- struct{}{}:
	default:
	}
	select {
	case <-m.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
