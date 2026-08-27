package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/appleauth"
	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/Akhilmadineni/clixor-backend/internal/presence"
	"github.com/Akhilmadineni/clixor-backend/internal/ratelimit"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/Akhilmadineni/clixor-backend/internal/verification"
	"github.com/google/uuid"
)

type resetMailRecorder struct {
	mu          sync.Mutex
	resetTo     string
	resetCode   string
	changedTo   string
	resetCount  int
	changeCount int
	resetErr    error
	resetCodes  []string
}

func (r *resetMailRecorder) SendPasswordReset(_ context.Context, to, code string, _ time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resetTo = to
	r.resetCode = code
	r.resetCount++
	r.resetCodes = append(r.resetCodes, code)
	return r.resetErr
}

func (r *resetMailRecorder) SendPasswordChanged(_ context.Context, to string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changedTo = to
	r.changeCount++
	return nil
}

func (r *resetMailRecorder) Ping(context.Context) error { return nil }

func TestPasswordResetRequiresEmailedCodeAndRevokesSessions(t *testing.T) {
	server, recorder := newPasswordResetHTTPServer(t)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	var registered authResponse
	client.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": "reset@example.com", "password": "original-password-123",
		"display_name": "Reset User", "device_name": "Test iPhone", "platform": "ios",
	}, http.StatusCreated, &registered)

	var started passwordResetStartResponse
	client.do(t, http.MethodPost, "/v1/auth/password/reset/start", map[string]any{
		"email": "reset@example.com",
	}, http.StatusAccepted, &started)
	if started.ChallengeID == "" || started.ExpiresIn != 600 {
		t.Fatalf("unexpected reset response: %+v", started)
	}
	recorder.mu.Lock()
	code := recorder.resetCode
	if recorder.resetTo != "reset@example.com" || recorder.resetCount != 1 || len(code) != 8 {
		t.Fatalf("unexpected queued reset mail: %+v", recorder)
	}
	recorder.mu.Unlock()
	wrongCode := "00000000"
	if code == wrongCode {
		wrongCode = "99999999"
	}

	client.do(t, http.MethodPost, "/v1/auth/password/reset/confirm", map[string]any{
		"challenge_id": started.ChallengeID, "code": wrongCode,
		"new_password": "replacement-password-456",
	}, http.StatusBadRequest, nil)
	client.do(t, http.MethodPost, "/v1/auth/password/reset/confirm", map[string]any{
		"challenge_id": started.ChallengeID, "code": code,
		"new_password": "replacement-password-456",
	}, http.StatusNoContent, nil)

	client.token = registered.Tokens.AccessToken
	client.do(t, http.MethodGet, "/v1/me", nil, http.StatusUnauthorized, nil)
	client.token = ""
	client.do(t, http.MethodPost, "/v1/auth/login", map[string]any{
		"email": "reset@example.com", "password": "original-password-123",
		"device_name": "Test iPhone", "platform": "ios",
	}, http.StatusUnauthorized, nil)
	client.do(t, http.MethodPost, "/v1/auth/login", map[string]any{
		"email": "reset@example.com", "password": "replacement-password-456",
		"device_name": "Test iPhone", "platform": "ios",
	}, http.StatusOK, nil)
	client.do(t, http.MethodPost, "/v1/auth/password/reset/confirm", map[string]any{
		"challenge_id": started.ChallengeID, "code": code,
		"new_password": "another-password-789",
	}, http.StatusBadRequest, nil)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.changedTo != "reset@example.com" || recorder.changeCount != 1 {
		t.Fatalf("password change confirmation was not queued: %+v", recorder)
	}
}

func TestPasswordResetStartDoesNotEnumerateAccounts(t *testing.T) {
	server, recorder := newPasswordResetHTTPServer(t)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	var response passwordResetStartResponse
	client.do(t, http.MethodPost, "/v1/auth/password/reset/start", map[string]any{
		"email": "missing@example.com",
	}, http.StatusAccepted, &response)
	if response.ChallengeID == "" || !strings.Contains(response.Message, "If this email") {
		t.Fatalf("unexpected generic response: %+v", response)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.resetCount != 0 {
		t.Fatal("unknown account generated outbound mail")
	}
}

func TestConcurrentPasswordResetStartsReturnGenericResponsesAndOneUsableChallenge(t *testing.T) {
	server, recorder, persistence := newPasswordResetHTTPServerWithStore(t)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	client.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": "reset-concurrent@example.com", "password": "original-password-123",
		"display_name": "Concurrent Reset", "device_name": "Test iPhone", "platform": "ios",
	}, http.StatusCreated, nil)

	type startResult struct {
		status   int
		response passwordResetStartResponse
		err      error
	}
	start := make(chan struct{})
	results := make(chan startResult, 2)
	for range 2 {
		go func() {
			<-start
			request, err := http.NewRequestWithContext(
				context.Background(), http.MethodPost,
				server.URL+"/v1/auth/password/reset/start",
				strings.NewReader(`{"email":"reset-concurrent@example.com"}`),
			)
			if err != nil {
				results <- startResult{err: err}
				return
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				results <- startResult{err: err}
				return
			}
			defer response.Body.Close()
			var decoded passwordResetStartResponse
			err = json.NewDecoder(response.Body).Decode(&decoded)
			results <- startResult{status: response.StatusCode, response: decoded, err: err}
		}()
	}
	close(start)
	responses := make([]passwordResetStartResponse, 0, 2)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.status != http.StatusAccepted || result.response.ChallengeID == "" ||
			!strings.Contains(result.response.Message, "If this email") {
			t.Fatalf("concurrent reset returned a non-generic response: %+v", result)
		}
		responses = append(responses, result.response)
	}
	recorder.mu.Lock()
	codes := append([]string(nil), recorder.resetCodes...)
	recorder.mu.Unlock()
	if len(codes) != 2 {
		t.Fatalf("concurrent reset mail count=%d, want 2", len(codes))
	}

	succeeded := 0
	for _, response := range responses {
		challengeID, err := uuid.Parse(response.ChallengeID)
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range codes {
			_, err := persistence.ConsumePasswordResetChallenge(
				context.Background(), challengeID,
				passwordResetCodeHash(strings.Repeat("r", 48), challengeID, code),
				"replacement-hash", 5,
			)
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, domain.ErrUnauthenticated):
			default:
				t.Fatalf("consume concurrent challenge returned %v", err)
			}
		}
	}
	if succeeded != 1 {
		t.Fatalf("usable concurrent reset challenges=%d, want exactly 1", succeeded)
	}
}

type resetCreateNotFoundStore struct {
	store.Store
}

func (resetCreateNotFoundStore) CreatePasswordResetChallenge(
	context.Context,
	domain.PasswordResetChallenge,
) error {
	return domain.ErrNotFound
}

func TestPasswordResetDeleteRaceKeepsGenericStartResponse(t *testing.T) {
	persistence := memory.New()
	t.Cleanup(persistence.Close)
	server, recorder := newPasswordResetHTTPServerForStore(
		t, resetCreateNotFoundStore{Store: persistence},
	)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	client.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": "reset-delete-race@example.com", "password": "original-password-123",
		"display_name": "Delete Race", "device_name": "Test iPhone", "platform": "ios",
	}, http.StatusCreated, nil)
	var response passwordResetStartResponse
	client.do(t, http.MethodPost, "/v1/auth/password/reset/start", map[string]any{
		"email": "reset-delete-race@example.com",
	}, http.StatusAccepted, &response)
	if response.ChallengeID == "" || !strings.Contains(response.Message, "If this email") {
		t.Fatalf("delete race did not preserve the generic response: %+v", response)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.resetCount != 0 {
		t.Fatal("delete-race reset queued mail without a persisted challenge")
	}
}

func TestPasswordResetMailFailureCancelsChallenge(t *testing.T) {
	server, recorder := newPasswordResetHTTPServer(t)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	client.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": "mail-failure@example.com", "password": "original-password-123",
		"display_name": "Mail Failure", "device_name": "Test iPhone", "platform": "ios",
	}, http.StatusCreated, nil)

	recorder.mu.Lock()
	recorder.resetErr = errors.New("mail queue unavailable")
	recorder.mu.Unlock()
	var started passwordResetStartResponse
	client.do(t, http.MethodPost, "/v1/auth/password/reset/start", map[string]any{
		"email": "mail-failure@example.com",
	}, http.StatusAccepted, &started)
	recorder.mu.Lock()
	code := recorder.resetCode
	recorder.mu.Unlock()
	if code == "" {
		t.Fatal("mail failure test did not attempt to enqueue a reset code")
	}

	client.do(t, http.MethodPost, "/v1/auth/password/reset/confirm", map[string]any{
		"challenge_id": started.ChallengeID, "code": code,
		"new_password": "replacement-password-456",
	}, http.StatusBadRequest, nil)
}

func TestPasswordResetRateLimitDoesNotReplaceUsableChallenge(t *testing.T) {
	server, recorder := newPasswordResetHTTPServer(t)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	client.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": "reset-limit@example.com", "password": "original-password-123",
		"display_name": "Reset Limit", "device_name": "Test iPhone", "platform": "ios",
	}, http.StatusCreated, nil)

	var latest passwordResetStartResponse
	for range 3 {
		client.do(t, http.MethodPost, "/v1/auth/password/reset/start", map[string]any{
			"email": "reset-limit@example.com",
		}, http.StatusAccepted, &latest)
	}
	recorder.mu.Lock()
	latestCode := recorder.resetCode
	resetCount := recorder.resetCount
	recorder.mu.Unlock()
	if latest.ChallengeID == "" || latestCode == "" || resetCount != 3 {
		t.Fatalf("latest reset was not queued: response=%+v mail_count=%d", latest, resetCount)
	}

	client.do(t, http.MethodPost, "/v1/auth/password/reset/start", map[string]any{
		"email": "reset-limit@example.com",
	}, http.StatusTooManyRequests, nil)
	recorder.mu.Lock()
	if recorder.resetCount != resetCount {
		t.Fatalf("rate-limited reset unexpectedly queued mail: count=%d", recorder.resetCount)
	}
	recorder.mu.Unlock()

	client.do(t, http.MethodPost, "/v1/auth/password/reset/confirm", map[string]any{
		"challenge_id": latest.ChallengeID, "code": latestCode,
		"new_password": "replacement-password-456",
	}, http.StatusNoContent, nil)
}

func newPasswordResetHTTPServer(t *testing.T) (*httptest.Server, *resetMailRecorder) {
	t.Helper()
	server, recorder, _ := newPasswordResetHTTPServerWithStore(t)
	return server, recorder
}

func newPasswordResetHTTPServerWithStore(
	t *testing.T,
) (*httptest.Server, *resetMailRecorder, *memory.Store) {
	t.Helper()
	persistence := memory.New()
	t.Cleanup(persistence.Close)
	server, recorder := newPasswordResetHTTPServerForStore(t, persistence)
	return server, recorder, persistence
}

func newPasswordResetHTTPServerForStore(
	t *testing.T,
	persistence store.Store,
) (*httptest.Server, *resetMailRecorder) {
	t.Helper()
	bus := events.NewMemoryBus()
	limiter := ratelimit.NewMemory()
	presenceService := presence.NewMemory()
	recorder := &resetMailRecorder{}
	t.Cleanup(func() {
		presenceService.Close()
		limiter.Close()
		bus.Close()
	})
	tokens := auth.NewTokenManager(
		"test", strings.Repeat("s", 48), 15*time.Minute, 30*24*time.Hour, persistence,
	)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(
		persistence, tokens, bus, limiter, media.Unavailable{}, verification.Unavailable{},
		appleauth.Unavailable{}, presenceService, recorder, PasswordResetPolicy{
			Enabled: true, HMACSecret: strings.Repeat("r", 48), CodeLength: 8,
			TTL: 10 * time.Minute, MaxAttempts: 5,
		}, nil, "", logger,
	).Router())
	t.Cleanup(server.Close)
	return server, recorder
}
