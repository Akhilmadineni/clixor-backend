package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestSessionRevocationCacheScopesAndExpires(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	cache := newSessionRevocationCache(8, time.Minute, func() time.Time { return now })
	userID := uuid.New()
	first := identity{UserID: userID, DeviceID: uuid.New(), SessionID: uuid.New()}
	second := identity{UserID: userID, DeviceID: uuid.New(), SessionID: uuid.New()}

	firstGuard := cache.Register(first)
	secondGuard := cache.Register(second)
	cache.Revoke(userID, &first.SessionID)
	if !firstGuard.IsRevoked() {
		t.Fatal("session revocation did not fence its open socket")
	}
	if secondGuard.IsRevoked() {
		t.Fatal("session revocation fenced another session for the same user")
	}
	if replacement := cache.Register(first); !replacement.IsRevoked() {
		t.Fatal("cached session revocation allowed a reconnect")
	}

	now = now.Add(time.Minute + time.Nanosecond)
	if replacement := cache.Register(first); replacement.IsRevoked() {
		t.Fatal("expired acceleration record remained active; durable storage is authoritative after expiry")
	}

	cache.Revoke(userID, nil)
	if !secondGuard.IsRevoked() {
		t.Fatal("user-wide revocation did not fence every open session")
	}
	if replacement := cache.Register(second); !replacement.IsRevoked() {
		t.Fatal("cached user-wide revocation allowed a reconnect")
	}
	newSession := identity{UserID: userID, DeviceID: uuid.New(), SessionID: uuid.New()}
	if replacement := cache.Register(newSession); replacement.IsRevoked() {
		t.Fatal("user-wide revocation incorrectly denied a newly issued session")
	}
}

func TestSessionRevocationCacheCapacityFailsClosedAndRemainsBounded(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	cache := newSessionRevocationCache(1, time.Minute, func() time.Time { return now })
	first := identity{UserID: uuid.New(), DeviceID: uuid.New(), SessionID: uuid.New()}
	second := identity{UserID: uuid.New(), DeviceID: uuid.New(), SessionID: uuid.New()}
	firstGuard := cache.Register(first)
	secondGuard := cache.Register(second)

	cache.Revoke(first.UserID, &first.SessionID)
	if !firstGuard.IsRevoked() || secondGuard.IsRevoked() {
		t.Fatal("first cache record was not scoped to its session")
	}
	cache.Revoke(second.UserID, &second.SessionID)
	if !secondGuard.IsRevoked() {
		t.Fatal("capacity exhaustion did not fail closed for open sockets")
	}
	if len(cache.records) > cache.capacity {
		t.Fatalf("revocation cache grew past capacity: records=%d capacity=%d", len(cache.records), cache.capacity)
	}
	if guard := cache.Register(identity{UserID: uuid.New(), DeviceID: uuid.New(), SessionID: uuid.New()}); !guard.IsRevoked() {
		t.Fatal("capacity fail-closed epoch admitted a new socket")
	}

	now = now.Add(time.Minute + time.Nanosecond)
	if guard := cache.Register(identity{UserID: uuid.New(), DeviceID: uuid.New(), SessionID: uuid.New()}); guard.IsRevoked() {
		t.Fatal("bounded fail-closed epoch did not expire")
	}
	if len(cache.records) != 0 {
		t.Fatalf("expired records were not pruned: %d", len(cache.records))
	}
}

func TestRealtimeSessionGuardLinearizesRevocationBeforeLaterActions(t *testing.T) {
	guard := newRealtimeSessionGuard(identity{
		UserID: uuid.New(), DeviceID: uuid.New(), SessionID: uuid.New(),
	})
	actionStarted := make(chan struct{})
	releaseAction := make(chan struct{})
	actionDone := make(chan struct{})
	go func() {
		defer close(actionDone)
		_, _ = guard.WhileActive(func() error {
			close(actionStarted)
			<-releaseAction
			return nil
		})
	}()
	<-actionStarted

	revoked := make(chan struct{})
	go func() {
		guard.Revoke()
		close(revoked)
	}()
	select {
	case <-revoked:
		t.Fatal("revocation returned while a guarded action was still in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseAction)
	<-actionDone
	<-revoked

	var laterActionRan atomic.Bool
	active, err := guard.WhileActive(func() error {
		laterActionRan.Store(true)
		return nil
	})
	if err != nil || active || laterActionRan.Load() {
		t.Fatalf("post-revocation action passed the fence: active=%t ran=%t err=%v", active, laterActionRan.Load(), err)
	}
}

func TestMalformedRevocationSignalFailsClosedForUser(t *testing.T) {
	for name, payload := range map[string][]byte{
		"invalid JSON":       []byte(`{"all":`),
		"ambiguous scope":    []byte(`{"all":true,"session_id":"00000000-0000-0000-0000-000000000001"}`),
		"nil session UUID":   []byte(`{"session_id":"00000000-0000-0000-0000-000000000000"}`),
		"missing scope":      []byte(`{}`),
		"wrong session type": []byte(`{"session_id":7}`),
	} {
		t.Run(name, func(t *testing.T) {
			cache := newSessionRevocationCache(8, time.Minute, time.Now)
			server := &Server{
				logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
				sessionRevocations: cache,
			}
			userID := uuid.New()
			first := cache.Register(identity{UserID: userID, DeviceID: uuid.New(), SessionID: uuid.New()})
			second := cache.Register(identity{UserID: userID, DeviceID: uuid.New(), SessionID: uuid.New()})
			server.applySessionRevocation(userID, payload)
			if !first.IsRevoked() || !second.IsRevoked() {
				t.Fatal("malformed internal revocation signal did not fail closed")
			}
		})
	}
}

type failingSessionStore struct {
	store.Store
}

func (failingSessionStore) SessionActive(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (bool, error) {
	return false, errors.New("durable session store unavailable")
}

func TestRealtimeDurableSessionFailureFailsClosed(t *testing.T) {
	cache := newSessionRevocationCache(8, time.Minute, time.Now)
	server := &Server{
		store:              failingSessionStore{},
		logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessionRevocations: cache,
	}
	id := identity{UserID: uuid.New(), DeviceID: uuid.New(), SessionID: uuid.New()}
	guard := cache.Register(id)
	if server.realtimeSessionActive(context.Background(), id, guard) {
		t.Fatal("durable session failure was treated as active")
	}
	if !guard.IsRevoked() {
		t.Fatal("durable session failure did not fence the socket")
	}
}

type failingPublishBus struct {
	called          atomic.Bool
	contextCanceled atomic.Bool
}

func (bus *failingPublishBus) Ping(context.Context) error { return nil }

func (bus *failingPublishBus) Publish(
	ctx context.Context,
	_ []uuid.UUID,
	_ domain.RealtimeEvent,
) error {
	bus.called.Store(true)
	bus.contextCanceled.Store(ctx.Err() != nil)
	return errors.New("revocation transport unavailable")
}

func (*failingPublishBus) Subscribe(context.Context, uuid.UUID) (events.Subscription, error) {
	return nil, errors.New("not implemented")
}

func (*failingPublishBus) RegisterSessionOwner(context.Context, uuid.UUID, uuid.UUID, events.SessionFence) (events.SessionOwner, error) {
	return nil, errors.New("not implemented")
}

func (bus *failingPublishBus) FenceSessions(ctx context.Context, _ uuid.UUID, _ *uuid.UUID) (events.SessionFenceTicket, error) {
	bus.called.Store(true)
	bus.contextCanceled.Store(ctx.Err() != nil)
	return nil, errors.New("revocation transport unavailable")
}

func (*failingPublishBus) Close() {}

func TestRevocationPublishFailureStillFencesLocalSocket(t *testing.T) {
	cache := newSessionRevocationCache(8, time.Minute, time.Now)
	bus := &failingPublishBus{}
	server := &Server{
		bus:                bus,
		logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessionRevocations: cache,
	}
	id := identity{UserID: uuid.New(), DeviceID: uuid.New(), SessionID: uuid.New()}
	guard := cache.Register(id)
	requestContext, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = server.publishSessionRevocation(requestContext, id.UserID, &id.SessionID)
	if !guard.IsRevoked() {
		t.Fatal("local socket remained active after revocation transport failed")
	}
	if !bus.called.Load() {
		t.Fatal("cross-process revocation was not attempted")
	}
	if bus.contextCanceled.Load() {
		t.Fatal("canceled request context suppressed the detached revocation attempt")
	}
}

func TestRealtimeGuardFailsClosedWhenOwnerLeaseExpires(t *testing.T) {
	guard := newRealtimeSessionGuard(identity{UserID: uuid.New(), SessionID: uuid.New()})
	valid := atomic.Bool{}
	valid.Store(true)
	guard.SetLeaseValidator(valid.Load)
	writes := 0
	if wrote, err := guard.WhileActive(func() error { writes++; return nil }); err != nil || !wrote {
		t.Fatal("valid lease blocked write")
	}
	valid.Store(false)
	if wrote, err := guard.WhileActive(func() error { writes++; return nil }); err != nil || wrote {
		t.Fatal("expired lease allowed write")
	}
	if writes != 1 || !guard.IsRevoked() {
		t.Fatalf("writes=%d revoked=%t", writes, guard.IsRevoked())
	}
}

type revocationBarrierStore struct {
	store.Store
	revoked atomic.Bool
}

func (s *revocationBarrierStore) RevokeSession(context.Context, uuid.UUID, uuid.UUID) error {
	s.revoked.Store(true)
	return nil
}

func TestLogoutReturnsUnavailableAndDoesNotMutateWhenFenceFails(t *testing.T) {
	persistence := &revocationBarrierStore{}
	server := &Server{
		store: persistence, bus: &failingPublishBus{},
		logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessionRevocations: newSessionRevocationCache(8, time.Minute, time.Now),
	}
	id := identity{UserID: uuid.New(), DeviceID: uuid.New(), SessionID: uuid.New()}
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	request = request.WithContext(withIdentity(request.Context(), id))
	response := httptest.NewRecorder()
	server.logout(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if persistence.revoked.Load() {
		t.Fatal("session mutation ran despite failed barrier")
	}
}

func TestTypingFloodIsRateLimitedBeforeDurableCheck(t *testing.T) {
	started := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	var last time.Time
	accepted := 0
	for offset := time.Duration(0); offset < time.Second; offset += 10 * time.Millisecond {
		if typingFrameDue(started.Add(offset), &last) {
			accepted++
		}
	}
	if accepted != 4 {
		t.Fatalf("typing flood passed %d durable-check gates in one second, want 4", accepted)
	}
}
