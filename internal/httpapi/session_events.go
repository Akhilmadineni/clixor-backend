package httpapi

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/google/uuid"
)

const (
	sessionRevokedEventType               = "session.revoked"
	realtimeDurableSessionRecheckInterval = 5 * time.Second
	sessionRevocationCacheRetention       = 30 * time.Second
	sessionRevocationCacheCapacity        = 65_536
	sessionRevocationPublishTimeout       = 2 * time.Second
)

type sessionRevocationPayload struct {
	SessionID *uuid.UUID `json:"session_id,omitempty"`
	All       bool       `json:"all,omitempty"`
}

type sessionRevocationKey struct {
	userID    uuid.UUID
	sessionID uuid.UUID
}

// realtimeSessionGuard serializes a connection's data writes with revocation.
// A write that already owns the guard is linearized before revocation; once
// Revoke returns, no later application event or typing publication can pass.
type realtimeSessionGuard struct {
	identity identity

	mu         sync.Mutex
	revoked    bool
	revokedCh  chan struct{}
	leaseValid func() bool
}

func newRealtimeSessionGuard(id identity) *realtimeSessionGuard {
	return &realtimeSessionGuard{identity: id, revokedCh: make(chan struct{})}
}

func (g *realtimeSessionGuard) Revoke() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked {
		return
	}
	g.revoked = true
	close(g.revokedCh)
}

func (g *realtimeSessionGuard) Revoked() <-chan struct{} {
	return g.revokedCh
}

func (g *realtimeSessionGuard) IsRevoked() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.revoked
}

func (g *realtimeSessionGuard) WhileActive(action func() error) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked || (g.leaseValid != nil && !g.leaseValid()) {
		if !g.revoked {
			g.revoked = true
			close(g.revokedCh)
		}
		return false, nil
	}
	return true, action()
}

func (g *realtimeSessionGuard) SetLeaseValidator(valid func() bool) {
	g.mu.Lock()
	g.leaseValid = valid
	g.mu.Unlock()
}

// sessionRevocationCache keeps only short-lived acceleration records plus the
// guards for currently open sockets. The database remains authoritative. When
// capacity is exhausted the cache enters a bounded fail-closed epoch and closes
// every registered socket instead of evicting a revocation record fail-open.
type sessionRevocationCache struct {
	mu sync.Mutex

	capacity        int
	retention       time.Duration
	now             func() time.Time
	records         map[sessionRevocationKey]time.Time
	guardsByUser    map[uuid.UUID]map[*realtimeSessionGuard]struct{}
	failClosedUntil time.Time
}

func newSessionRevocationCache(
	capacity int,
	retention time.Duration,
	now func() time.Time,
) *sessionRevocationCache {
	if capacity < 1 {
		capacity = 1
	}
	if retention <= 0 {
		retention = sessionRevocationCacheRetention
	}
	if now == nil {
		now = time.Now
	}
	return &sessionRevocationCache{
		capacity: capacity, retention: retention, now: now,
		records:      make(map[sessionRevocationKey]time.Time),
		guardsByUser: make(map[uuid.UUID]map[*realtimeSessionGuard]struct{}),
	}
}

func (c *sessionRevocationCache) Register(id identity) *realtimeSessionGuard {
	guard := newRealtimeSessionGuard(id)
	now := c.now().UTC()
	c.mu.Lock()
	c.pruneLocked(now)
	denied := c.failClosedUntil.After(now) ||
		c.recordActiveLocked(sessionRevocationKey{userID: id.UserID, sessionID: id.SessionID}, now)
	guards := c.guardsByUser[id.UserID]
	if guards == nil {
		guards = make(map[*realtimeSessionGuard]struct{})
		c.guardsByUser[id.UserID] = guards
	}
	guards[guard] = struct{}{}
	c.mu.Unlock()
	if denied {
		guard.Revoke()
	}
	return guard
}

func (c *sessionRevocationCache) Unregister(guard *realtimeSessionGuard) {
	if guard == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	guards := c.guardsByUser[guard.identity.UserID]
	delete(guards, guard)
	if len(guards) == 0 {
		delete(c.guardsByUser, guard.identity.UserID)
	}
}

func (c *sessionRevocationCache) Revoke(userID uuid.UUID, sessionID *uuid.UUID) {
	now := c.now().UTC()
	c.mu.Lock()
	c.pruneLocked(now)
	userGuards := c.guardsByUser[userID]
	keys := make([]sessionRevocationKey, 0, max(1, len(userGuards)))
	if sessionID != nil {
		keys = append(keys, sessionRevocationKey{userID: userID, sessionID: *sessionID})
	} else {
		// User-wide revocation applies to every session that exists now, not to a
		// future session created after a password reset. Reconnects using an old
		// session are still rejected by the authoritative initial database check.
		seenSessions := make(map[uuid.UUID]struct{}, len(userGuards))
		for guard := range userGuards {
			if _, duplicate := seenSessions[guard.identity.SessionID]; duplicate {
				continue
			}
			seenSessions[guard.identity.SessionID] = struct{}{}
			keys = append(keys, sessionRevocationKey{
				userID: userID, sessionID: guard.identity.SessionID,
			})
		}
	}
	expiresAt := now.Add(c.retention)
	failClosed := false
	for _, key := range keys {
		if _, alreadyRecorded := c.records[key]; !alreadyRecorded && len(c.records) >= c.capacity {
			failClosed = true
			c.failClosedUntil = expiresAt
			break
		}
		c.records[key] = expiresAt
	}
	guards := make([]*realtimeSessionGuard, 0, len(userGuards))
	if failClosed {
		for _, userGuards := range c.guardsByUser {
			for guard := range userGuards {
				guards = append(guards, guard)
			}
		}
	} else {
		for guard := range userGuards {
			if sessionID == nil || guard.identity.SessionID == *sessionID {
				guards = append(guards, guard)
			}
		}
	}
	c.mu.Unlock()
	for _, guard := range guards {
		guard.Revoke()
	}
}

func (c *sessionRevocationCache) recordActiveLocked(key sessionRevocationKey, now time.Time) bool {
	expiresAt, ok := c.records[key]
	return ok && expiresAt.After(now)
}

func (c *sessionRevocationCache) pruneLocked(now time.Time) {
	for key, expiresAt := range c.records {
		if !expiresAt.After(now) {
			delete(c.records, key)
		}
	}
	if !c.failClosedUntil.After(now) {
		c.failClosedUntil = time.Time{}
	}
}

func (s *Server) realtimeRevocations() *sessionRevocationCache {
	s.sessionRevocationsOnce.Do(func() {
		if s.sessionRevocations == nil {
			s.sessionRevocations = newSessionRevocationCache(
				sessionRevocationCacheCapacity, sessionRevocationCacheRetention, time.Now,
			)
		}
	})
	return s.sessionRevocations
}

func (s *Server) applySessionRevocation(userID uuid.UUID, encoded json.RawMessage) {
	var payload sessionRevocationPayload
	if err := json.Unmarshal(encoded, &payload); err != nil ||
		(payload.All && payload.SessionID != nil) ||
		(!payload.All && (payload.SessionID == nil || *payload.SessionID == uuid.Nil)) {
		// A malformed internal control event is safer to interpret as a user-wide
		// revocation than to expose data while waiting for the durable fallback.
		s.logger.Warn("session_revocation_signal_invalid", "user_id", userID)
		s.realtimeRevocations().Revoke(userID, nil)
		return
	}
	s.realtimeRevocations().Revoke(userID, payload.SessionID)
}

// publishSessionRevocation first fences local sockets synchronously, then sends
// the cross-process acceleration event. A short context detached from client
// cancellation prevents an aborted HTTP request from suppressing the signal.
func (s *Server) publishSessionRevocation(
	ctx context.Context,
	userID uuid.UUID,
	sessionID *uuid.UUID,
) (events.SessionFenceTicket, error) {
	s.realtimeRevocations().Revoke(userID, sessionID)
	publishContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionRevocationPublishTimeout)
	defer cancel()
	ticket, err := s.bus.FenceSessions(publishContext, userID, sessionID)
	if err != nil {
		s.logger.Warn("session_revocation_signal_failed", "user_id", userID, "error", err)
		if ticket != nil {
			_ = ticket.Release(context.Background())
		}
		return nil, err
	}
	return ticket, nil
}

func releaseSessionFence(ticket events.SessionFenceTicket) {
	if ticket == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionRevocationPublishTimeout)
	defer cancel()
	_ = ticket.Release(ctx)
}
