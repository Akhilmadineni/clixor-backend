package events

import (
	"context"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

type MemoryBus struct {
	mu          sync.RWMutex
	subscribers map[uuid.UUID]map[*memorySubscription]struct{}
	owners      map[uuid.UUID]map[*memorySessionOwner]struct{}
	fences      map[uuid.UUID]map[uuid.UUID]memoryFence
}

type memoryFence struct {
	sessionID  *uuid.UUID
	validUntil time.Time
}

type memoryFenceTicket struct {
	bus              *MemoryBus
	userID, ticketID uuid.UUID
	once             sync.Once
}

type memorySessionOwner struct {
	bus    *MemoryBus
	userID uuid.UUID
	fence  SessionFence
	once   sync.Once
}

func (o *memorySessionOwner) Valid() bool {
	o.bus.mu.RLock()
	defer o.bus.mu.RUnlock()
	_, present := o.bus.owners[o.userID][o]
	return present
}

type memorySubscription struct {
	bus    *MemoryBus
	userID uuid.UUID
	ch     chan domain.RealtimeEvent
	once   sync.Once
}

func NewMemoryBus() *MemoryBus {
	return &MemoryBus{
		subscribers: make(map[uuid.UUID]map[*memorySubscription]struct{}),
		owners:      make(map[uuid.UUID]map[*memorySessionOwner]struct{}),
		fences:      make(map[uuid.UUID]map[uuid.UUID]memoryFence),
	}
}

func (*MemoryBus) Ping(context.Context) error { return nil }

func (b *MemoryBus) Publish(_ context.Context, users []uuid.UUID, event domain.RealtimeEvent) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, userID := range users {
		for subscription := range b.subscribers[userID] {
			select {
			case subscription.ch <- event:
			default:
				// A slow client will replay from its last acknowledged sequence after reconnect.
			}
		}
	}
	return nil
}

func (b *MemoryBus) Subscribe(_ context.Context, userID uuid.UUID) (Subscription, error) {
	subscription := &memorySubscription{
		bus: b, userID: userID, ch: make(chan domain.RealtimeEvent, 256),
	}
	b.mu.Lock()
	if b.subscribers[userID] == nil {
		b.subscribers[userID] = make(map[*memorySubscription]struct{})
	}
	b.subscribers[userID][subscription] = struct{}{}
	b.mu.Unlock()
	return subscription, nil
}

func (b *MemoryBus) RegisterSessionOwner(_ context.Context, userID, sessionID uuid.UUID, fence SessionFence) (SessionOwner, error) {
	owner := &memorySessionOwner{bus: b, userID: userID, fence: fence}
	b.mu.Lock()
	if b.owners[userID] == nil {
		b.owners[userID] = make(map[*memorySessionOwner]struct{})
	}
	b.owners[userID][owner] = struct{}{}
	barriers := make([]memoryFence, 0, len(b.fences[userID]))
	for ticketID, barrier := range b.fences[userID] {
		if !barrier.validUntil.After(time.Now()) {
			delete(b.fences[userID], ticketID)
			continue
		}
		barriers = append(barriers, barrier)
	}
	b.mu.Unlock()
	for _, barrier := range barriers {
		if barrier.sessionID == nil || *barrier.sessionID == sessionID {
			fence(barrier.sessionID)
		}
	}
	return owner, nil
}

func (b *MemoryBus) FenceSessions(_ context.Context, userID uuid.UUID, sessionID *uuid.UUID) (SessionFenceTicket, error) {
	b.mu.Lock()
	ticketID := uuid.New()
	if b.fences[userID] == nil {
		b.fences[userID] = make(map[uuid.UUID]memoryFence)
	}
	b.fences[userID][ticketID] = memoryFence{sessionID: cloneSessionID(sessionID), validUntil: time.Now().Add(realtimeFenceTTL)}
	owners := make([]*memorySessionOwner, 0, len(b.owners[userID]))
	for owner := range b.owners[userID] {
		owners = append(owners, owner)
	}
	b.mu.Unlock()
	for _, owner := range owners {
		owner.fence(sessionID)
	}
	return &memoryFenceTicket{bus: b, userID: userID, ticketID: ticketID}, nil
}

func (t *memoryFenceTicket) Release(context.Context) error {
	t.once.Do(func() { t.bus.mu.Lock(); delete(t.bus.fences[t.userID], t.ticketID); t.bus.mu.Unlock() })
	return nil
}

func cloneSessionID(sessionID *uuid.UUID) *uuid.UUID {
	if sessionID == nil {
		return nil
	}
	cloned := *sessionID
	return &cloned
}

func (b *MemoryBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, subscriptions := range b.subscribers {
		for subscription := range subscriptions {
			subscription.once.Do(func() { close(subscription.ch) })
		}
	}
	b.subscribers = make(map[uuid.UUID]map[*memorySubscription]struct{})
	b.owners = make(map[uuid.UUID]map[*memorySessionOwner]struct{})
	b.fences = make(map[uuid.UUID]map[uuid.UUID]memoryFence)
}

func (o *memorySessionOwner) Close() error {
	o.once.Do(func() {
		o.bus.mu.Lock()
		delete(o.bus.owners[o.userID], o)
		if len(o.bus.owners[o.userID]) == 0 {
			delete(o.bus.owners, o.userID)
		}
		o.bus.mu.Unlock()
	})
	return nil
}

func (s *memorySubscription) Events() <-chan domain.RealtimeEvent { return s.ch }

func (s *memorySubscription) Close() error {
	s.once.Do(func() {
		s.bus.mu.Lock()
		delete(s.bus.subscribers[s.userID], s)
		s.bus.mu.Unlock()
		close(s.ch)
	})
	return nil
}
