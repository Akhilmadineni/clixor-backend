package events

import (
	"context"
	"sync"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

type MemoryBus struct {
	mu          sync.RWMutex
	subscribers map[uuid.UUID]map[*memorySubscription]struct{}
}

type memorySubscription struct {
	bus    *MemoryBus
	userID uuid.UUID
	ch     chan domain.RealtimeEvent
	once   sync.Once
}

func NewMemoryBus() *MemoryBus {
	return &MemoryBus{subscribers: make(map[uuid.UUID]map[*memorySubscription]struct{})}
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

func (b *MemoryBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, subscriptions := range b.subscribers {
		for subscription := range subscriptions {
			subscription.once.Do(func() { close(subscription.ch) })
		}
	}
	b.subscribers = make(map[uuid.UUID]map[*memorySubscription]struct{})
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
