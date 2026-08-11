package events

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

type NATSBUS struct {
	conn *nats.Conn
}

type natsSubscription struct {
	sub  *nats.Subscription
	ch   chan domain.RealtimeEvent
	once sync.Once
}

func NewNATS(url, caFile string) (*NATSBUS, error) {
	options := []nats.Option{
		nats.Name("clustr-api"),
		nats.Timeout(5 * time.Second),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	}
	if caFile != "" {
		options = append(options, nats.RootCAs(caFile))
	}
	conn, err := nats.Connect(url, options...)
	if err != nil {
		return nil, fmt.Errorf("connect NATS: %w", err)
	}
	return &NATSBUS{conn: conn}, nil
}

func (b *NATSBUS) Ping(ctx context.Context) error {
	if b.conn == nil || !b.conn.IsConnected() {
		return fmt.Errorf("NATS is not connected")
	}
	return b.conn.FlushWithContext(ctx)
}

func (b *NATSBUS) Publish(_ context.Context, users []uuid.UUID, event domain.RealtimeEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	for _, userID := range uniqueUsers(users) {
		if err := b.conn.Publish("users."+userID.String()+".events", payload); err != nil {
			return err
		}
	}
	return b.conn.Flush()
}

func (b *NATSBUS) Subscribe(_ context.Context, userID uuid.UUID) (Subscription, error) {
	result := &natsSubscription{ch: make(chan domain.RealtimeEvent, 256)}
	sub, err := b.conn.Subscribe("users."+userID.String()+".events", func(message *nats.Msg) {
		var event domain.RealtimeEvent
		if json.Unmarshal(message.Data, &event) != nil {
			return
		}
		select {
		case result.ch <- event:
		default:
		}
	})
	if err != nil {
		return nil, err
	}
	result.sub = sub
	return result, nil
}

func (b *NATSBUS) Close() {
	if b.conn != nil {
		b.conn.Drain()
		b.conn.Close()
	}
}

func (s *natsSubscription) Events() <-chan domain.RealtimeEvent { return s.ch }

func (s *natsSubscription) Close() error {
	var err error
	s.once.Do(func() {
		err = s.sub.Unsubscribe()
		close(s.ch)
	})
	return err
}

func uniqueUsers(users []uuid.UUID) []uuid.UUID {
	seen := make(map[string]struct{}, len(users))
	result := make([]uuid.UUID, 0, len(users))
	for _, userID := range users {
		key := strings.ToLower(userID.String())
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, userID)
	}
	return result
}
