package events

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

type NATSBUS struct {
	conn       *nats.Conn
	kv         nats.KeyValue
	replicaID  string
	controlSub *nats.Subscription
	mu         sync.Mutex
	owners     map[uuid.UUID]map[*natsSessionOwner]struct{}
	closed     chan struct{}
}

const (
	realtimeOwnerBucket  = "CLIXOR_REALTIME_OWNERS"
	realtimeOwnerTTL     = 15 * time.Second
	realtimeOwnerRefresh = 5 * time.Second
)

type natsSessionOwner struct {
	bus        *NATSBUS
	userID     uuid.UUID
	fence      SessionFence
	once       sync.Once
	validUntil atomic.Int64
}

type fenceCommand struct {
	RequestID string     `json:"request_id"`
	UserID    uuid.UUID  `json:"user_id"`
	SessionID *uuid.UUID `json:"session_id,omitempty"`
}

type fenceAck struct {
	RequestID string `json:"request_id"`
	ReplicaID string `json:"replica_id"`
}

type natsFenceTicket struct {
	bus  *NATSBUS
	key  string
	once sync.Once
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
	js, err := conn.JetStream()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open NATS JetStream: %w", err)
	}
	kv, err := js.KeyValue(realtimeOwnerBucket)
	if err != nil {
		kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
			Bucket: realtimeOwnerBucket, TTL: realtimeOwnerTTL, History: 1, Storage: nats.FileStorage,
		})
		if err != nil {
			// Another replica may have won the bucket-creation race.
			kv, err = js.KeyValue(realtimeOwnerBucket)
		}
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open realtime owner registry: %w", err)
	}
	status, err := kv.Status()
	if err != nil || status.TTL() != realtimeOwnerTTL || status.History() != 1 || status.BackingStore() != "JetStream" {
		conn.Close()
		return nil, fmt.Errorf("realtime owner registry has incompatible durability contract")
	}
	stream, err := js.StreamInfo("KV_" + realtimeOwnerBucket)
	if err != nil || stream.Config.Storage != nats.FileStorage {
		conn.Close()
		return nil, fmt.Errorf("realtime owner registry must use file storage")
	}
	b := &NATSBUS{
		conn: conn, kv: kv, replicaID: uuid.NewString(),
		owners: make(map[uuid.UUID]map[*natsSessionOwner]struct{}), closed: make(chan struct{}),
	}
	b.controlSub, err = conn.Subscribe("realtime.control."+b.replicaID, b.handleFenceCommand)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("subscribe realtime control: %w", err)
	}
	flushContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.FlushWithContext(flushContext); err != nil {
		b.Close()
		return nil, fmt.Errorf("register realtime control subscription: %w", err)
	}
	go b.refreshOwners()
	return b, nil
}

func (b *NATSBUS) Ping(ctx context.Context) error {
	if b.conn == nil || !b.conn.IsConnected() {
		return fmt.Errorf("NATS is not connected")
	}
	return b.conn.FlushWithContext(ctx)
}

func (b *NATSBUS) Publish(ctx context.Context, users []uuid.UUID, event domain.RealtimeEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	for _, userID := range uniqueUsers(users) {
		if err := b.conn.Publish("users."+userID.String()+".events", payload); err != nil {
			return err
		}
	}
	return b.conn.FlushWithContext(ctx)
}

func (b *NATSBUS) Subscribe(ctx context.Context, userID uuid.UUID) (Subscription, error) {
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
	if err := b.conn.FlushWithContext(ctx); err != nil {
		_ = sub.Unsubscribe()
		return nil, err
	}
	return result, nil
}

func (b *NATSBUS) RegisterSessionOwner(ctx context.Context, userID, sessionID uuid.UUID, fence SessionFence) (SessionOwner, error) {
	owner := &natsSessionOwner{bus: b, userID: userID, fence: fence}
	b.mu.Lock()
	if b.owners[userID] == nil {
		b.owners[userID] = make(map[*natsSessionOwner]struct{})
	}
	b.owners[userID][owner] = struct{}{}
	b.mu.Unlock()
	if err := b.putOwner(ctx, userID); err != nil {
		owner.fence(nil)
		_ = owner.Close()
		return nil, fmt.Errorf("register realtime owner: %w", err)
	}
	owner.validUntil.Store(time.Now().Add(realtimeOwnerTTL - realtimeOwnerRefresh).UnixNano())
	markers, err := b.keysWithPrefix(ctx, "f."+userID.String()+".")
	if err != nil {
		owner.fence(nil)
		_ = owner.Close()
		return nil, fmt.Errorf("read realtime fence marker: %w", err)
	}
	for _, key := range markers {
		all, fencedSession, valid := parseFenceKey(key, userID)
		if !valid {
			owner.fence(nil)
			continue
		}
		if all || fencedSession == sessionID {
			var scoped *uuid.UUID
			if !all {
				scoped = &fencedSession
			}
			owner.fence(scoped)
		}
	}
	return owner, nil
}

func (b *NATSBUS) FenceSessions(ctx context.Context, userID uuid.UUID, sessionID *uuid.UUID) (SessionFenceTicket, error) {
	requestID := uuid.NewString()
	command, _ := json.Marshal(fenceCommand{RequestID: requestID, UserID: userID, SessionID: sessionID})
	scope := "a"
	if sessionID != nil {
		scope = "s." + sessionID.String()
	}
	markerKey := "f." + userID.String() + "." + scope + ".t." + requestID
	if err := b.putKey(ctx, markerKey, command); err != nil {
		return nil, fmt.Errorf("install realtime fence marker: %w", err)
	}
	ticket := &natsFenceTicket{bus: b, key: markerKey}
	keys, err := b.keysWithPrefix(ctx, "u."+userID.String()+".r.")
	if err != nil {
		return ticket, fmt.Errorf("list realtime owners: %w", err)
	}
	prefix := "u." + userID.String() + ".r."
	seen := make(map[string]struct{})
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		replicaID := strings.TrimPrefix(key, prefix)
		if replicaID == "" {
			return ticket, fmt.Errorf("invalid realtime owner key %q", key)
		}
		if _, duplicate := seen[replicaID]; duplicate {
			continue
		}
		seen[replicaID] = struct{}{}
		message, err := b.conn.RequestWithContext(ctx, "realtime.control."+replicaID, command)
		if err != nil {
			return ticket, fmt.Errorf("fence realtime replica %s: %w", replicaID, err)
		}
		if !validFenceAck(message.Data, requestID, replicaID) {
			return ticket, fmt.Errorf("invalid realtime fence acknowledgement from %s", replicaID)
		}
	}
	return ticket, nil
}

func (b *NATSBUS) keysWithPrefix(ctx context.Context, prefix string) ([]string, error) {
	watcher, err := b.kv.Watch(prefix+">", nats.MetaOnly(), nats.Context(ctx))
	if err != nil {
		return nil, err
	}
	defer watcher.Stop()
	var keys []string
	for {
		select {
		case entry, open := <-watcher.Updates():
			if !open {
				return nil, fmt.Errorf("owner registry watch closed")
			}
			if entry == nil {
				return keys, nil
			}
			if entry.Operation() == nats.KeyValuePut {
				keys = append(keys, entry.Key())
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func parseFenceKey(key string, userID uuid.UUID) (bool, uuid.UUID, bool) {
	prefix := "f." + userID.String() + "."
	value := strings.TrimPrefix(key, prefix)
	if value == key {
		return false, uuid.Nil, false
	}
	if strings.HasPrefix(value, "a.t.") {
		return true, uuid.Nil, strings.TrimPrefix(value, "a.t.") != ""
	}
	if !strings.HasPrefix(value, "s.") {
		return false, uuid.Nil, false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[2] != "t" || parts[3] == "" {
		return false, uuid.Nil, false
	}
	id, err := uuid.Parse(parts[1])
	return false, id, err == nil && id != uuid.Nil
}

func validFenceAck(encoded []byte, requestID, replicaID string) bool {
	var ack fenceAck
	return json.Unmarshal(encoded, &ack) == nil && ack.RequestID == requestID && ack.ReplicaID == replicaID
}

func (b *NATSBUS) handleFenceCommand(message *nats.Msg) {
	var command fenceCommand
	if json.Unmarshal(message.Data, &command) != nil || command.RequestID == "" || command.UserID == uuid.Nil {
		return
	}
	b.mu.Lock()
	owners := make([]*natsSessionOwner, 0, len(b.owners[command.UserID]))
	for owner := range b.owners[command.UserID] {
		owners = append(owners, owner)
	}
	b.mu.Unlock()
	for _, owner := range owners {
		owner.fence(command.SessionID)
	}
	ack, _ := json.Marshal(fenceAck{RequestID: command.RequestID, ReplicaID: b.replicaID})
	_ = message.Respond(ack)
}

func (b *NATSBUS) ownerKey(userID uuid.UUID) string {
	return "u." + userID.String() + ".r." + b.replicaID
}

func (b *NATSBUS) putOwner(ctx context.Context, userID uuid.UUID) error {
	return b.putKey(ctx, b.ownerKey(userID), []byte(b.replicaID))
}

func (b *NATSBUS) putKey(ctx context.Context, key string, value []byte) error {
	done := make(chan error, 1)
	go func() {
		_, err := b.kv.Put(key, value)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// The legacy KV API has no context-aware Put. If the server accepts the
		// write after our deadline, compensate by removing it so a timed-out owner
		// or fence registration cannot appear later as a ghost lease.
		go func() {
			if err := <-done; err == nil {
				_ = b.kv.Delete(key)
			}
		}()
		return ctx.Err()
	}
}

func (t *natsFenceTicket) Release(ctx context.Context) error {
	var result error
	t.once.Do(func() {
		done := make(chan error, 1)
		go func() { done <- t.bus.kv.Delete(t.key) }()
		select {
		case result = <-done:
		case <-ctx.Done():
			result = ctx.Err()
		}
	})
	return result
}

func (b *NATSBUS) refreshOwners() {
	ticker := time.NewTicker(realtimeOwnerRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.mu.Lock()
			users := make([]uuid.UUID, 0, len(b.owners))
			for userID := range b.owners {
				users = append(users, userID)
			}
			b.mu.Unlock()
			for _, userID := range users {
				ctx, cancel := context.WithTimeout(context.Background(), realtimeOwnerRefresh)
				err := b.putOwner(ctx, userID)
				cancel()
				if err != nil {
					b.mu.Lock()
					owners := make([]*natsSessionOwner, 0, len(b.owners[userID]))
					for owner := range b.owners[userID] {
						owners = append(owners, owner)
					}
					b.mu.Unlock()
					for _, owner := range owners {
						owner.fence(nil)
					}
				} else {
					validUntil := time.Now().Add(realtimeOwnerTTL - realtimeOwnerRefresh).UnixNano()
					b.mu.Lock()
					for owner := range b.owners[userID] {
						owner.validUntil.Store(validUntil)
					}
					b.mu.Unlock()
				}
			}
		case <-b.closed:
			return
		}
	}
}

func (o *natsSessionOwner) Valid() bool {
	return time.Now().UnixNano() < o.validUntil.Load()
}

func (b *NATSBUS) Close() {
	if b.conn != nil {
		select {
		case <-b.closed:
		default:
			close(b.closed)
		}
		b.mu.Lock()
		for userID, owners := range b.owners {
			for owner := range owners {
				owner.fence(nil)
			}
			_ = b.kv.Delete(b.ownerKey(userID))
		}
		b.owners = make(map[uuid.UUID]map[*natsSessionOwner]struct{})
		b.mu.Unlock()
		b.conn.Drain()
		b.conn.Close()
	}
}

func (o *natsSessionOwner) Close() error {
	o.once.Do(func() {
		o.bus.mu.Lock()
		delete(o.bus.owners[o.userID], o)
		last := len(o.bus.owners[o.userID]) == 0
		if last {
			delete(o.bus.owners, o.userID)
		}
		o.bus.mu.Unlock()
		if last {
			_ = o.bus.kv.Delete(o.bus.ownerKey(o.userID))
		}
	})
	return nil
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
