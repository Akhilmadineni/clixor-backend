package events

import (
	"context"
	"encoding/json"
	"errors"
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
	ownerKV    nats.KeyValue
	fenceKV    nats.KeyValue
	replicaID  string
	generation string
	controlSub *nats.Subscription
	mu         sync.Mutex
	owners     map[uuid.UUID]map[*natsSessionOwner]struct{}
	closed     chan struct{}
}

const (
	realtimeOwnerBucket = "CLIXOR_REALTIME_OWNERS"
	// Keep the already-deployed 15-second owner-bucket contract. A successful
	// refresh admits work for only three seconds; every guarded realtime action
	// is bounded to ten seconds, leaving at least two seconds before the
	// published lease expires if refresh fails.
	realtimeOwnerTTL       = 15 * time.Second
	realtimeOwnerRefresh   = 2 * time.Second
	realtimeOwnerAdmission = 3 * time.Second

	realtimeFenceBucket = "CLIXOR_REALTIME_FENCES"
	// HTTP mutations are bounded to thirty seconds. The marker survives that
	// whole mutation plus delayed registration and retry margins.
	realtimeFenceTTL = 2 * time.Minute
)

type natsSessionOwner struct {
	bus        *NATSBUS
	userID     uuid.UUID
	sessionID  uuid.UUID
	fence      SessionFence
	once       sync.Once
	validUntil atomic.Int64
}

type ownerLease struct {
	ReplicaID  string `json:"replica_id"`
	Generation string `json:"generation"`
}

type fenceCommand struct {
	RequestID string     `json:"request_id"`
	UserID    uuid.UUID  `json:"user_id"`
	SessionID *uuid.UUID `json:"session_id,omitempty"`
}

type fenceAck struct {
	RequestID  string `json:"request_id"`
	ReplicaID  string `json:"replica_id"`
	Generation string `json:"generation"`
}

type natsFenceTicket struct {
	bus      *NATSBUS
	key      string
	revision uint64
	mu       sync.Mutex
	released bool
}

type natsSubscription struct {
	sub  *nats.Subscription
	ch   chan domain.RealtimeEvent
	once sync.Once
}

func NewNATS(url, caFile string) (*NATSBUS, error) {
	options := []nats.Option{
		nats.Name("clustr-api"), nats.Timeout(5 * time.Second), nats.MaxReconnects(-1),
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
	ownerKV, err := openKV(js, realtimeOwnerBucket, realtimeOwnerTTL)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open realtime owner registry: %w", err)
	}
	fenceKV, err := openKV(js, realtimeFenceBucket, realtimeFenceTTL)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open realtime fence registry: %w", err)
	}
	b := &NATSBUS{
		conn: conn, ownerKV: ownerKV, fenceKV: fenceKV,
		replicaID: uuid.NewString(), generation: uuid.NewString(),
		owners: make(map[uuid.UUID]map[*natsSessionOwner]struct{}), closed: make(chan struct{}),
	}
	b.controlSub, err = conn.Subscribe(b.controlSubject(), b.handleFenceCommand)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("subscribe realtime control: %w", err)
	}
	// The control subscription must be routable before any owner lease appears.
	flushContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.FlushWithContext(flushContext); err != nil {
		b.Close()
		return nil, fmt.Errorf("register realtime control subscription: %w", err)
	}
	if err := b.putReplicaLease(flushContext); err != nil {
		b.Close()
		return nil, fmt.Errorf("publish realtime replica lease: %w", err)
	}
	if _, err := b.verifyReplicaLease(); err != nil {
		b.Close()
		return nil, fmt.Errorf("verify realtime replica lease: %w", err)
	}
	go b.refreshOwners()
	return b, nil
}

func openKV(js nats.JetStreamContext, bucket string, ttl time.Duration) (nats.KeyValue, error) {
	kv, err := js.KeyValue(bucket)
	if err != nil {
		kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
			Bucket: bucket, TTL: ttl, History: 1, Storage: nats.FileStorage,
		})
		if err != nil {
			kv, err = js.KeyValue(bucket) // another replica may have won creation
		}
	}
	if err != nil {
		return nil, err
	}
	status, err := kv.Status()
	if err != nil || status.TTL() != ttl || status.History() != 1 || status.BackingStore() != "JetStream" {
		return nil, fmt.Errorf("bucket %s has incompatible durability contract", bucket)
	}
	stream, err := js.StreamInfo("KV_" + bucket)
	if err != nil || stream.Config.Storage != nats.FileStorage {
		return nil, fmt.Errorf("bucket %s must use file storage", bucket)
	}
	return kv, nil
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
	if userID == uuid.Nil || sessionID == uuid.Nil || fence == nil {
		return nil, domain.ErrInvalid
	}
	owner := &natsSessionOwner{bus: b, userID: userID, sessionID: sessionID, fence: fence}
	b.mu.Lock()
	if b.owners[userID] == nil {
		b.owners[userID] = make(map[*natsSessionOwner]struct{})
	}
	b.owners[userID][owner] = struct{}{}
	b.mu.Unlock()

	leaseCreated, err := b.verifyReplicaLease()
	if err != nil || !leaseCreated.Add(realtimeOwnerAdmission).After(time.Now()) {
		owner.fence(nil)
		_ = owner.Close()
		if err == nil {
			err = fmt.Errorf("owner lease admission window already drained")
		}
		return nil, fmt.Errorf("verify realtime owner: %w", err)
	}
	owner.validUntil.Store(leaseCreated.Add(realtimeOwnerAdmission).UnixNano())

	// Marker-first fencing plus this post-publication scan closes owner-less and
	// first-owner registration races.
	markers, err := entriesWithPrefix(ctx, b.fenceKV, "f."+userID.String()+".")
	if err != nil {
		owner.fence(nil)
		_ = owner.Close()
		return nil, fmt.Errorf("read realtime fence marker: %w", err)
	}
	for _, entry := range markers {
		all, fencedSession, valid := parseFenceKey(entry.Key(), userID)
		var command fenceCommand
		if !valid || json.Unmarshal(entry.Value(), &command) != nil || command.RequestID == "" ||
			command.UserID != userID || !fenceCommandMatchesKey(command, all, fencedSession) {
			owner.fence(nil)
			_ = owner.Close()
			return nil, fmt.Errorf("invalid realtime fence marker %q", entry.Key())
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
	if userID == uuid.Nil || (sessionID != nil && *sessionID == uuid.Nil) {
		return nil, domain.ErrInvalid
	}
	requestID := uuid.NewString()
	command := fenceCommand{RequestID: requestID, UserID: userID, SessionID: cloneSessionID(sessionID)}
	encoded, _ := json.Marshal(command)
	scope := "a"
	if sessionID != nil {
		scope = "s." + sessionID.String()
	}
	markerKey := "f." + userID.String() + "." + scope + ".t." + requestID
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	revision, err := b.fenceKV.Create(markerKey, encoded)
	if err != nil {
		return nil, fmt.Errorf("install realtime fence marker: %w", err)
	}
	ticket := &natsFenceTicket{bus: b, key: markerKey, revision: revision}
	leases, err := entriesWithPrefix(ctx, b.ownerKV, "r.")
	if err != nil {
		return ticket, fmt.Errorf("list realtime owners: %w", err)
	}

	type target struct{ replicaID, generation string }
	targets := make([]target, 0, len(leases))
	seen := make(map[string]struct{}, len(leases))
	for _, entry := range leases {
		lease, valid := parseOwnerLease(entry, time.Now())
		if !valid {
			return ticket, fmt.Errorf("invalid realtime owner lease %q", entry.Key())
		}
		key := lease.ReplicaID + "." + lease.Generation
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target{lease.ReplicaID, lease.Generation})
	}
	type result struct {
		target target
		err    error
	}
	results := make(chan result, len(targets))
	for _, current := range targets {
		current := current
		go func() {
			message, requestErr := b.conn.RequestWithContext(
				ctx, controlSubject(current.replicaID, current.generation), encoded,
			)
			if requestErr == nil && !validFenceAck(message.Data, requestID, current.replicaID, current.generation) {
				requestErr = fmt.Errorf("invalid acknowledgement")
			}
			results <- result{current, requestErr}
		}()
	}
	for range targets {
		current := <-results
		if current.err != nil {
			return ticket, fmt.Errorf("fence realtime replica %s generation %s: %w",
				current.target.replicaID, current.target.generation, current.err)
		}
	}
	return ticket, nil
}

func entriesWithPrefix(ctx context.Context, kv nats.KeyValue, prefix string) ([]nats.KeyValueEntry, error) {
	watcher, err := kv.Watch(prefix+">", nats.Context(ctx))
	if err != nil {
		return nil, err
	}
	defer watcher.Stop()
	var entries []nats.KeyValueEntry
	for {
		select {
		case entry, open := <-watcher.Updates():
			if !open {
				return nil, fmt.Errorf("registry watch closed")
			}
			if entry == nil {
				return entries, nil
			}
			if entry.Operation() == nats.KeyValuePut {
				entries = append(entries, entry)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func parseOwnerLease(entry nats.KeyValueEntry, now time.Time) (ownerLease, bool) {
	var lease ownerLease
	if entry == nil || entry.Operation() != nats.KeyValuePut ||
		!entry.Created().Add(realtimeOwnerTTL).After(now) || json.Unmarshal(entry.Value(), &lease) != nil ||
		lease.ReplicaID == "" || lease.Generation == "" {
		return ownerLease{}, false
	}
	want := "r." + lease.ReplicaID + ".g." + lease.Generation
	return lease, entry.Key() == want
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

func fenceCommandMatchesKey(command fenceCommand, all bool, sessionID uuid.UUID) bool {
	if all {
		return command.SessionID == nil
	}
	return command.SessionID != nil && *command.SessionID == sessionID
}

func validFenceAck(encoded []byte, requestID, replicaID, generation string) bool {
	var ack fenceAck
	return json.Unmarshal(encoded, &ack) == nil && ack.RequestID == requestID &&
		ack.ReplicaID == replicaID && ack.Generation == generation
}

func (b *NATSBUS) handleFenceCommand(message *nats.Msg) {
	var command fenceCommand
	if json.Unmarshal(message.Data, &command) != nil || command.RequestID == "" || command.UserID == uuid.Nil ||
		(command.SessionID != nil && *command.SessionID == uuid.Nil) {
		return
	}
	b.mu.Lock()
	owners := make([]*natsSessionOwner, 0, len(b.owners[command.UserID]))
	for owner := range b.owners[command.UserID] {
		owners = append(owners, owner)
	}
	b.mu.Unlock()
	for _, owner := range owners {
		if command.SessionID == nil || owner.sessionID == *command.SessionID {
			owner.fence(command.SessionID)
		}
	}
	ack, _ := json.Marshal(fenceAck{
		RequestID: command.RequestID, ReplicaID: b.replicaID, Generation: b.generation,
	})
	_ = message.Respond(ack) // only after every applicable local guard fenced
}

func controlSubject(replicaID, generation string) string {
	return "realtime.control." + replicaID + "." + generation
}

func (b *NATSBUS) controlSubject() string { return controlSubject(b.replicaID, b.generation) }

func (b *NATSBUS) replicaLeaseKey() string {
	return "r." + b.replicaID + ".g." + b.generation
}

func (b *NATSBUS) putReplicaLease(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, _ := json.Marshal(ownerLease{ReplicaID: b.replicaID, Generation: b.generation})
	_, err := b.ownerKV.Put(b.replicaLeaseKey(), encoded)
	return err
}

func (b *NATSBUS) verifyReplicaLease() (time.Time, error) {
	entry, err := b.ownerKV.Get(b.replicaLeaseKey())
	if err != nil {
		return time.Time{}, err
	}
	lease, valid := parseOwnerLease(entry, time.Now())
	if !valid || lease.ReplicaID != b.replicaID || lease.Generation != b.generation {
		return time.Time{}, fmt.Errorf("owner lease is not the current generation")
	}
	return entry.Created(), nil
}

func (b *NATSBUS) markOwnersAdmissible(refreshedAt time.Time) {
	validUntil := refreshedAt.Add(realtimeOwnerAdmission).UnixNano()
	b.mu.Lock()
	for _, owners := range b.owners {
		for owner := range owners {
			owner.validUntil.Store(validUntil)
		}
	}
	b.mu.Unlock()
}

func (t *natsFenceTicket) Release(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.released {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := t.bus.fenceKV.Delete(t.key, nats.LastRevision(t.revision))
	if err != nil && !errors.Is(err, nats.ErrKeyNotFound) && !errors.Is(err, nats.ErrKeyDeleted) {
		return err
	}
	if _, getErr := t.bus.fenceKV.Get(t.key); getErr == nil {
		return fmt.Errorf("realtime fence marker still exists")
	} else if !errors.Is(getErr, nats.ErrKeyNotFound) && !errors.Is(getErr, nats.ErrKeyDeleted) {
		return getErr
	}
	t.released = true
	return nil
}

func (b *NATSBUS) refreshOwners() {
	ticker := time.NewTicker(realtimeOwnerRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), realtimeOwnerRefresh)
			err := b.putReplicaLease(ctx)
			var leaseCreated time.Time
			if err == nil {
				leaseCreated, err = b.verifyReplicaLease()
				if err == nil && !leaseCreated.Add(realtimeOwnerAdmission).After(time.Now()) {
					err = fmt.Errorf("owner lease admission window already drained")
				}
			}
			cancel()
			if err != nil {
				b.mu.Lock()
				owners := make([]*natsSessionOwner, 0)
				for _, byUser := range b.owners {
					for owner := range byUser {
						owners = append(owners, owner)
					}
				}
				b.mu.Unlock()
				for _, owner := range owners {
					owner.validUntil.Store(0)
					owner.fence(nil)
				}
			} else {
				b.markOwnersAdmissible(leaseCreated)
			}
		case <-b.closed:
			return
		}
	}
}

func (o *natsSessionOwner) Valid() bool { return time.Now().UnixNano() < o.validUntil.Load() }

func (b *NATSBUS) Close() {
	if b.conn == nil {
		return
	}
	select {
	case <-b.closed:
		return
	default:
		close(b.closed)
	}
	b.mu.Lock()
	for _, owners := range b.owners {
		for owner := range owners {
			owner.validUntil.Store(0)
			owner.fence(nil)
		}
	}
	b.owners = make(map[uuid.UUID]map[*natsSessionOwner]struct{})
	b.mu.Unlock()
	_ = b.ownerKV.Delete(b.replicaLeaseKey())
	b.conn.Drain()
	b.conn.Close()
}

func (o *natsSessionOwner) Close() error {
	o.once.Do(func() {
		o.validUntil.Store(0)
		o.bus.mu.Lock()
		delete(o.bus.owners[o.userID], o)
		last := len(o.bus.owners[o.userID]) == 0
		if last {
			delete(o.bus.owners, o.userID)
		}
		o.bus.mu.Unlock()
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
