package presence

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/tlsconfig"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type Service interface {
	Ping(context.Context) error
	Online(context.Context, uuid.UUID, uuid.UUID) error
	Heartbeat(context.Context, uuid.UUID, uuid.UUID) error
	Offline(context.Context, uuid.UUID, uuid.UUID) error
	IsOnline(context.Context, uuid.UUID) (bool, error)
	Close() error
}

type Memory struct {
	mu      sync.Mutex
	devices map[uuid.UUID]map[uuid.UUID]time.Time
}

func NewMemory() *Memory {
	return &Memory{devices: make(map[uuid.UUID]map[uuid.UUID]time.Time)}
}

func (*Memory) Ping(context.Context) error { return nil }

func (m *Memory) Online(_ context.Context, userID, deviceID uuid.UUID) error {
	return m.set(userID, deviceID)
}
func (m *Memory) Heartbeat(_ context.Context, userID, deviceID uuid.UUID) error {
	return m.set(userID, deviceID)
}
func (m *Memory) Offline(_ context.Context, userID, deviceID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.devices[userID], deviceID)
	return nil
}
func (m *Memory) IsOnline(_ context.Context, userID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for deviceID, expires := range m.devices[userID] {
		if expires.After(now) {
			return true, nil
		}
		delete(m.devices[userID], deviceID)
	}
	return false, nil
}
func (*Memory) Close() error { return nil }
func (m *Memory) set(userID, deviceID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.devices[userID] == nil {
		m.devices[userID] = make(map[uuid.UUID]time.Time)
	}
	m.devices[userID][deviceID] = time.Now().Add(70 * time.Second)
	return nil
}

type Redis struct {
	client *redis.Client
}

func NewRedis(ctx context.Context, rawURL, caFile string) (*Redis, error) {
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	if options.TLSConfig != nil {
		options.TLSConfig, err = tlsconfig.Client(caFile)
		if err != nil {
			return nil, err
		}
	}
	client := redis.NewClient(options)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &Redis{client: client}, nil
}

func (r *Redis) Online(ctx context.Context, userID, deviceID uuid.UUID) error {
	return r.heartbeat(ctx, userID, deviceID)
}
func (r *Redis) Heartbeat(ctx context.Context, userID, deviceID uuid.UUID) error {
	return r.heartbeat(ctx, userID, deviceID)
}
func (r *Redis) Offline(ctx context.Context, userID, deviceID uuid.UUID) error {
	return r.client.ZRem(ctx, presenceKey(userID), deviceID.String()).Err()
}
func (r *Redis) IsOnline(ctx context.Context, userID uuid.UUID) (bool, error) {
	key := presenceKey(userID)
	now := time.Now().Unix()
	pipe := r.client.TxPipeline()
	pipe.ZRemRangeByScore(ctx, key, "-inf", formatScore(now))
	count := pipe.ZCard(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}
	return count.Val() > 0, nil
}
func (r *Redis) Ping(ctx context.Context) error { return r.client.Ping(ctx).Err() }
func (r *Redis) Close() error                   { return r.client.Close() }
func (r *Redis) heartbeat(ctx context.Context, userID, deviceID uuid.UUID) error {
	key := presenceKey(userID)
	expires := time.Now().Add(70 * time.Second).Unix()
	pipe := r.client.TxPipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(expires), Member: deviceID.String()})
	pipe.Expire(ctx, key, 2*time.Minute)
	_, err := pipe.Exec(ctx)
	return err
}
func presenceKey(userID uuid.UUID) string { return "presence:user:" + userID.String() }
func formatScore(value int64) string      { return strconv.FormatInt(value, 10) }
