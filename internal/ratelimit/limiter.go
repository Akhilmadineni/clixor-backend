package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/tlsconfig"
	"github.com/redis/go-redis/v9"
)

type Limiter interface {
	Ping(context.Context) error
	Allow(context.Context, string, int, time.Duration) (bool, error)
	Close() error
}

type Memory struct {
	mu      sync.Mutex
	windows map[string]window
}

type window struct {
	count   int
	expires time.Time
}

func NewMemory() *Memory {
	return &Memory{windows: make(map[string]window)}
}

func (*Memory) Ping(context.Context) error { return nil }

func (m *Memory) Allow(_ context.Context, key string, limit int, duration time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	current := m.windows[key]
	if current.expires.Before(now) {
		current = window{expires: now.Add(duration)}
	}
	current.count++
	m.windows[key] = current
	return current.count <= limit, nil
}

func (*Memory) Close() error { return nil }

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

var fixedWindowScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return current
`)

func (r *Redis) Allow(ctx context.Context, key string, limit int, duration time.Duration) (bool, error) {
	count, err := fixedWindowScript.Run(ctx, r.client, []string{"ratelimit:" + key}, duration.Milliseconds()).Int64()
	if err != nil {
		return false, err
	}
	return count <= int64(limit), nil
}

func (r *Redis) Ping(ctx context.Context) error { return r.client.Ping(ctx).Err() }
func (r *Redis) Close() error                   { return r.client.Close() }
