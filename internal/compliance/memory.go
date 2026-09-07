package compliance

import (
	"context"
	"crypto/subtle"
	"sort"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

// Memory is for tests and explicitly non-durable development stores only.
type Memory struct {
	delivery    sync.RWMutex
	blocks      map[[2]uuid.UUID]bool
	mu          sync.Mutex
	acceptances map[string]Acceptance
	cases       map[uuid.UUID]Case
	reviews     []Review
}

func NewMemory() *Memory {
	return &Memory{acceptances: map[string]Acceptance{}, cases: map[uuid.UUID]Case{}, blocks: map[[2]uuid.UUID]bool{}}
}

func (m *Memory) SetBlock(_ context.Context, a, b uuid.UUID, block bool) error {
	if a == uuid.Nil || b == uuid.Nil || a == b {
		return domain.ErrInvalid
	}
	m.delivery.Lock()
	defer m.delivery.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if block {
		m.blocks[[2]uuid.UUID{a, b}] = true
	} else {
		delete(m.blocks, [2]uuid.UUID{a, b})
	}
	return nil
}
func (m *Memory) Blocks(_ context.Context, a uuid.UUID) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]uuid.UUID, 0)
	for pair := range m.blocks {
		if pair[0] == a {
			result = append(result, pair[1])
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}
func (m *Memory) Blocked(_ context.Context, a, b uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blocks[[2]uuid.UUID{a, b}] || m.blocks[[2]uuid.UUID{b, a}], nil
}
func (m *Memory) DeliverIfAllowed(ctx context.Context, a, b uuid.UUID, send func() error) (bool, error) {
	m.delivery.RLock()
	defer m.delivery.RUnlock()
	blocked, err := m.Blocked(ctx, a, b)
	if err != nil || blocked {
		return false, err
	}
	return true, send()
}
func (m *Memory) Accept(_ context.Context, a Acceptance) (Acceptance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := a.UserID.String() + ":" + a.Version
	if old, ok := m.acceptances[key]; ok {
		if old.DocumentSHA256 != a.DocumentSHA256 || old.AgeGroup != a.AgeGroup || old.GuardianPermission != a.GuardianPermission {
			return Acceptance{}, domain.ErrConflict
		}
		return old, nil
	}
	m.acceptances[key] = a
	return a, nil
}
func (m *Memory) Acceptance(_ context.Context, id uuid.UUID, version string) (Acceptance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.acceptances[id.String()+":"+version]
	if !ok {
		return Acceptance{}, domain.ErrNotFound
	}
	return a, nil
}
func (m *Memory) Submit(_ context.Context, c Case) (CaseStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.cases[c.ID]; ok {
		if subtle.ConstantTimeCompare(old.TokenHash, c.TokenHash) != 1 || subtle.ConstantTimeCompare(old.RequestHash, c.RequestHash) != 1 {
			return CaseStatus{}, domain.ErrConflict
		}
		return old.Public(), nil
	}
	c.TokenHash = append([]byte(nil), c.TokenHash...)
	c.RequestHash = append([]byte(nil), c.RequestHash...)
	m.cases[c.ID] = c
	return c.Public(), nil
}
func (m *Memory) Status(_ context.Context, id uuid.UUID, hash []byte) (CaseStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cases[id]
	if !ok || subtle.ConstantTimeCompare(c.TokenHash, hash) != 1 {
		return CaseStatus{}, domain.ErrNotFound
	}
	return c.Public(), nil
}
func (m *Memory) ListCases(_ context.Context, limit int) ([]Case, error) {
	if limit < 1 || limit > 100 {
		return nil, domain.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Case, 0)
	for _, c := range m.cases {
		if c.Status != "resolved" && c.Status != "declined" {
			result = append(result, c)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ReceivedAt.Before(result[j].ReceivedAt) })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}
func (m *Memory) Review(_ context.Context, r Review) error {
	if err := r.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cases[r.CaseID]
	if !ok {
		return domain.ErrNotFound
	}
	if c.Status != r.ExpectedStatus {
		return domain.ErrConflict
	}
	c.Status = r.Status
	c.PublicUpdate = r.PublicUpdate
	c.UpdatedAt = time.Now().UTC()
	m.cases[c.ID] = c
	m.reviews = append(m.reviews, r)
	return nil
}
