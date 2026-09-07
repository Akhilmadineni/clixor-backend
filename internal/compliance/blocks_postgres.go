package compliance

import (
	"context"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func (p *Postgres) SetBlock(ctx context.Context, a, b uuid.UUID, block bool) error {
	if a == uuid.Nil || b == uuid.Nil || a == b {
		return domain.ErrInvalid
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, AccountDeliveryBarrierKey); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE id=ANY($1) AND deleted_at IS NULL`, []uuid.UUID{a, b}).Scan(&count); err != nil {
		return err
	}
	if block && count != 2 {
		return domain.ErrNotFound
	}
	if block {
		_, err = tx.Exec(ctx, `INSERT INTO user_blocks(blocker_id,blocked_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, a, b)
	} else {
		_, err = tx.Exec(ctx, `DELETE FROM user_blocks WHERE blocker_id=$1 AND blocked_id=$2`, a, b)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (p *Postgres) Blocks(ctx context.Context, a uuid.UUID) ([]uuid.UUID, error) {
	rows, err := p.pool.Query(ctx, `SELECT blocked_id FROM user_blocks WHERE blocker_id=$1 ORDER BY blocked_id`, a)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}
func (p *Postgres) Blocked(ctx context.Context, a, b uuid.UUID) (bool, error) {
	var blocked bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1))`, a, b).Scan(&blocked)
	return blocked, err
}
func (p *Postgres) DeliverIfAllowed(ctx context.Context, a, b uuid.UUID, send func() error) (bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, AccountDeliveryBarrierKey); err != nil {
		return false, err
	}
	var blocked bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1))`, a, b).Scan(&blocked)
	if err != nil || blocked {
		return false, err
	}
	if err = send(); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
