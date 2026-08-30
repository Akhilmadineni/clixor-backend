package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) PutAccountDeletionIntent(ctx context.Context, intent domain.AccountDeletionIntent) error {
	if intent.RequestID == uuid.Nil || intent.UserID == uuid.Nil || len(intent.TokenHash) != 32 {
		return domain.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Account deletion uses media-quota -> user as its global lock order. Take
	// the same locks before the intent row so registration cannot deadlock with
	// either legacy deletion or capability execution.
	if err := lockMediaQuota(ctx, tx, "user", intent.UserID); err != nil {
		return err
	}
	if err := lockLiveUser(ctx, tx, intent.UserID); err != nil {
		return err
	}
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `
		INSERT INTO account_deletion_intents(request_id,user_id,token_hash,state,created_at)
		VALUES($1,$2,$3,'pending',$4) ON CONFLICT(request_id) DO NOTHING`,
		intent.RequestID, intent.UserID, intent.TokenHash, now)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		var existingUser uuid.UUID
		var existingHash []byte
		if err := tx.QueryRow(ctx, `
			SELECT user_id,token_hash FROM account_deletion_intents
			WHERE request_id=$1 FOR UPDATE`, intent.RequestID,
		).Scan(&existingUser, &existingHash); err != nil {
			return mapError(err)
		}
		if existingUser != intent.UserID || subtle.ConstantTimeCompare(existingHash, intent.TokenHash) != 1 {
			return domain.ErrConflict
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ExecuteAccountDeletionIntent(
	ctx context.Context,
	requestID uuid.UUID,
	tokenHash []byte,
	fence store.AccountDeletionFence,
) error {
	if requestID == uuid.Nil || len(tokenHash) != 32 || fence == nil {
		return domain.ErrNotFound
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Resolve the immutable binding without a lock, then acquire the shared
	// account lock order (media-quota -> user -> intent). The binding is checked
	// again under the intent lock before the capability is trusted.
	var userID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT user_id FROM account_deletion_intents WHERE request_id=$1`, requestID,
	).Scan(&userID); err != nil {
		return domain.ErrNotFound
	}
	if err := lockMediaQuota(ctx, tx, "user", userID); err != nil {
		return err
	}
	var lockedUserID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&lockedUserID); err != nil {
		return domain.ErrNotFound
	}
	var expectedHash []byte
	var state string
	if err := tx.QueryRow(ctx, `
		SELECT user_id,token_hash,state FROM account_deletion_intents
		WHERE request_id=$1 FOR UPDATE`, requestID,
	).Scan(&userID, &expectedHash, &state); err != nil {
		return domain.ErrNotFound
	}
	if subtle.ConstantTimeCompare(expectedHash, tokenHash) != 1 {
		return domain.ErrNotFound
	}
	if state == domain.AccountDeletionCompleted {
		return tx.Commit(ctx)
	}
	if state != domain.AccountDeletionPending {
		return domain.ErrNotFound
	}
	if err := s.deleteAccountTx(ctx, tx, userID, fence); err != nil && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE account_deletion_intents
		SET state='completed',completed_at=now()
		WHERE request_id=$1 AND state='pending'`, requestID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
