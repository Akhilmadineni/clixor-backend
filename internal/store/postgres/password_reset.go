package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CreatePasswordResetChallenge(
	ctx context.Context,
	challenge domain.PasswordResetChallenge,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize replacement of the partial-unique active challenge. The user row
	// is locked before challenge rows to match account deletion and confirmation;
	// this avoids both uniqueness-based enumeration and lock-order deadlocks.
	if _, err := lockPasswordResetUser(ctx, tx, challenge.UserID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE password_reset_challenges SET consumed_at=now()
		WHERE user_id=$1 AND consumed_at IS NULL`, challenge.UserID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO password_reset_challenges
			(id,user_id,code_hash,attempts,expires_at,created_at)
		VALUES($1,$2,$3,0,$4,$5)`,
		challenge.ID, challenge.UserID, challenge.CodeHash,
		challenge.ExpiresAt, challenge.CreatedAt)
	if err != nil {
		return mapError(err)
	}
	return tx.Commit(ctx)
}

func (s *Store) CancelPasswordResetChallenge(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM password_reset_challenges WHERE id=$1`, id)
	return err
}

func (s *Store) ConsumePasswordResetChallenge(
	ctx context.Context,
	id uuid.UUID,
	codeHash []byte,
	newPasswordHash string,
	maxAttempts int,
) (string, error) {
	// Read only the owner needed to choose the per-user lock. Do not lock the
	// challenge first: account deletion locks users before its cleanup trigger
	// deletes reset rows, and the opposite order can deadlock.
	var userID uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		SELECT user_id FROM password_reset_challenges WHERE id=$1`, id,
	).Scan(&userID); errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrUnauthenticated
	} else if err != nil {
		return "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	email, err := lockPasswordResetUser(ctx, tx, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return "", domain.ErrUnauthenticated
	}
	if err != nil {
		return "", err
	}

	var expectedHash []byte
	var attempts int
	var expiresAt time.Time
	var consumedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT code_hash,attempts,expires_at,consumed_at
		FROM password_reset_challenges
		WHERE id=$1 AND user_id=$2
		FOR UPDATE`, id, userID,
	).Scan(&expectedHash, &attempts, &expiresAt, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrUnauthenticated
	}
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if consumedAt != nil || !expiresAt.After(now) || attempts >= maxAttempts {
		return "", domain.ErrUnauthenticated
	}
	if len(expectedHash) != len(codeHash) ||
		subtle.ConstantTimeCompare(expectedHash, codeHash) != 1 {
		if _, err := tx.Exec(ctx, `
			UPDATE password_reset_challenges SET attempts=attempts+1 WHERE id=$1`, id); err != nil {
			return "", err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", err
		}
		return "", domain.ErrUnauthenticated
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET password_hash=$2,updated_at=$3 WHERE id=$1`,
		userID, newPasswordHash, now); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions SET revoked_at=$2
		WHERE user_id=$1 AND revoked_at IS NULL`, userID, now); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE password_reset_challenges SET consumed_at=$2
		WHERE user_id=$1 AND consumed_at IS NULL`, userID, now); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return email, nil
}

// lockPasswordResetUser defines the lock order shared by reset start and
// confirmation: namespaced advisory lock, live password-user row, then reset
// challenge rows. A legacy account deletion does not take the advisory lock,
// but it takes the same user row first, so its trigger cannot form a lock cycle.
func lockPasswordResetUser(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
) (string, error) {
	lockKey := "password-reset:" + userID.String()
	if _, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return "", err
	}
	var email string
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(email,'') FROM users
		WHERE id=$1 AND deleted_at IS NULL AND password_hash<>''
		FOR UPDATE`, userID).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrNotFound
	}
	return email, err
}
