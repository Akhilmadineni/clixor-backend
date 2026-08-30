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

func (s *Store) CreatePasswordResetChallenge(
	ctx context.Context,
	challenge domain.PasswordResetChallenge,
) error {
	return s.createPasswordResetChallenge(ctx, challenge, nil)
}

func (s *Store) CreatePasswordResetChallengeWithMail(
	ctx context.Context,
	challenge domain.PasswordResetChallenge,
	buildMail store.MailDeliveryBuilder,
) error {
	if buildMail == nil {
		return domain.ErrInvalid
	}
	return s.createPasswordResetChallenge(ctx, challenge, buildMail)
}

func (s *Store) createPasswordResetChallenge(
	ctx context.Context,
	challenge domain.PasswordResetChallenge,
	buildMail store.MailDeliveryBuilder,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize replacement of the partial-unique active challenge. The user row
	// is locked before challenge rows to match account deletion and confirmation;
	// this avoids both uniqueness-based enumeration and lock-order deadlocks.
	email, err := lockPasswordResetUser(ctx, tx, challenge.UserID)
	if err != nil {
		return err
	}
	var delivery *domain.MailDelivery
	if buildMail != nil {
		built, err := buildMail(email)
		if err != nil {
			return err
		}
		if err := validateMailDelivery(built, domain.MailDeliveryPasswordReset, challenge.ID); err != nil {
			return err
		}
		delivery = &built
	}
	if _, err := tx.Exec(ctx, `
		WITH replaced AS (
			UPDATE password_reset_challenges SET consumed_at=now()
			WHERE user_id=$1 AND consumed_at IS NULL
			RETURNING id
		)
		UPDATE mail_deliveries AS delivery
		SET status='canceled',locked_until=NULL,lease_token=NULL,
			canceled_at=now(),updated_at=now(),last_error_class='superseded'
		WHERE delivery.status='pending'
		  AND delivery.password_reset_challenge_id IN (SELECT id FROM replaced)`,
		challenge.UserID); err != nil {
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
	if delivery != nil {
		if err := insertMailDelivery(ctx, tx, *delivery); err != nil {
			return err
		}
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
	completion, err := s.consumePasswordResetChallenge(ctx, id, codeHash, newPasswordHash, maxAttempts, nil, nil)
	return completion.Email, err
}

func (s *Store) ConsumePasswordResetChallengeWithMail(
	ctx context.Context,
	id uuid.UUID,
	codeHash []byte,
	newPasswordHash string,
	maxAttempts int,
	buildMail store.MailDeliveryBuilder,
) (store.PasswordResetCompletion, error) {
	if buildMail == nil {
		return store.PasswordResetCompletion{}, domain.ErrInvalid
	}
	return s.consumePasswordResetChallenge(
		ctx, id, codeHash, newPasswordHash, maxAttempts, buildMail, nil,
	)
}

func (s *Store) ConsumePasswordResetChallengeWithMailAndFence(
	ctx context.Context, id uuid.UUID, codeHash []byte, newPasswordHash string,
	maxAttempts int, buildMail store.MailDeliveryBuilder, fence store.PasswordResetFence,
) (store.PasswordResetCompletion, error) {
	if buildMail == nil || fence == nil {
		return store.PasswordResetCompletion{}, domain.ErrInvalid
	}
	return s.consumePasswordResetChallenge(ctx, id, codeHash, newPasswordHash, maxAttempts, buildMail, fence)
}

func (s *Store) consumePasswordResetChallenge(
	ctx context.Context,
	id uuid.UUID,
	codeHash []byte,
	newPasswordHash string,
	maxAttempts int,
	buildMail store.MailDeliveryBuilder,
	fence store.PasswordResetFence,
) (store.PasswordResetCompletion, error) {
	// Read only the owner needed to choose the per-user lock. Do not lock the
	// challenge first: account deletion locks users before its cleanup trigger
	// deletes reset rows, and the opposite order can deadlock.
	var userID uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		SELECT user_id FROM password_reset_challenges WHERE id=$1`, id,
	).Scan(&userID); errors.Is(err, pgx.ErrNoRows) {
		return store.PasswordResetCompletion{}, domain.ErrUnauthenticated
	} else if err != nil {
		return store.PasswordResetCompletion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.PasswordResetCompletion{}, err
	}
	defer tx.Rollback(ctx)
	email, err := lockPasswordResetUser(ctx, tx, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return store.PasswordResetCompletion{}, domain.ErrUnauthenticated
	}
	if err != nil {
		return store.PasswordResetCompletion{}, err
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
		return store.PasswordResetCompletion{}, domain.ErrUnauthenticated
	}
	if err != nil {
		return store.PasswordResetCompletion{}, err
	}
	now := time.Now().UTC()
	if consumedAt != nil || !expiresAt.After(now) || attempts >= maxAttempts {
		return store.PasswordResetCompletion{}, domain.ErrUnauthenticated
	}
	if len(expectedHash) != len(codeHash) ||
		subtle.ConstantTimeCompare(expectedHash, codeHash) != 1 {
		if _, err := tx.Exec(ctx, `
			UPDATE password_reset_challenges SET attempts=attempts+1 WHERE id=$1`, id); err != nil {
			return store.PasswordResetCompletion{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return store.PasswordResetCompletion{}, err
		}
		return store.PasswordResetCompletion{}, domain.ErrUnauthenticated
	}
	var delivery *domain.MailDelivery
	if buildMail != nil {
		built, err := buildMail(email)
		if err != nil {
			return store.PasswordResetCompletion{}, err
		}
		if err := validateMailDelivery(built, domain.MailDeliveryPasswordChanged, id); err != nil {
			return store.PasswordResetCompletion{}, err
		}
		delivery = &built
	}
	if fence != nil {
		if err := fence(userID); err != nil {
			return store.PasswordResetCompletion{}, err
		}
	}
	// Once a reset code is consumed, any still-pending copy of that code must
	// never leave the queue. A concurrently leased worker will lose its lease
	// acknowledgement if this update wins; provider acceptance before the commit
	// cannot be recalled, but the code is already single-use at that point.
	if _, err := tx.Exec(ctx, `
			UPDATE mail_deliveries
			SET status='canceled',locked_until=NULL,lease_token=NULL,
				canceled_at=now(),updated_at=now(),last_error_class='challenge_consumed'
			WHERE password_reset_challenge_id=$1
			  AND purpose='password_reset' AND status='pending'`, id); err != nil {
		return store.PasswordResetCompletion{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET password_hash=$2,updated_at=$3 WHERE id=$1`,
		userID, newPasswordHash, now); err != nil {
		return store.PasswordResetCompletion{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions SET revoked_at=$2
		WHERE user_id=$1 AND revoked_at IS NULL`, userID, now); err != nil {
		return store.PasswordResetCompletion{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET push_token='' WHERE user_id=$1`, userID); err != nil {
		return store.PasswordResetCompletion{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE password_reset_challenges SET consumed_at=$2
		WHERE user_id=$1 AND consumed_at IS NULL`, userID, now); err != nil {
		return store.PasswordResetCompletion{}, err
	}
	if delivery != nil {
		if err := insertMailDelivery(ctx, tx, *delivery); err != nil {
			return store.PasswordResetCompletion{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return store.PasswordResetCompletion{}, err
	}
	return store.PasswordResetCompletion{UserID: userID, Email: email}, nil
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
