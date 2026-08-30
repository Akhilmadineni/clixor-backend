package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const mailDeliveryLease = 2 * time.Minute

func validateMailDelivery(
	delivery domain.MailDelivery,
	purpose string,
	challengeID uuid.UUID,
) error {
	if delivery.ID == uuid.Nil || delivery.ChallengeID != challengeID ||
		delivery.Purpose != purpose || len(delivery.Ciphertext) < 29 {
		return domain.ErrInvalid
	}
	return nil
}

func insertMailDelivery(ctx context.Context, tx pgx.Tx, delivery domain.MailDelivery) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO mail_deliveries(
			id,password_reset_challenge_id,purpose,encrypted_payload,
			status,next_attempt_at,created_at,updated_at
		) VALUES($1,$2,$3,$4,'pending',$5,$6,$6)`,
		delivery.ID, delivery.ChallengeID, delivery.Purpose, delivery.Ciphertext,
		delivery.NextAttemptAt, delivery.CreatedAt)
	return mapError(err)
}

func (s *Store) LockMailDeliveryBatch(
	ctx context.Context,
	limit int,
) ([]domain.MailDelivery, error) {
	if limit < 1 || limit > store.MaxRetentionPruneBatchSize {
		return nil, domain.ErrInvalid
	}
	leaseToken := uuid.New()
	rows, err := s.pool.Query(ctx, `
		WITH canceled AS (
			UPDATE mail_deliveries AS delivery
			SET status='canceled',locked_until=NULL,lease_token=NULL,
				canceled_at=now(),updated_at=now(),last_error_class='challenge_inactive'
			FROM password_reset_challenges AS challenge
			WHERE delivery.password_reset_challenge_id=challenge.id
			  AND delivery.purpose='password_reset'
			  AND delivery.status='pending'
			  AND (challenge.consumed_at IS NOT NULL OR challenge.expires_at<=now())
			RETURNING delivery.id
		), selected AS (
			SELECT id
			FROM mail_deliveries
				WHERE status='pending'
				  AND next_attempt_at<=now()
				  AND (locked_until IS NULL OR locked_until<now())
				  AND (
					purpose<>'password_reset'
					OR EXISTS (
						SELECT 1 FROM password_reset_challenges AS active_challenge
						WHERE active_challenge.id=mail_deliveries.password_reset_challenge_id
						  AND active_challenge.consumed_at IS NULL
						  AND active_challenge.expires_at>now()
					)
				  )
			ORDER BY next_attempt_at,id
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		), claimed AS (
			UPDATE mail_deliveries AS delivery
			SET locked_until=now()+$3::interval,lease_token=$2,
				attempts=attempts+1,updated_at=now()
			FROM selected
			WHERE delivery.id=selected.id
			RETURNING delivery.*
		)
		SELECT id,password_reset_challenge_id,purpose,encrypted_payload,status,
			attempts,next_attempt_at,lease_token,locked_until,created_at,
			delivered_at,dead_lettered_at,canceled_at,last_error_class
		FROM claimed
		ORDER BY next_attempt_at,id`, limit, leaseToken, mailDeliveryLease.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := make([]domain.MailDelivery, 0, limit)
	for rows.Next() {
		var delivery domain.MailDelivery
		if err := rows.Scan(
			&delivery.ID, &delivery.ChallengeID, &delivery.Purpose,
			&delivery.Ciphertext, &delivery.Status, &delivery.Attempts,
			&delivery.NextAttemptAt, &delivery.LeaseToken, &delivery.LockedUntil,
			&delivery.CreatedAt, &delivery.DeliveredAt, &delivery.DeadLetteredAt,
			&delivery.CanceledAt, &delivery.LastErrorClass,
		); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

func (s *Store) FinishMailDelivery(
	ctx context.Context,
	id uuid.UUID,
	leaseToken uuid.UUID,
	result string,
	nextAttemptAt time.Time,
	errorClass string,
) error {
	switch result {
	case domain.MailDeliveryPending, domain.MailDeliveryDelivered,
		domain.MailDeliveryDeadLetter, domain.MailDeliveryCanceled:
	default:
		return domain.ErrInvalid
	}
	if id == uuid.Nil || leaseToken == uuid.Nil || !validMailErrorClass(errorClass) {
		return domain.ErrInvalid
	}
	if nextAttemptAt.IsZero() {
		nextAttemptAt = time.Now().UTC()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var challengeID uuid.UUID
	var purpose string
	err = tx.QueryRow(ctx, `
		UPDATE mail_deliveries
		SET status=$3,
			next_attempt_at=CASE WHEN $3='pending' THEN $4 ELSE next_attempt_at END,
			locked_until=NULL,lease_token=NULL,last_error_class=$5,updated_at=now(),
			delivered_at=CASE WHEN $3='delivered' THEN now() ELSE NULL END,
			dead_lettered_at=CASE WHEN $3='dead_letter' THEN now() ELSE NULL END,
			canceled_at=CASE WHEN $3='canceled' THEN now() ELSE NULL END
		WHERE id=$1 AND status='pending' AND lease_token=$2
		RETURNING password_reset_challenge_id,purpose`,
		id, leaseToken, result, nextAttemptAt, errorClass,
	).Scan(&challengeID, &purpose)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrConflict
	}
	if err != nil {
		return mapError(err)
	}
	if result == domain.MailDeliveryDeadLetter && purpose == domain.MailDeliveryPasswordReset {
		if _, err := tx.Exec(ctx, `
			UPDATE password_reset_challenges SET consumed_at=COALESCE(consumed_at,now())
			WHERE id=$1`, challengeID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) PruneMailDeliveries(
	ctx context.Context,
	deliveredBefore, deadLetterBefore, canceledBefore time.Time,
	limit int,
) (int64, error) {
	if limit < 1 || limit > store.MaxRetentionPruneBatchSize {
		return 0, domain.ErrInvalid
	}
	tag, err := s.pool.Exec(ctx, `
		WITH candidates AS (
			SELECT id
			FROM mail_deliveries
			WHERE (status='delivered' AND delivered_at<$1)
			   OR (status='dead_letter' AND dead_lettered_at<$2)
			   OR (status='canceled' AND canceled_at<$3)
			ORDER BY COALESCE(delivered_at,dead_lettered_at,canceled_at),id
			FOR UPDATE SKIP LOCKED
			LIMIT $4
		)
		DELETE FROM mail_deliveries AS delivery
		USING candidates
		WHERE delivery.id=candidates.id`,
		deliveredBefore, deadLetterBefore, canceledBefore, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func validMailErrorClass(value string) bool {
	if len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && character != '_' {
			return false
		}
	}
	return strings.TrimSpace(value) == value
}
