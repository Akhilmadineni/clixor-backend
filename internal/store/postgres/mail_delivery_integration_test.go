package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresMailClaimsNeverReturnExpiredOrConsumedResetCodes(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(persistence.Close)

	type fixture struct {
		userID, challengeID, deliveryID uuid.UUID
	}
	createFixture := func(label string, expiresAt time.Time) fixture {
		user, createErr := persistence.CreateUser(ctx, store.CreateUserParams{
			Email: label + "-" + uuid.NewString() + "@example.com", PasswordHash: "existing-hash",
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		t.Cleanup(func() {
			_, _ = persistence.pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, user.ID)
		})
		challenge := domain.PasswordResetChallenge{
			ID: uuid.New(), UserID: user.ID, CodeHash: bytes.Repeat([]byte{0x42}, 32),
			ExpiresAt: expiresAt, CreatedAt: time.Now().UTC(),
		}
		deliveryID := uuid.New()
		if createErr := persistence.CreatePasswordResetChallengeWithMail(
			ctx, challenge, func(string) (domain.MailDelivery, error) {
				return postgresTestMailDelivery(
					deliveryID, challenge.ID, domain.MailDeliveryPasswordReset,
				), nil
			},
		); createErr != nil {
			t.Fatal(createErr)
		}
		return fixture{userID: user.ID, challengeID: challenge.ID, deliveryID: deliveryID}
	}

	expired := createFixture("mail-expired", time.Now().UTC().Add(-time.Minute))
	consumed := createFixture("mail-consumed", time.Now().UTC().Add(time.Hour))
	active := createFixture("mail-active", time.Now().UTC().Add(time.Hour))
	if _, err := persistence.pool.Exec(ctx, `
		UPDATE password_reset_challenges SET consumed_at=now() WHERE id=$1`, consumed.challengeID,
	); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	claimed := make(chan domain.MailDelivery, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	for range 2 {
		go func() {
			defer workers.Done()
			<-start
			batch, lockErr := persistence.LockMailDeliveryBatch(ctx, 10)
			if lockErr != nil {
				t.Errorf("lock mail delivery: %v", lockErr)
				return
			}
			for _, delivery := range batch {
				claimed <- delivery
			}
		}()
	}
	close(start)
	workers.Wait()
	close(claimed)
	var got []domain.MailDelivery
	for delivery := range claimed {
		got = append(got, delivery)
	}
	if len(got) != 1 || got[0].ID != active.deliveryID || got[0].Attempts != 1 {
		t.Fatalf("concurrent claims returned %+v, want only active delivery %s", got, active.deliveryID)
	}
	for _, inactive := range []fixture{expired, consumed} {
		var status string
		if err := persistence.pool.QueryRow(ctx, `
			SELECT status FROM mail_deliveries WHERE id=$1`, inactive.deliveryID,
		).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != domain.MailDeliveryCanceled {
			t.Fatalf("inactive delivery %s status=%q", inactive.deliveryID, status)
		}
	}
}

func TestPostgresPasswordChangedMailCascadesWithResetChallenge(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(persistence.Close)
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "mail-cascade-" + uuid.NewString() + "@example.com", PasswordHash: "old-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = persistence.pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, user.ID)
	})
	challenge := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: user.ID, CodeHash: bytes.Repeat([]byte{0x24}, 32),
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreatePasswordResetChallengeWithMail(
		ctx, challenge, func(string) (domain.MailDelivery, error) {
			return postgresTestMailDelivery(
				uuid.New(), challenge.ID, domain.MailDeliveryPasswordReset,
			), nil
		},
	); err != nil {
		t.Fatal(err)
	}
	sealErr := errors.New("local seal failed")
	if _, err := persistence.ConsumePasswordResetChallengeWithMail(
		ctx, challenge.ID, challenge.CodeHash, "must-not-commit", 5,
		func(string) (domain.MailDelivery, error) { return domain.MailDelivery{}, sealErr },
	); !errors.Is(err, sealErr) {
		t.Fatalf("failed changed-mail seal returned %v", err)
	}
	unchanged, err := persistence.UserByID(ctx, user.ID)
	if err != nil || unchanged.PasswordHash != "old-hash" {
		t.Fatalf("password mutation escaped failed mail transaction: user=%+v err=%v", unchanged, err)
	}
	var consumedAt *time.Time
	if err := persistence.pool.QueryRow(ctx, `
		SELECT consumed_at FROM password_reset_challenges WHERE id=$1`, challenge.ID,
	).Scan(&consumedAt); err != nil || consumedAt != nil {
		t.Fatalf("challenge consumed after failed mail transaction: consumed=%v err=%v", consumedAt, err)
	}
	changedID := uuid.New()
	completion, err := persistence.ConsumePasswordResetChallengeWithMail(
		ctx, challenge.ID, challenge.CodeHash, "new-hash", 5,
		func(email string) (domain.MailDelivery, error) {
			if email != user.Email {
				t.Fatalf("password-changed recipient=%q want %q", email, user.Email)
			}
			return postgresTestMailDelivery(
				changedID, challenge.ID, domain.MailDeliveryPasswordChanged,
			), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if completion.UserID != user.ID || completion.Email != user.Email {
		t.Fatalf("reset completion identity=%+v, want user=%s email=%q", completion, user.ID, user.Email)
	}
	var changedCount int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*) FROM mail_deliveries
		WHERE password_reset_challenge_id=$1 AND purpose='password_changed'`, challenge.ID,
	).Scan(&changedCount); err != nil || changedCount != 1 {
		t.Fatalf("password-changed delivery count=%d err=%v", changedCount, err)
	}
	if _, err := persistence.pool.Exec(ctx, `DELETE FROM password_reset_challenges WHERE id=$1`, challenge.ID); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*) FROM mail_deliveries WHERE password_reset_challenge_id=$1`, challenge.ID,
	).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("challenge deletion left %d mail rows: %v", remaining, err)
	}
}

func postgresTestMailDelivery(id, challengeID uuid.UUID, purpose string) domain.MailDelivery {
	now := time.Now().UTC()
	return domain.MailDelivery{
		ID: id, ChallengeID: challengeID, Purpose: purpose,
		Ciphertext: bytes.Repeat([]byte{0x77}, 29), Status: domain.MailDeliveryPending,
		NextAttemptAt: now, CreatedAt: now,
	}
}
