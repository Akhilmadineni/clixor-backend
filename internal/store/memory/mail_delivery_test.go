package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestMailDeliveryLifecycleIsLeasedRetriedDeadLetteredAndPruned(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "mail-lifecycle@example.com", PasswordHash: "existing-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: user.ID, CodeHash: []byte("hash"),
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	deliveryID := uuid.New()
	if err := persistence.CreatePasswordResetChallengeWithMail(
		ctx, challenge, func(email string) (domain.MailDelivery, error) {
			if email != user.Email {
				t.Fatalf("builder email=%q want locked email %q", email, user.Email)
			}
			return testMailDelivery(deliveryID, challenge.ID, domain.MailDeliveryPasswordReset), nil
		},
	); err != nil {
		t.Fatal(err)
	}

	claimed, err := persistence.LockMailDeliveryBatch(ctx, 1)
	if err != nil || len(claimed) != 1 || claimed[0].Attempts != 1 || claimed[0].LeaseToken == uuid.Nil {
		t.Fatalf("first claim=%+v err=%v", claimed, err)
	}
	if err := persistence.FinishMailDelivery(
		ctx, deliveryID, uuid.New(), domain.MailDeliveryPending, time.Now(), "network",
	); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("wrong lease returned %v, want conflict", err)
	}
	if err := persistence.FinishMailDelivery(
		ctx, deliveryID, claimed[0].LeaseToken, domain.MailDeliveryPending,
		time.Now().UTC().Add(-time.Second), "network",
	); err != nil {
		t.Fatal(err)
	}
	retry, err := persistence.LockMailDeliveryBatch(ctx, 1)
	if err != nil || len(retry) != 1 || retry[0].Attempts != 2 {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	if err := persistence.FinishMailDelivery(
		ctx, deliveryID, retry[0].LeaseToken, domain.MailDeliveryDeadLetter,
		time.Time{}, "smtp_rejected",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ConsumePasswordResetChallenge(
		ctx, challenge.ID, challenge.CodeHash, "replacement", 5,
	); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("dead-lettered reset remained usable: %v", err)
	}
	deleted, err := persistence.PruneMailDeliveries(
		ctx, time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(time.Hour),
		time.Now().UTC().Add(time.Hour), 1,
	)
	if err != nil || deleted != 1 {
		t.Fatalf("prune deleted=%d err=%v", deleted, err)
	}
}

func TestMailDeliveryLeaseSerializesAccountErasure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "mail-erasure@example.com", PasswordHash: "existing-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: user.ID, CodeHash: []byte("hash"),
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	deliveryID := uuid.New()
	if err := persistence.CreatePasswordResetChallengeWithMail(
		ctx, challenge, func(string) (domain.MailDelivery, error) {
			return testMailDelivery(deliveryID, challenge.ID, domain.MailDeliveryPasswordReset), nil
		},
	); err != nil {
		t.Fatal(err)
	}
	batch, err := persistence.LockMailDeliveryBatch(ctx, 1)
	if err != nil || len(batch) != 1 {
		t.Fatalf("claim mail: batch=%+v err=%v", batch, err)
	}
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	deliveryDone := make(chan error, 1)
	go func() {
		deliveryDone <- persistence.WithMailDeliveryLease(
			ctx, deliveryID, batch[0].LeaseToken,
			func(callbackContext context.Context, leased domain.MailDelivery) error {
				if leased.ID != deliveryID {
					return errors.New("wrong mail lease row")
				}
				close(callbackStarted)
				select {
				case <-callbackContext.Done():
					return callbackContext.Err()
				case <-releaseCallback:
					return nil
				}
			},
		)
	}()
	<-callbackStarted
	deletionDone := make(chan error, 1)
	go func() { deletionDone <- persistence.DeleteAccount(ctx, user.ID) }()
	select {
	case err := <-deletionDone:
		t.Fatalf("account erasure crossed active mail callback: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseCallback)
	if err := <-deliveryDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deletionDone; err != nil {
		t.Fatal(err)
	}
	called := false
	err = persistence.WithMailDeliveryLease(
		ctx, deliveryID, batch[0].LeaseToken,
		func(context.Context, domain.MailDelivery) error { called = true; return nil },
	)
	if !errors.Is(err, domain.ErrNotFound) || called {
		t.Fatalf("mail after erasure: called=%t err=%v", called, err)
	}
}

func TestMailDeliverySuppressesExpiredConsumedAndSupersededResetCodes(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "mail-suppress@example.com", PasswordHash: "existing-hash",
	})
	if err != nil {
		t.Fatal(err)
	}

	expired := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: user.ID, CodeHash: []byte("expired"),
		ExpiresAt: time.Now().UTC().Add(-time.Minute), CreatedAt: time.Now().UTC(),
	}
	expiredDelivery := uuid.New()
	if err := persistence.CreatePasswordResetChallengeWithMail(
		ctx, expired, func(string) (domain.MailDelivery, error) {
			return testMailDelivery(expiredDelivery, expired.ID, domain.MailDeliveryPasswordReset), nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if claimed, err := persistence.LockMailDeliveryBatch(ctx, 10); err != nil || len(claimed) != 0 {
		t.Fatalf("expired reset mail was claimed: %+v err=%v", claimed, err)
	}
	if got := persistence.mailDeliveries[expiredDelivery].Status; got != domain.MailDeliveryCanceled {
		t.Fatalf("expired reset status=%q", got)
	}

	active := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: user.ID, CodeHash: []byte("active"),
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	activeDelivery := uuid.New()
	if err := persistence.CreatePasswordResetChallengeWithMail(
		ctx, active, func(string) (domain.MailDelivery, error) {
			return testMailDelivery(activeDelivery, active.ID, domain.MailDeliveryPasswordReset), nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ConsumePasswordResetChallenge(
		ctx, active.ID, active.CodeHash, "replacement-hash", 5,
	); err != nil {
		t.Fatal(err)
	}
	if claimed, err := persistence.LockMailDeliveryBatch(ctx, 10); err != nil || len(claimed) != 0 {
		t.Fatalf("consumed reset mail was claimed: %+v err=%v", claimed, err)
	}
	if got := persistence.mailDeliveries[activeDelivery].Status; got != domain.MailDeliveryCanceled {
		t.Fatalf("consumed reset status=%q", got)
	}
}

func TestPasswordMutationAndChangedMailAreAtomic(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "mail-atomic@example.com", PasswordHash: "old-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: user.ID, CodeHash: []byte("correct"),
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreatePasswordResetChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	sealErr := errors.New("local seal failed")
	if _, err := persistence.ConsumePasswordResetChallengeWithMail(
		ctx, challenge.ID, challenge.CodeHash, "new-hash", 5,
		func(string) (domain.MailDelivery, error) { return domain.MailDelivery{}, sealErr },
	); !errors.Is(err, sealErr) {
		t.Fatalf("seal failure returned %v", err)
	}
	unchanged, err := persistence.UserByID(ctx, user.ID)
	if err != nil || unchanged.PasswordHash != "old-hash" {
		t.Fatalf("password changed without notification enqueue: user=%+v err=%v", unchanged, err)
	}
	if persistence.passwordResets[challenge.ID].ConsumedAt != nil {
		t.Fatal("challenge consumed without password-changed mail")
	}
	barrierErr := errors.New("missing replica acknowledgement")
	if _, err := persistence.ConsumePasswordResetChallengeWithMailAndFence(
		ctx, challenge.ID, challenge.CodeHash, "new-hash", 5,
		func(string) (domain.MailDelivery, error) {
			return testMailDelivery(uuid.New(), challenge.ID, domain.MailDeliveryPasswordChanged), nil
		},
		func(got uuid.UUID) error {
			if got != user.ID {
				t.Fatalf("barrier user=%s want %s", got, user.ID)
			}
			return barrierErr
		},
	); !errors.Is(err, barrierErr) {
		t.Fatalf("barrier failure returned %v", err)
	}
	unchanged, err = persistence.UserByID(ctx, user.ID)
	if err != nil || unchanged.PasswordHash != "old-hash" || persistence.passwordResets[challenge.ID].ConsumedAt != nil {
		t.Fatalf("barrier failure mutated reset state: user=%+v challenge=%+v err=%v", unchanged, persistence.passwordResets[challenge.ID], err)
	}

	changedDelivery := uuid.New()
	completion, err := persistence.ConsumePasswordResetChallengeWithMail(
		ctx, challenge.ID, challenge.CodeHash, "new-hash", 5,
		func(email string) (domain.MailDelivery, error) {
			if email != user.Email {
				t.Fatalf("changed-mail email=%q want %q", email, user.Email)
			}
			return testMailDelivery(changedDelivery, challenge.ID, domain.MailDeliveryPasswordChanged), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if completion.UserID != user.ID || completion.Email != user.Email {
		t.Fatalf("reset completion identity=%+v, want user=%s email=%q", completion, user.ID, user.Email)
	}
	changed, err := persistence.UserByID(ctx, user.ID)
	if err != nil || changed.PasswordHash != "new-hash" {
		t.Fatalf("atomic mutation failed: user=%+v err=%v", changed, err)
	}
	if got := persistence.mailDeliveries[changedDelivery].Status; got != domain.MailDeliveryPending {
		t.Fatalf("password-changed delivery status=%q", got)
	}
}

func testMailDelivery(id, challengeID uuid.UUID, purpose string) domain.MailDelivery {
	now := time.Now().UTC()
	return domain.MailDelivery{
		ID: id, ChallengeID: challengeID, Purpose: purpose,
		Ciphertext: make([]byte, 29), Status: domain.MailDeliveryPending,
		NextAttemptAt: now, CreatedAt: now,
	}
}
