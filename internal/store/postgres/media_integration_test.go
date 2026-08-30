package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresMediaQuotasExpiryAndConversationDeletion(t *testing.T) {
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
	defer persistence.Close()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-media-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	limits := store.DefaultMediaReservationLimits()
	limits.MaxPendingCountPerUser = 1
	limits.MaxPendingCountConversation = 1

	const attempts = 8
	start := make(chan struct{})
	var wait sync.WaitGroup
	var created atomic.Int32
	var quotaRejected atomic.Int32
	var createdID atomic.Value
	for index := 0; index < attempts; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			object := postgresTestMedia(user.ID, conversation.ID)
			if _, err := persistence.CreateMedia(ctx, object, limits); err == nil {
				created.Add(1)
				createdID.Store(object.ID)
			} else if errors.Is(err, domain.ErrQuotaExceeded) {
				quotaRejected.Add(1)
			} else {
				t.Errorf("create media: %v", err)
			}
		}()
	}
	close(start)
	wait.Wait()
	if created.Load() != 1 || quotaRejected.Load() != attempts-1 {
		t.Fatalf("created=%d quota_rejected=%d", created.Load(), quotaRejected.Load())
	}
	winningID, ok := createdID.Load().(uuid.UUID)
	if !ok {
		t.Fatal("winning media reservation ID was not recorded")
	}
	expiringClaim, err := persistence.ClaimMediaVerification(ctx, winningID, user.ID, time.Minute)
	if err != nil || expiringClaim.VerificationLeaseToken == nil {
		t.Fatalf("claim media before expiry sweep: media=%+v error=%v", expiringClaim, err)
	}
	if _, err := persistence.pool.Exec(ctx, `
		UPDATE media_objects SET expires_at=now()-interval '1 second' WHERE id=$1`, winningID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ExpirePendingMedia(ctx, time.Now().UTC(), store.MediaDeleteBatchSize); err != nil {
		t.Fatal(err)
	}
	var expiredStatus string
	var expiredToken *uuid.UUID
	var expiredLock *time.Time
	if err := persistence.pool.QueryRow(ctx, `
		SELECT status,verification_lease_token,verification_locked_until
		FROM media_objects WHERE id=$1`, winningID,
	).Scan(&expiredStatus, &expiredToken, &expiredLock); err != nil || expiredStatus != "deleted" ||
		expiredToken != nil || expiredLock != nil {
		t.Fatalf("expired status=%q token=%v lock=%v err=%v", expiredStatus, expiredToken, expiredLock, err)
	}

	storedConversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	storedLimits := store.DefaultMediaReservationLimits()
	storedLimits.MaxStoredCountPerUser = 1
	storedLimits.MaxStoredBytesPerUser = 3
	storedLimits.MaxStoredCountConversation = 1
	storedLimits.MaxStoredBytesConversation = 3
	storedLimits.MaxPendingCountPerUser = 1
	storedLimits.MaxPendingCountConversation = 1
	storedLimits.MaxPendingBytesPerUser = 3
	storedLimits.MaxPendingBytesConversation = 3
	ready := postgresTestMedia(user.ID, storedConversation.ID)
	if _, err := persistence.CreateMedia(ctx, ready, storedLimits); err != nil {
		t.Fatal(err)
	}
	claim, err := persistence.ClaimMediaVerification(ctx, ready.ID, user.ID, time.Minute)
	if err != nil || claim.VerificationLeaseToken == nil {
		t.Fatalf("claim media verification: media=%+v error=%v", claim, err)
	}
	if _, err := persistence.MarkMediaReady(
		ctx, ready.ID, user.ID, *claim.VerificationLeaseToken,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMedia(
		ctx, postgresTestMedia(user.ID, storedConversation.ID), storedLimits,
	); !errors.Is(err, domain.ErrQuotaExceeded) {
		t.Fatalf("ready object did not consume stored quota: %v", err)
	}
	if _, err := persistence.DeleteMedia(ctx, ready.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMedia(
		ctx, postgresTestMedia(user.ID, storedConversation.ID), storedLimits,
	); err != nil {
		t.Fatalf("deleted object did not release stored quota: %v", err)
	}

	fenced := postgresTestMedia(user.ID, storedConversation.ID)
	if _, err := persistence.CreateMedia(ctx, fenced, store.DefaultMediaReservationLimits()); err != nil {
		t.Fatal(err)
	}
	const claimers = 8
	claimResults := make(chan domain.MediaObject, claimers)
	claimErrors := make(chan error, claimers)
	startClaims := make(chan struct{})
	wait = sync.WaitGroup{}
	for range claimers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-startClaims
			claimed, claimErr := persistence.ClaimMediaVerification(ctx, fenced.ID, user.ID, time.Minute)
			claimResults <- claimed
			claimErrors <- claimErr
		}()
	}
	close(startClaims)
	wait.Wait()
	close(claimResults)
	close(claimErrors)
	var winningClaim domain.MediaObject
	claimSuccesses := 0
	for claimed := range claimResults {
		if claimed.VerificationLeaseToken != nil {
			winningClaim = claimed
		}
	}
	for claimErr := range claimErrors {
		if claimErr == nil {
			claimSuccesses++
		} else if !errors.Is(claimErr, domain.ErrConflict) {
			t.Fatalf("unexpected concurrent claim error: %v", claimErr)
		}
	}
	if claimSuccesses != 1 || winningClaim.VerificationLeaseToken == nil {
		t.Fatalf("claim successes=%d winner=%+v", claimSuccesses, winningClaim)
	}
	staleToken := *winningClaim.VerificationLeaseToken
	if _, err := persistence.pool.Exec(ctx, `
		UPDATE media_objects SET verification_locked_until=now()-interval '1 second' WHERE id=$1`,
		fenced.ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := persistence.ClaimMediaVerification(ctx, fenced.ID, user.ID, time.Minute)
	if err != nil || reclaimed.VerificationLeaseToken == nil || *reclaimed.VerificationLeaseToken == staleToken {
		t.Fatalf("reclaim media: media=%+v error=%v", reclaimed, err)
	}
	if _, err := persistence.MarkMediaReady(ctx, fenced.ID, user.ID, staleToken); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale completion returned %v", err)
	}
	if _, err := persistence.MarkMediaReady(
		ctx, fenced.ID, user.ID, *reclaimed.VerificationLeaseToken,
	); err != nil {
		t.Fatal(err)
	}
	idempotent, err := persistence.ClaimMediaVerification(ctx, fenced.ID, user.ID, time.Minute)
	if err != nil || idempotent.Status != "ready" || idempotent.VerificationLeaseToken != nil {
		t.Fatalf("idempotent ready claim: media=%+v error=%v", idempotent, err)
	}

	deletionConversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := postgresTestMedia(user.ID, deletionConversation.ID)
	second := postgresTestMedia(user.ID, deletionConversation.ID)
	if _, err := persistence.CreateMedia(ctx, first, store.DefaultMediaReservationLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMedia(ctx, second, store.DefaultMediaReservationLimits()); err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteConversation(ctx, deletionConversation.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*) FROM media_objects WHERE conversation_id=$1`, deletionConversation.ID,
	).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("conversation media rows=%d err=%v", remaining, err)
	}
	queued := postgresMediaDeletionKeys(t, ctx, persistence)
	for _, key := range []string{first.ObjectKey, second.ObjectKey} {
		if _, found := queued[key]; !found {
			t.Fatalf("object key %q was not durably queued: %v", key, queued)
		}
	}
}

func postgresTestMedia(ownerID, conversationID uuid.UUID) domain.MediaObject {
	id := uuid.New()
	return domain.MediaObject{
		ID: id, OwnerID: ownerID, ConversationID: conversationID,
		ObjectKey:   "integration/" + conversationID.String() + "/" + id.String(),
		ContentType: "application/octet-stream", ByteSize: 3,
		CiphertextSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
}

func postgresMediaDeletionKeys(t *testing.T, ctx context.Context, persistence *Store) map[string]struct{} {
	t.Helper()
	rows, err := persistence.pool.Query(ctx, `
		SELECT payload FROM outbox_events WHERE topic='media.delete' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := make(map[string]struct{})
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var payload store.MediaDeletePayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		for _, key := range payload.ObjectKeys {
			result[key] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}
