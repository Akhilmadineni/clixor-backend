package memory

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestMediaReservationsEnforceUserAndConversationQuotas(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "media-quota@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	firstConversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondConversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	limits := store.MediaReservationLimits{
		PendingTTL: time.Minute, MaxPendingCountPerUser: 2, MaxPendingBytesPerUser: 9,
		MaxPendingCountConversation: 1, MaxPendingBytesConversation: 8,
		MaxStoredCountPerUser: 10, MaxStoredBytesPerUser: 100,
		MaxStoredCountConversation: 10, MaxStoredBytesConversation: 100,
	}
	first := testConversationMedia(user.ID, firstConversation.ID, 4)
	if _, err := persistence.CreateMedia(ctx, first, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMedia(
		ctx, testConversationMedia(user.ID, firstConversation.ID, 1), limits,
	); !errors.Is(err, domain.ErrQuotaExceeded) {
		t.Fatalf("conversation count quota returned %v", err)
	}
	profile := testProfileMedia(user.ID, 5)
	if _, err := persistence.CreateProfileMedia(ctx, profile, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMedia(
		ctx, testConversationMedia(user.ID, secondConversation.ID, 1), limits,
	); !errors.Is(err, domain.ErrQuotaExceeded) {
		t.Fatalf("cross-scope user quota returned %v", err)
	}
	if _, err := persistence.RejectPendingMedia(ctx, first.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMedia(
		ctx, testConversationMedia(user.ID, secondConversation.ID, 4), limits,
	); err != nil {
		t.Fatalf("released reservation did not free quota: %v", err)
	}
}

func TestCompletedMediaStillConsumesStoredQuotaUntilDeleted(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "media-stored-quota@example.com"})
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
	limits.MaxStoredCountPerUser = 1
	limits.MaxStoredBytesPerUser = 4
	limits.MaxStoredCountConversation = 1
	limits.MaxStoredBytesConversation = 4
	limits.MaxPendingCountPerUser = 1
	limits.MaxPendingBytesPerUser = 4
	limits.MaxPendingCountConversation = 1
	limits.MaxPendingBytesConversation = 4

	first, err := persistence.CreateMedia(ctx, testConversationMedia(user.ID, conversation.ID, 4), limits)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := persistence.ClaimMediaVerification(ctx, first.ID, user.ID, time.Minute)
	if err != nil || claim.VerificationLeaseToken == nil {
		t.Fatalf("claim media verification: media=%+v error=%v", claim, err)
	}
	if _, err := persistence.MarkMediaReady(
		ctx, first.ID, user.ID, *claim.VerificationLeaseToken, first.ObjectKey,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMedia(
		ctx, testConversationMedia(user.ID, conversation.ID, 1), limits,
	); !errors.Is(err, domain.ErrQuotaExceeded) {
		t.Fatalf("ready object did not consume stored quota: %v", err)
	}
	if _, err := persistence.DeleteMedia(ctx, first.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMedia(
		ctx, testConversationMedia(user.ID, conversation.ID, 1), limits,
	); err != nil {
		t.Fatalf("deleted object did not release stored quota: %v", err)
	}
}

func TestExpiredMediaReservationsQueueDurableDeletion(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "media-expiry@example.com"})
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
	conversationMedia := testConversationMedia(user.ID, conversation.ID, 3)
	profileMedia := testProfileMedia(user.ID, 3)
	first, err := persistence.CreateMedia(ctx, conversationMedia, limits)
	if err != nil {
		t.Fatal(err)
	}
	second, err := persistence.CreateProfileMedia(ctx, profileMedia, limits)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := persistence.ExpirePendingMedia(ctx, time.Now().UTC().Add(10*time.Minute), 500)
	if err != nil || expired != 2 {
		t.Fatalf("expired=%d err=%v", expired, err)
	}
	for _, id := range []uuid.UUID{first.ID, second.ID} {
		if _, err := persistence.Media(ctx, id, user.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expired media %s returned %v", id, err)
		}
	}
	keys := mediaDeletionKeys(t, persistence)
	want := []string{
		conversationMedia.ObjectKey, "published/" + conversationMedia.ObjectKey,
		profileMedia.ObjectKey, "published/" + profileMedia.ObjectKey,
	}
	sort.Strings(want)
	if len(keys) != len(want) {
		t.Fatalf("queued keys=%v want=%v", keys, want)
	}
	for index := range want {
		if keys[index] != want[index] {
			t.Fatalf("queued keys=%v want=%v", keys, want)
		}
	}
}

func TestConversationDeletionQueuesMediaBeforeRowsDisappear(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "conversation-media-delete@example.com"})
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
	first := testConversationMedia(user.ID, conversation.ID, 3)
	second := testConversationMedia(user.ID, conversation.ID, 4)
	if _, err := persistence.CreateMedia(ctx, first, limits); err != nil {
		t.Fatal(err)
	}
	createdSecond, err := persistence.CreateMedia(ctx, second, limits)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := persistence.ClaimMediaVerification(ctx, createdSecond.ID, user.ID, time.Minute)
	if err != nil || claim.VerificationLeaseToken == nil {
		t.Fatalf("claim media verification: media=%+v error=%v", claim, err)
	}
	if _, err := persistence.MarkMediaReady(
		ctx, createdSecond.ID, user.ID, *claim.VerificationLeaseToken, createdSecond.ObjectKey,
	); err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteConversation(ctx, conversation.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, exists := persistence.media[first.ID]; exists {
		t.Fatal("pending media row survived conversation deletion")
	}
	if _, exists := persistence.media[second.ID]; exists {
		t.Fatal("ready media row survived conversation deletion")
	}
	keys := mediaDeletionKeys(t, persistence)
	want := []string{
		first.ObjectKey, "published/" + first.ObjectKey,
		second.ObjectKey, "published/" + second.ObjectKey,
	}
	sort.Strings(want)
	if len(keys) != len(want) {
		t.Fatalf("queued keys=%v want=%v", keys, want)
	}
	for index := range want {
		if keys[index] != want[index] {
			t.Fatalf("queued keys=%v want=%v", keys, want)
		}
	}
}

func TestMediaVerificationClaimIsExclusiveAndFencedAcrossReclaim(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "media-fence@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := persistence.CreateMedia(
		ctx, testConversationMedia(user.ID, conversation.ID, 3), store.DefaultMediaReservationLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}

	const contenders = 24
	results := make(chan error, contenders)
	var workers sync.WaitGroup
	workers.Add(contenders)
	for range contenders {
		go func() {
			defer workers.Done()
			_, claimErr := persistence.ClaimMediaVerification(ctx, created.ID, user.ID, time.Minute)
			results <- claimErr
		}()
	}
	workers.Wait()
	close(results)
	successes := 0
	for claimErr := range results {
		if claimErr == nil {
			successes++
		} else if !errors.Is(claimErr, domain.ErrConflict) {
			t.Fatalf("unexpected claim error: %v", claimErr)
		}
	}
	if successes != 1 {
		t.Fatalf("successful claims=%d, want 1", successes)
	}

	persistence.mu.Lock()
	first := persistence.media[created.ID]
	if first.VerificationLeaseToken == nil {
		persistence.mu.Unlock()
		t.Fatal("winning claim has no fencing token")
	}
	staleToken := *first.VerificationLeaseToken
	expired := time.Now().UTC().Add(-time.Second)
	first.VerificationLockedUntil = &expired
	persistence.media[created.ID] = first
	persistence.mu.Unlock()

	reclaimed, err := persistence.ClaimMediaVerification(ctx, created.ID, user.ID, time.Minute)
	if err != nil || reclaimed.VerificationLeaseToken == nil {
		t.Fatalf("reclaim media: media=%+v error=%v", reclaimed, err)
	}
	if *reclaimed.VerificationLeaseToken == staleToken {
		t.Fatal("reclaim reused the stale fencing token")
	}
	if _, err := persistence.MarkMediaReady(
		ctx, created.ID, user.ID, staleToken, created.ObjectKey,
	); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale completion returned %v", err)
	}
	if _, err := persistence.RejectMediaVerification(ctx, created.ID, user.ID, staleToken); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale rejection returned %v", err)
	}
	ready, err := persistence.MarkMediaReady(
		ctx, created.ID, user.ID, *reclaimed.VerificationLeaseToken, created.ObjectKey,
	)
	if err != nil || ready.Status != "ready" {
		t.Fatalf("current fence completion: media=%+v error=%v", ready, err)
	}
	idempotent, err := persistence.ClaimMediaVerification(ctx, created.ID, user.ID, time.Minute)
	if err != nil || idempotent.Status != "ready" || idempotent.VerificationLeaseToken != nil {
		t.Fatalf("ready claim was not idempotent: media=%+v error=%v", idempotent, err)
	}
}

func TestPublishedProfileMediaAccountDeletionRestoresStagingCleanup(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "published-delete@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := persistence.CreateProfileMedia(
		ctx, testProfileMedia(user.ID, 3), store.DefaultMediaReservationLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.PersistMediaUploadCapability(ctx, created.ID, user.ID, "oci-write-par-id"); err != nil {
		t.Fatal(err)
	}
	if err := persistence.PersistMediaUploadCapability(ctx, created.ID, user.ID, "oci-write-par-id"); err != nil {
		t.Fatalf("idempotent capability persistence: %v", err)
	}
	if err := persistence.PersistMediaUploadCapability(ctx, created.ID, user.ID, "different-par-id"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("capability replacement returned %v", err)
	}
	claim, err := persistence.ClaimMediaVerification(ctx, created.ID, user.ID, time.Minute)
	if err != nil || claim.VerificationLeaseToken == nil {
		t.Fatalf("claim media: media=%+v err=%v", claim, err)
	}
	publishedKey := "published/" + created.ObjectKey
	ready, err := persistence.MarkMediaReady(
		ctx, created.ID, user.ID, *claim.VerificationLeaseToken, publishedKey,
	)
	if err != nil || ready.ObjectKey != publishedKey {
		t.Fatalf("ready media=%+v err=%v", ready, err)
	}
	if capability, err := persistence.MediaUploadCapability(ctx, created.ID, user.ID); err != nil || capability != "" {
		t.Fatalf("ready capability=%q err=%v", capability, err)
	}
	if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
		t.Fatal(err)
	}

	persistence.mu.RLock()
	defer persistence.mu.RUnlock()
	queued := make(map[string]bool)
	for _, event := range persistence.outbox {
		if event.Topic != "media.delete" {
			continue
		}
		var payload store.MediaDeletePayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		for _, key := range payload.ObjectKeys {
			queued[key] = true
		}
	}
	if len(queued) != 2 || !queued[created.ObjectKey] || !queued[publishedKey] {
		t.Fatalf("account deletion keys=%v", queued)
	}
}

func TestFormerMemberDeletionRevokesPendingUploadAndKeepsReadySharedMedia(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	owner, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "media-former-owner@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "media-former-delete@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: owner.ID, MemberIDs: []uuid.UUID{deleted.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := persistence.CreateMedia(
		ctx, testConversationMedia(deleted.ID, conversation.ID, 3), store.DefaultMediaReservationLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.PersistMediaUploadCapability(ctx, pending.ID, deleted.ID, "pending-capability"); err != nil {
		t.Fatal(err)
	}
	ready, err := persistence.CreateMedia(
		ctx, testConversationMedia(deleted.ID, conversation.ID, 3), store.DefaultMediaReservationLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	markMemoryMediaReady(t, ctx, persistence, ready, deleted.ID)
	if err := persistence.RemoveConversationMember(ctx, conversation.ID, owner.ID, deleted.ID); err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.Media(ctx, pending.ID, owner.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("pending former-member media returned %v, want not found", err)
	}
	if _, exists := persistence.mediaUploadCapabilities[pending.ID]; exists {
		t.Fatal("former-member upload capability survived account deletion")
	}
	shared, err := persistence.Media(ctx, ready.ID, owner.ID)
	if err != nil || shared.Status != "ready" {
		t.Fatalf("ready shared media was not retained: media=%+v err=%v", shared, err)
	}
	assertMediaDeleteDeadline(t, persistence, pending.ObjectKey, pending.UploadValidUntil)
}

func TestTransientVerificationReleaseAllowsImmediateRetry(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, _ := persistence.CreateUser(ctx, store.CreateUserParams{Email: "media-release@example.com"})
	conversation, _ := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	created, err := persistence.CreateMedia(
		ctx, testConversationMedia(user.ID, conversation.ID, 3), store.DefaultMediaReservationLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := persistence.ClaimMediaVerification(ctx, created.ID, user.ID, time.Minute)
	if err != nil || first.VerificationLeaseToken == nil {
		t.Fatalf("first claim: media=%+v error=%v", first, err)
	}
	if err := persistence.ReleaseMediaVerification(
		ctx, created.ID, user.ID, *first.VerificationLeaseToken,
	); err != nil {
		t.Fatal(err)
	}
	second, err := persistence.ClaimMediaVerification(ctx, created.ID, user.ID, time.Minute)
	if err != nil || second.VerificationLeaseToken == nil ||
		*second.VerificationLeaseToken == *first.VerificationLeaseToken {
		t.Fatalf("retry claim: first=%+v second=%+v error=%v", first, second, err)
	}
}

func TestReadyMediaDeletionUsesImmutableUploadValidityDeadline(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, _ := persistence.CreateUser(ctx, store.CreateUserParams{Email: "media-delete-deadline@example.com"})
	conversation, _ := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	created, err := persistence.CreateMedia(
		ctx, testConversationMedia(user.ID, conversation.ID, 3), store.DefaultMediaReservationLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := persistence.ClaimMediaVerification(ctx, created.ID, user.ID, time.Minute)
	if err != nil || claim.VerificationLeaseToken == nil {
		t.Fatalf("claim: media=%+v error=%v", claim, err)
	}
	ready, err := persistence.MarkMediaReady(
		ctx, created.ID, user.ID, *claim.VerificationLeaseToken, created.ObjectKey,
	)
	if err != nil || ready.UploadValidUntil.IsZero() || ready.ExpiresAt != nil {
		t.Fatalf("ready media lost immutable upload deadline: media=%+v error=%v", ready, err)
	}
	if _, err := persistence.DeleteMedia(ctx, created.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	events, err := persistence.LockOutboxBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var payload store.MediaDeletePayload
	for _, event := range events {
		if event.Topic == "media.delete" {
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	wantNotBefore := created.UploadValidUntil.Add(store.MediaDeleteGrace)
	if payload.NotBefore == nil || payload.NotBefore.Before(wantNotBefore) {
		t.Fatalf("delete not_before=%v, want >=%s", payload.NotBefore, wantNotBefore)
	}
}

func TestExpirySweepClearsActiveVerificationFence(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, _ := persistence.CreateUser(ctx, store.CreateUserParams{Email: "media-expire-lease@example.com"})
	conversation, _ := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	created, err := persistence.CreateMedia(
		ctx, testConversationMedia(user.ID, conversation.ID, 3), store.DefaultMediaReservationLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ClaimMediaVerification(ctx, created.ID, user.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if count, err := persistence.ExpirePendingMedia(ctx, created.UploadValidUntil.Add(time.Second), 1); err != nil || count != 1 {
		t.Fatalf("expire leased media: count=%d error=%v", count, err)
	}
	persistence.mu.RLock()
	expired := persistence.media[created.ID]
	persistence.mu.RUnlock()
	if expired.Status != "deleted" || expired.VerificationLeaseToken != nil || expired.VerificationLockedUntil != nil {
		t.Fatalf("expiry retained verification fence: %+v", expired)
	}
}

func TestEveryMediaDeletionPathHonorsImmutableUploadValidity(t *testing.T) {
	t.Run("verification rejection", func(t *testing.T) {
		ctx, persistence, user, conversation := newMediaDeletionFixture(t, "reject")
		created, err := persistence.CreateMedia(
			ctx, testConversationMedia(user.ID, conversation.ID, 3), store.DefaultMediaReservationLimits(),
		)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := persistence.ClaimMediaVerification(ctx, created.ID, user.ID, time.Minute)
		if err != nil || claim.VerificationLeaseToken == nil {
			t.Fatalf("claim: media=%+v error=%v", claim, err)
		}
		if _, err := persistence.RejectMediaVerification(
			ctx, created.ID, user.ID, *claim.VerificationLeaseToken,
		); err != nil {
			t.Fatal(err)
		}
		assertMediaDeleteDeadline(t, persistence, created.ObjectKey, created.UploadValidUntil)
	})

	t.Run("avatar replacement", func(t *testing.T) {
		ctx, persistence, user, _ := newMediaDeletionFixture(t, "avatar")
		first, err := persistence.CreateProfileMedia(
			ctx, testProfileMedia(user.ID, 3), store.DefaultMediaReservationLimits(),
		)
		if err != nil {
			t.Fatal(err)
		}
		markMemoryMediaReady(t, ctx, persistence, first, user.ID)
		second, err := persistence.CreateProfileMedia(
			ctx, testProfileMedia(user.ID, 3), store.DefaultMediaReservationLimits(),
		)
		if err != nil {
			t.Fatal(err)
		}
		markMemoryMediaReady(t, ctx, persistence, second, user.ID)
		assertMediaDeleteDeadline(t, persistence, first.ObjectKey, first.UploadValidUntil)
	})

	t.Run("conversation deletion", func(t *testing.T) {
		ctx, persistence, user, conversation := newMediaDeletionFixture(t, "conversation")
		created, err := persistence.CreateMedia(
			ctx, testConversationMedia(user.ID, conversation.ID, 3), store.DefaultMediaReservationLimits(),
		)
		if err != nil {
			t.Fatal(err)
		}
		markMemoryMediaReady(t, ctx, persistence, created, user.ID)
		if err := persistence.DeleteConversation(ctx, conversation.ID, user.ID); err != nil {
			t.Fatal(err)
		}
		assertMediaDeleteDeadline(t, persistence, created.ObjectKey, created.UploadValidUntil)
	})

	t.Run("account deletion", func(t *testing.T) {
		ctx, persistence, user, _ := newMediaDeletionFixture(t, "account")
		created, err := persistence.CreateProfileMedia(
			ctx, testProfileMedia(user.ID, 3), store.DefaultMediaReservationLimits(),
		)
		if err != nil {
			t.Fatal(err)
		}
		markMemoryMediaReady(t, ctx, persistence, created, user.ID)
		if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
			t.Fatal(err)
		}
		assertMediaDeleteDeadline(t, persistence, created.ObjectKey, created.UploadValidUntil)
	})
}

func newMediaDeletionFixture(
	t *testing.T,
	suffix string,
) (context.Context, *Store, domain.User, domain.Conversation) {
	t.Helper()
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "media-delete-" + suffix + "@example.com",
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
	return ctx, persistence, user, conversation
}

func markMemoryMediaReady(
	t *testing.T,
	ctx context.Context,
	persistence *Store,
	object domain.MediaObject,
	userID uuid.UUID,
) {
	t.Helper()
	claim, err := persistence.ClaimMediaVerification(ctx, object.ID, userID, time.Minute)
	if err != nil || claim.VerificationLeaseToken == nil {
		t.Fatalf("claim media: media=%+v error=%v", claim, err)
	}
	if _, err := persistence.MarkMediaReady(
		ctx, object.ID, userID, *claim.VerificationLeaseToken, object.ObjectKey,
	); err != nil {
		t.Fatal(err)
	}
}

func assertMediaDeleteDeadline(
	t *testing.T,
	persistence *Store,
	objectKey string,
	uploadValidUntil time.Time,
) {
	t.Helper()
	want := uploadValidUntil.Add(store.MediaDeleteGrace)
	persistence.mu.RLock()
	defer persistence.mu.RUnlock()
	for _, event := range persistence.outbox {
		if event.Topic != "media.delete" {
			continue
		}
		var payload store.MediaDeletePayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		for _, candidate := range payload.ObjectKeys {
			if candidate == objectKey {
				if payload.NotBefore == nil || payload.NotBefore.Before(want) || event.AvailableAt.Before(want) {
					t.Fatalf("key=%q payload not_before=%v available_at=%s want >=%s", objectKey, payload.NotBefore, event.AvailableAt, want)
				}
				return
			}
		}
	}
	t.Fatalf("no media.delete event for %q", objectKey)
}

func testConversationMedia(ownerID, conversationID uuid.UUID, byteSize int64) domain.MediaObject {
	id := uuid.New()
	return domain.MediaObject{
		ID: id, OwnerID: ownerID, ConversationID: conversationID,
		ObjectKey:   "conversations/" + conversationID.String() + "/" + id.String(),
		ContentType: "application/octet-stream", ByteSize: byteSize,
		CiphertextSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
}

func testProfileMedia(ownerID uuid.UUID, byteSize int64) domain.MediaObject {
	id := uuid.New()
	return domain.MediaObject{
		ID: id, OwnerID: ownerID, ObjectKey: "users/" + ownerID.String() + "/avatars/" + id.String(),
		ContentType: "image/jpeg", ByteSize: byteSize,
		CiphertextSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
}

func mediaDeletionKeys(t *testing.T, persistence *Store) []string {
	t.Helper()
	events, err := persistence.LockOutboxBatch(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, event := range events {
		if event.Topic != "media.delete" {
			continue
		}
		var payload store.MediaDeletePayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, payload.ObjectKeys...)
	}
	sort.Strings(keys)
	return keys
}
