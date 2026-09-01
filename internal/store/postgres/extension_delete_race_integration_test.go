package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestPostgresLegacyDeleteSerializesNewExtensionWrites(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()

	t.Run("profile create cannot follow tombstone", func(t *testing.T) {
		user := createExtensionRaceUser(t, ctx, persistence, "profile-create")
		mediaObject := extensionRaceProfileMedia(user)
		err := legacyTombstoneWhileWriteBlocked(t, ctx, persistence, user, nil, func() error {
			_, err := persistence.CreateProfileMedia(ctx, mediaObject, store.DefaultMediaReservationLimits())
			return err
		})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("profile create after tombstone returned %v, want not found", err)
		}
		assertNoProfileMediaRow(t, ctx, persistence, mediaObject.ID)
	})

	t.Run("profile completion cannot reactivate after tombstone", func(t *testing.T) {
		user := createExtensionRaceUser(t, ctx, persistence, "profile-complete")
		mediaObject := extensionRaceProfileMedia(user)
		if _, err := persistence.CreateProfileMedia(ctx, mediaObject, store.DefaultMediaReservationLimits()); err != nil {
			t.Fatal(err)
		}
		claimed, err := persistence.ClaimMediaVerification(ctx, mediaObject.ID, user, time.Minute)
		if err != nil || claimed.VerificationLeaseToken == nil {
			t.Fatalf("claim media verification: media=%+v err=%v", claimed, err)
		}
		err = legacyTombstoneWhileWriteBlocked(t, ctx, persistence, user, nil, func() error {
			_, err := persistence.MarkMediaReady(
				ctx, mediaObject.ID, user, *claimed.VerificationLeaseToken, mediaObject.ObjectKey,
			)
			return err
		})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("profile complete after tombstone returned %v, want not found", err)
		}
		assertNoProfileMediaRow(t, ctx, persistence, mediaObject.ID)
		assertProfileMediaDeleteQueued(t, ctx, persistence, user, mediaObject.ObjectKey)
	})

	t.Run("profile deletion and tombstone do not orphan an object", func(t *testing.T) {
		user := createExtensionRaceUser(t, ctx, persistence, "profile-delete")
		mediaObject := extensionRaceProfileMedia(user)
		if _, err := persistence.CreateProfileMedia(ctx, mediaObject, store.DefaultMediaReservationLimits()); err != nil {
			t.Fatal(err)
		}
		claimed, err := persistence.ClaimMediaVerification(ctx, mediaObject.ID, user, time.Minute)
		if err != nil || claimed.VerificationLeaseToken == nil {
			t.Fatalf("claim media verification: media=%+v err=%v", claimed, err)
		}
		if _, err := persistence.MarkMediaReady(
			ctx, mediaObject.ID, user, *claimed.VerificationLeaseToken, mediaObject.ObjectKey,
		); err != nil {
			t.Fatal(err)
		}
		err = legacyTombstoneWhileWriteBlocked(t, ctx, persistence, user, nil, func() error {
			_, err := persistence.DeleteMedia(ctx, mediaObject.ID, user)
			return err
		})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("profile delete after tombstone returned %v, want not found", err)
		}
		assertNoProfileMediaRow(t, ctx, persistence, mediaObject.ID)
		assertProfileMediaDeleteQueued(t, ctx, persistence, user, mediaObject.ObjectKey)
	})

	t.Run("invite create cannot follow creator tombstone", func(t *testing.T) {
		owner := createExtensionRaceUser(t, ctx, persistence, "invite-owner")
		creator := createExtensionRaceUser(t, ctx, persistence, "invite-creator")
		conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
			Kind: "group", CreatedBy: owner, MemberIDs: []uuid.UUID{creator},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := persistence.AddConversationMember(
			ctx, conversation.ID, owner, creator, "admin",
		); err != nil {
			t.Fatal(err)
		}
		tokenHash := sha256.Sum256([]byte("invite-create-" + uuid.NewString()))
		err = legacyTombstoneWhileWriteBlocked(t, ctx, persistence, creator, nil, func() error {
			_, err := persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
				ConversationID: conversation.ID, ActorID: creator, TokenHash: tokenHash[:],
				ExpiresAt: time.Now().UTC().Add(time.Hour), MaxUses: 2,
			})
			return err
		})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("invite create after tombstone returned %v, want not found", err)
		}
		var count int
		if err := persistence.pool.QueryRow(ctx, `
			SELECT count(*) FROM conversation_invite_links WHERE token_hash=$1`, tokenHash[:],
		).Scan(&count); err != nil || count != 0 {
			t.Fatalf("invite appeared after creator deletion: count=%d err=%v", count, err)
		}
	})

	t.Run("invite accept cannot add a tombstoned user", func(t *testing.T) {
		owner := createExtensionRaceUser(t, ctx, persistence, "accept-owner")
		joiner := createExtensionRaceUser(t, ctx, persistence, "accept-joiner")
		conversation, tokenHash := createExtensionRaceInvite(t, ctx, persistence, owner, owner)
		err := legacyTombstoneWhileWriteBlocked(t, ctx, persistence, joiner, nil, func() error {
			_, err := persistence.AcceptConversationInvite(ctx, tokenHash, joiner)
			return err
		})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("invite acceptance after joiner tombstone returned %v, want not found", err)
		}
		assertNotConversationMember(t, ctx, persistence, conversation.ID, joiner)
	})

	t.Run("invite accept follows conversation then invite lock order", func(t *testing.T) {
		owner := createExtensionRaceUser(t, ctx, persistence, "lock-order-owner")
		creator := createExtensionRaceUser(t, ctx, persistence, "lock-order-creator")
		joiner := createExtensionRaceUser(t, ctx, persistence, "lock-order-joiner")
		conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
			Kind: "group", CreatedBy: owner, MemberIDs: []uuid.UUID{creator},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := persistence.AddConversationMember(
			ctx, conversation.ID, owner, creator, "admin",
		); err != nil {
			t.Fatal(err)
		}
		_, tokenHash := createExtensionRaceInvite(
			t, ctx, persistence, owner, creator, conversation,
		)
		err = legacyTombstoneWhileWriteBlocked(
			t, ctx, persistence, creator, []uuid.UUID{conversation.ID}, func() error {
				_, err := persistence.AcceptConversationInvite(ctx, tokenHash, joiner)
				return err
			},
		)
		if !errors.Is(err, domain.ErrInviteRevoked) {
			t.Fatalf("accept after creator tombstone returned %v, want revoked", err)
		}
		assertNotConversationMember(t, ctx, persistence, conversation.ID, joiner)
	})
}

func legacyTombstoneWhileWriteBlocked(
	t *testing.T,
	ctx context.Context,
	persistence *Store,
	userID uuid.UUID,
	conversationIDs []uuid.UUID,
	write func() error,
) error {
	t.Helper()
	tx, err := persistence.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var lockedUser uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, userID).
		Scan(&lockedUser); err != nil {
		t.Fatal(err)
	}
	for _, conversationID := range conversationIDs {
		var lockedConversation uuid.UUID
		if err := tx.QueryRow(ctx, `
			SELECT id FROM conversations WHERE id=$1 FOR UPDATE`, conversationID,
		).Scan(&lockedConversation); err != nil {
			t.Fatal(err)
		}
	}

	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		result <- write()
	}()
	<-started
	select {
	case err := <-result:
		t.Fatalf("extension write completed while the legacy delete held its first lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET email=NULL,phone=NULL,display_name=$2,avatar_url='',
			profile='{"deleted":true}'::jsonb,password_hash='',deleted_at=now(),updated_at=now()
		WHERE id=$1 AND deleted_at IS NULL`, userID, store.DeletedUserDisplayName); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("extension write deadlocked with legacy account deletion")
		return nil
	}
}

func createExtensionRaceUser(t *testing.T, ctx context.Context, persistence *Store, label string) uuid.UUID {
	t.Helper()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email:        "pg-extension-race-" + label + "-" + uuid.NewString() + "@example.com",
		PasswordHash: "password-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	return user.ID
}

func extensionRaceProfileMedia(ownerID uuid.UUID) domain.MediaObject {
	return domain.MediaObject{
		ID: uuid.New(), OwnerID: ownerID,
		ObjectKey:   "users/" + ownerID.String() + "/avatars/" + uuid.NewString(),
		ContentType: "image/jpeg", ByteSize: 3,
		CiphertextSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
}

func createExtensionRaceInvite(
	t *testing.T,
	ctx context.Context,
	persistence *Store,
	ownerID uuid.UUID,
	creatorID uuid.UUID,
	provided ...domain.Conversation,
) (domain.Conversation, []byte) {
	t.Helper()
	var conversation domain.Conversation
	if len(provided) == 0 {
		var err error
		conversation, err = persistence.CreateConversation(ctx, store.CreateConversationParams{
			Kind: "group", CreatedBy: ownerID,
		})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		conversation = provided[0]
	}
	tokenHash := sha256.Sum256([]byte("invite-accept-" + uuid.NewString()))
	if _, err := persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
		ConversationID: conversation.ID, ActorID: creatorID, TokenHash: tokenHash[:],
		ExpiresAt: time.Now().UTC().Add(time.Hour), MaxUses: 2,
	}); err != nil {
		t.Fatal(err)
	}
	return conversation, tokenHash[:]
}

func assertNoProfileMediaRow(t *testing.T, ctx context.Context, persistence *Store, mediaID uuid.UUID) {
	t.Helper()
	var count int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*) FROM profile_media_objects WHERE id=$1`, mediaID,
	).Scan(&count); err != nil || count != 0 {
		t.Fatalf("profile media row survived deletion: count=%d err=%v", count, err)
	}
}

func assertProfileMediaDeleteQueued(
	t *testing.T,
	ctx context.Context,
	persistence *Store,
	userID uuid.UUID,
	objectKey string,
) {
	t.Helper()
	var found bool
	if err := persistence.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM outbox_events
			WHERE topic='media.delete' AND aggregate_id=$1
			  AND payload->'object_keys' ? $2
		)`, userID, objectKey,
	).Scan(&found); err != nil || !found {
		t.Fatalf("profile object deletion was not durable: found=%t err=%v", found, err)
	}
}

func assertNotConversationMember(
	t *testing.T,
	ctx context.Context,
	persistence *Store,
	conversationID uuid.UUID,
	userID uuid.UUID,
) {
	t.Helper()
	var count int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*) FROM conversation_members
		WHERE conversation_id=$1 AND user_id=$2`, conversationID, userID,
	).Scan(&count); err != nil || count != 0 {
		t.Fatalf("tombstoned user became a member: count=%d err=%v", count, err)
	}
}
