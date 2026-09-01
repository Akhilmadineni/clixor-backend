package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresMessagingLifecycle(t *testing.T) {
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

	alice, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-alice-" + uuid.NewString() + "@example.com", PasswordHash: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-bob-" + uuid.NewString() + "@example.com", PasswordHash: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: alice.ID, Name: "iPhone", Platform: "ios", CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: device.ID, UserID: bob.ID, Name: "Other iPhone", Platform: "ios", CreatedAt: time.Now(),
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("cross-account device reassignment returned %v, want conflict", err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "direct", CreatedBy: alice.ID, MemberIDs: []uuid.UUID{bob.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	reused, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "direct", CreatedBy: bob.ID, MemberIDs: []uuid.UUID{alice.ID},
	})
	if err != nil || reused.ID != conversation.ID {
		t.Fatalf("direct conversation reuse failed: conversation=%+v err=%v", reused, err)
	}

	params := store.CreateMessageParams{
		ID: uuid.New(), ClientMessageID: uuid.NewString(), ConversationID: conversation.ID,
		SenderID: alice.ID, SenderDeviceID: device.ID, ContentType: "text",
		Ciphertext: "ZW5jcnlwdGVk", Envelope: json.RawMessage(`{"protocol":"signal-v1"}`),
	}
	message, recipients, err := persistence.CreateMessage(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, _, err := persistence.CreateMessage(ctx, params)
	if err != nil || duplicate.ID != message.ID || message.Seq != 1 || len(recipients) != 2 {
		t.Fatalf("message idempotency failed: first=%+v duplicate=%+v recipients=%v err=%v",
			message, duplicate, recipients, err)
	}
	for sequence := int64(2); sequence <= 6; sequence++ {
		params.ID = uuid.New()
		params.ClientMessageID = uuid.NewString()
		if _, _, err := persistence.CreateMessage(ctx, params); err != nil {
			t.Fatal(err)
		}
	}
	messages, err := persistence.ListMessages(ctx, store.ListMessagesParams{
		ConversationID: conversation.ID, UserID: bob.ID, Limit: 3,
	})
	if err != nil || len(messages) != 3 || messages[0].Seq != 4 || messages[2].Seq != 6 {
		t.Fatalf("latest message page failed: messages=%+v err=%v", messages, err)
	}
	before := int64(4)
	messages, err = persistence.ListMessages(ctx, store.ListMessagesParams{
		ConversationID: conversation.ID, UserID: bob.ID, BeforeSeq: &before, Limit: 2,
	})
	if err != nil || len(messages) != 2 || messages[0].Seq != 2 || messages[1].Seq != 3 {
		t.Fatalf("older message page failed: messages=%+v err=%v", messages, err)
	}
	after := int64(2)
	messages, err = persistence.ListMessages(ctx, store.ListMessagesParams{
		ConversationID: conversation.ID, UserID: bob.ID, AfterSeq: &after, Limit: 2,
	})
	if err != nil || len(messages) != 2 || messages[0].Seq != 3 || messages[1].Seq != 4 {
		t.Fatalf("catch-up message page failed: messages=%+v err=%v", messages, err)
	}
	if _, err := persistence.UpsertReceipt(ctx, domain.Receipt{
		ConversationID: conversation.ID, UserID: bob.ID, DeliveredSeq: 1, ReadSeq: 1,
	}); err != nil {
		t.Fatal(err)
	}
	receipts, err := persistence.ListReceipts(ctx, conversation.ID, alice.ID)
	if err != nil || len(receipts) != 1 {
		t.Fatalf("receipt replay failed: receipts=%+v err=%v", receipts, err)
	}
	entityID := uuid.New()
	expectedCreate := int64(0)
	if _, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "expense", ID: entityID,
		Payload: json.RawMessage(`{"amount":42.50}`), CreatedBy: alice.ID,
	}, &expectedCreate); err != nil {
		t.Fatal(err)
	}
	expectedDelete := int64(1)
	deleted, err := persistence.DeleteEntity(
		ctx, conversation.ID, alice.ID, "expense", entityID, &expectedDelete,
	)
	if err != nil || deleted.DeletedAt == nil || deleted.Version != 2 {
		t.Fatalf("entity tombstone failed: entity=%+v err=%v", deleted, err)
	}
}

func TestPostgresPasswordResetIsAtomicAndRevokesSessions(t *testing.T) {
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
		Email: "pg-reset-" + uuid.NewString() + "@example.com", PasswordHash: "old-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: user.ID, Name: "iPhone", Platform: "ios",
		PushToken: "aabbccdd", CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	session := domain.Session{
		ID: uuid.New(), UserID: user.ID, DeviceID: device.ID,
		RefreshTokenHash: []byte("refresh"), ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}
	if err := persistence.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	challenge := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: user.ID, CodeHash: []byte("01234567890123456789012345678901"),
		ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
	}
	if err := persistence.CreatePasswordResetChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ConsumePasswordResetChallenge(
		ctx, challenge.ID, []byte("wrong"), "new-hash", 5,
	); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("wrong reset code returned %v", err)
	}
	email, err := persistence.ConsumePasswordResetChallenge(
		ctx, challenge.ID, challenge.CodeHash, "new-hash", 5,
	)
	if err != nil || email != user.Email {
		t.Fatalf("password reset returned email=%q err=%v", email, err)
	}
	updated, err := persistence.UserByID(ctx, user.ID)
	if err != nil || updated.PasswordHash != "new-hash" {
		t.Fatalf("password was not updated: user=%+v err=%v", updated, err)
	}
	active, err := persistence.SessionActive(ctx, session.ID, user.ID, device.ID)
	if err != nil || active {
		t.Fatalf("session remained active=%v err=%v", active, err)
	}
	resetDevice, err := persistence.Device(ctx, user.ID, device.ID)
	if err != nil || resetDevice.PushToken != "" {
		t.Fatalf("password reset retained push token=%q err=%v", resetDevice.PushToken, err)
	}
	if _, err := persistence.ConsumePasswordResetChallenge(
		ctx, challenge.ID, challenge.CodeHash, "third-hash", 5,
	); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("replayed reset code returned %v", err)
	}
}

func TestPostgresConcurrentPasswordResetStartsSerialize(t *testing.T) {
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
		Email:        "pg-reset-race-" + uuid.NewString() + "@example.com",
		PasswordHash: "old-hash",
	})
	if err != nil {
		t.Fatal(err)
	}

	const challengeCount = 8
	now := time.Now().UTC()
	challenges := make([]domain.PasswordResetChallenge, challengeCount)
	for index := range challenges {
		challengeID := uuid.New()
		codeHash := sha256.Sum256(challengeID[:])
		challenges[index] = domain.PasswordResetChallenge{
			ID: challengeID, UserID: user.ID, CodeHash: codeHash[:],
			ExpiresAt: now.Add(10 * time.Minute),
			CreatedAt: now.Add(time.Duration(index) * time.Nanosecond),
		}
	}
	start := make(chan struct{})
	results := make(chan error, challengeCount)
	for _, challenge := range challenges {
		go func(challenge domain.PasswordResetChallenge) {
			<-start
			results <- persistence.CreatePasswordResetChallenge(ctx, challenge)
		}(challenge)
	}
	close(start)
	for range challengeCount {
		if err := <-results; err != nil {
			t.Fatalf("concurrent reset start returned an observable store error: %v", err)
		}
	}

	var totalCount, activeCount int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*),count(*) FILTER (WHERE consumed_at IS NULL)
		FROM password_reset_challenges WHERE user_id=$1`, user.ID,
	).Scan(&totalCount, &activeCount); err != nil {
		t.Fatal(err)
	}
	if totalCount != challengeCount || activeCount != 1 {
		t.Fatalf("reset rows total=%d active=%d, want total=%d active=1",
			totalCount, activeCount, challengeCount)
	}
	var activeID uuid.UUID
	if err := persistence.pool.QueryRow(ctx, `
		SELECT id FROM password_reset_challenges
		WHERE user_id=$1 AND consumed_at IS NULL`, user.ID,
	).Scan(&activeID); err != nil {
		t.Fatal(err)
	}
	for _, challenge := range challenges {
		if challenge.ID == activeID {
			continue
		}
		if _, err := persistence.ConsumePasswordResetChallenge(
			ctx, challenge.ID, challenge.CodeHash, "replacement-hash", 5,
		); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Fatalf("superseded challenge %s returned %v, want unauthenticated", challenge.ID, err)
		}
	}
	for _, challenge := range challenges {
		if challenge.ID != activeID {
			continue
		}
		email, err := persistence.ConsumePasswordResetChallenge(
			ctx, challenge.ID, challenge.CodeHash, "replacement-hash", 5,
		)
		if err != nil || email != user.Email {
			t.Fatalf("sole active challenge returned email=%q err=%v", email, err)
		}
	}
}

func TestPostgresPasswordResetStartAndConfirmUseOneLockOrder(t *testing.T) {
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
		Email:        "pg-reset-lock-order-" + uuid.NewString() + "@example.com",
		PasswordHash: "old-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	initialID := uuid.New()
	initialHash := sha256.Sum256(initialID[:])
	initial := domain.PasswordResetChallenge{
		ID: initialID, UserID: user.ID, CodeHash: initialHash[:],
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute), CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreatePasswordResetChallenge(ctx, initial); err != nil {
		t.Fatal(err)
	}
	replacementID := uuid.New()
	replacementHash := sha256.Sum256(replacementID[:])
	replacement := domain.PasswordResetChallenge{
		ID: replacementID, UserID: user.ID, CodeHash: replacementHash[:],
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute), CreatedAt: time.Now().UTC(),
	}
	type consumeResult struct {
		email string
		err   error
	}
	start := make(chan struct{})
	createResult := make(chan error, 1)
	confirmResult := make(chan consumeResult, 1)
	go func() {
		<-start
		createResult <- persistence.CreatePasswordResetChallenge(ctx, replacement)
	}()
	go func() {
		<-start
		email, err := persistence.ConsumePasswordResetChallenge(
			ctx, initial.ID, initial.CodeHash, "replacement-hash", 5,
		)
		confirmResult <- consumeResult{email: email, err: err}
	}()
	close(start)
	select {
	case err := <-createResult:
		if err != nil {
			t.Fatalf("concurrent reset start returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reset start deadlocked with confirmation")
	}
	select {
	case result := <-confirmResult:
		if result.err != nil && !errors.Is(result.err, domain.ErrUnauthenticated) {
			t.Fatalf("concurrent reset confirmation returned %v", result.err)
		}
		if result.err == nil && result.email != user.Email {
			t.Fatalf("confirmation email=%q, want %q", result.email, user.Email)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reset confirmation deadlocked with start")
	}
	var activeCount int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*) FROM password_reset_challenges
		WHERE user_id=$1 AND consumed_at IS NULL`, user.ID,
	).Scan(&activeCount); err != nil || activeCount != 1 {
		t.Fatalf("active reset challenges=%d, want 1: %v", activeCount, err)
	}
}

func TestPostgresLegacyDeleteCannotDeadlockResetStartOrConfirm(t *testing.T) {
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
		Email:        "pg-reset-delete-race-" + uuid.NewString() + "@example.com",
		PasswordHash: "old-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	initialID := uuid.New()
	initialHash := sha256.Sum256(initialID[:])
	initial := domain.PasswordResetChallenge{
		ID: initialID, UserID: user.ID, CodeHash: initialHash[:],
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute), CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreatePasswordResetChallenge(ctx, initial); err != nil {
		t.Fatal(err)
	}
	replacementID := uuid.New()
	replacementHash := sha256.Sum256(replacementID[:])
	replacement := domain.PasswordResetChallenge{
		ID: replacementID, UserID: user.ID, CodeHash: replacementHash[:],
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute), CreatedAt: time.Now().UTC(),
	}

	deleteTx, err := persistence.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer deleteTx.Rollback(ctx)
	var lockedUser uuid.UUID
	if err := deleteTx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, user.ID).
		Scan(&lockedUser); err != nil {
		t.Fatal(err)
	}
	type consumeResult struct {
		err error
	}
	start := make(chan struct{})
	createResult := make(chan error, 1)
	confirmResult := make(chan consumeResult, 1)
	go func() {
		<-start
		createResult <- persistence.CreatePasswordResetChallenge(ctx, replacement)
	}()
	go func() {
		<-start
		_, err := persistence.ConsumePasswordResetChallenge(
			ctx, initial.ID, initial.CodeHash, "replacement-hash", 5,
		)
		confirmResult <- consumeResult{err: err}
	}()
	close(start)
	select {
	case err := <-createResult:
		t.Fatalf("reset start escaped the held user lock: %v", err)
	case result := <-confirmResult:
		t.Fatalf("reset confirmation escaped the held user lock: %v", result.err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := deleteTx.Exec(ctx, `
		UPDATE users SET email=NULL,phone=NULL,display_name=$2,avatar_url='',
			profile='{"deleted":true}'::jsonb,password_hash='',deleted_at=now(),updated_at=now()
		WHERE id=$1`, user.ID, store.DeletedUserDisplayName); err != nil {
		t.Fatal(err)
	}
	if err := deleteTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-createResult:
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("reset start after delete returned %v, want not found", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reset start deadlocked with account deletion")
	}
	select {
	case result := <-confirmResult:
		if !errors.Is(result.err, domain.ErrUnauthenticated) {
			t.Fatalf("reset confirmation after delete returned %v, want unauthenticated", result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reset confirmation deadlocked with account deletion")
	}
}

func TestPostgresLegacyAccountTombstoneCleansNewExtensionState(t *testing.T) {
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

	deletedUser, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email:        "pg-legacy-delete-" + uuid.NewString() + "@example.com",
		DisplayName:  "Legacy Delete",
		PasswordHash: "legacy-password-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-legacy-delete-owner-" + uuid.NewString() + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Legacy delete trigger", CreatedBy: owner.ID,
		MemberIDs: []uuid.UUID{deletedUser.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.AddConversationMember(
		ctx, conversation.ID, owner.ID, deletedUser.ID, "admin",
	); err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("legacy-delete-" + uuid.NewString()))
	invite, err := persistence.CreateConversationInvite(ctx, store.CreateConversationInviteParams{
		ConversationID: conversation.ID,
		ActorID:        deletedUser.ID,
		TokenHash:      tokenHash[:],
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
		MaxUses:        3,
	})
	if err != nil {
		t.Fatal(err)
	}
	resetChallenge := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: deletedUser.ID,
		CodeHash:  []byte("01234567890123456789012345678901"),
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute), CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreatePasswordResetChallenge(ctx, resetChallenge); err != nil {
		t.Fatal(err)
	}
	profileMedia := []domain.MediaObject{
		{
			ID: uuid.New(), OwnerID: deletedUser.ID,
			ObjectKey:   "profiles/legacy-delete/" + uuid.NewString(),
			ContentType: "image/jpeg", ByteSize: 17,
			CiphertextSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			ID: uuid.New(), OwnerID: deletedUser.ID,
			ObjectKey:   "profiles/legacy-delete/" + uuid.NewString(),
			ContentType: "image/png", ByteSize: 23,
			CiphertextSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
	}
	for _, mediaObject := range profileMedia {
		if _, err := persistence.CreateProfileMedia(ctx, mediaObject, store.DefaultMediaReservationLimits()); err != nil {
			t.Fatal(err)
		}
	}

	// This is the final tombstone write made by the production-05b account
	// deletion transaction. It intentionally bypasses the new DeleteAccount
	// implementation to prove the migration trigger protects a mixed rollout.
	command, err := persistence.pool.Exec(ctx, `
		UPDATE users SET email=NULL,phone=NULL,display_name=$2,avatar_url='',
			profile='{"deleted":true}'::jsonb,password_hash='',deleted_at=now(),updated_at=now()
		WHERE id=$1 AND deleted_at IS NULL`, deletedUser.ID, store.DeletedUserDisplayName)
	if err != nil {
		t.Fatal(err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("legacy tombstone affected %d rows, want 1", command.RowsAffected())
	}

	var inviteRevoked bool
	if err := persistence.pool.QueryRow(ctx, `
		SELECT revoked_at IS NOT NULL FROM conversation_invite_links WHERE id=$1`,
		invite.ID,
	).Scan(&inviteRevoked); err != nil || !inviteRevoked {
		t.Fatalf("legacy invite was not revoked: revoked=%t err=%v", inviteRevoked, err)
	}
	var resetCount int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*) FROM password_reset_challenges WHERE user_id=$1`, deletedUser.ID,
	).Scan(&resetCount); err != nil || resetCount != 0 {
		t.Fatalf("password reset challenges retained %d rows: %v", resetCount, err)
	}
	var profileMediaCount int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT count(*) FROM profile_media_objects WHERE owner_id=$1`, deletedUser.ID,
	).Scan(&profileMediaCount); err != nil || profileMediaCount != 0 {
		t.Fatalf("profile media retained %d rows: %v", profileMediaCount, err)
	}

	rows, err := persistence.pool.Query(ctx, `
		SELECT payload FROM outbox_events
		WHERE topic='media.delete' AND aggregate_id=$1 ORDER BY id`, deletedUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	deletedKeys := make(map[string]bool)
	for rows.Next() {
		var raw json.RawMessage
		var payload store.MediaDeletePayload
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		for _, objectKey := range payload.ObjectKeys {
			deletedKeys[objectKey] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(deletedKeys) != len(profileMedia)*2 {
		t.Fatalf("media deletion outbox contains %d unique keys, want %d: %v",
			len(deletedKeys), len(profileMedia)*2, deletedKeys)
	}
	for _, mediaObject := range profileMedia {
		if !deletedKeys[mediaObject.ObjectKey] {
			t.Fatalf("media deletion outbox omitted %q: %v", mediaObject.ObjectKey, deletedKeys)
		}
		if !deletedKeys["published/"+mediaObject.ObjectKey] {
			t.Fatalf("media deletion outbox omitted published key for %q: %v", mediaObject.ObjectKey, deletedKeys)
		}
	}
}

func TestPostgresDeleteAccountTransaction(t *testing.T) {
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

	email := "pg-delete-" + uuid.NewString() + "@example.com"
	phone := "+1312" + time.Now().UTC().Format("150405")
	username := "@pg_delete_" + uuid.NewString()[:8]
	deletedUser, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: email, Phone: phone,
		DisplayName: "Postgres Delete", PasswordHash: "secret-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	deletedUser, err = persistence.UpdateUserProfile(ctx, deletedUser.ID, json.RawMessage(`{
		"display_name":"Postgres Delete","username":"`+username+`"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	remainingUser, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-remaining-" + uuid.NewString() + "@example.com", DisplayName: "Remaining",
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: deletedUser.ID, Name: "Private iPhone", Platform: "ios",
		PushToken: "push-secret", IdentityKey: "identity-secret", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	session := domain.Session{
		ID: uuid.New(), UserID: deletedUser.ID, DeviceID: device.ID,
		RefreshTokenHash: []byte("refresh-secret"), ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	resetChallenge := domain.PasswordResetChallenge{
		ID: uuid.New(), UserID: deletedUser.ID, CodeHash: []byte("01234567890123456789012345678901"),
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute), CreatedAt: time.Now().UTC(),
	}
	if err := persistence.CreatePasswordResetChallenge(ctx, resetChallenge); err != nil {
		t.Fatal(err)
	}
	if err := persistence.LinkExternalIdentity(ctx, "apple", uuid.NewString(), deletedUser.ID, email); err != nil {
		t.Fatal(err)
	}
	shared, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Shared", CreatedBy: deletedUser.ID,
		MemberIDs: []uuid.UUID{remainingUser.ID},
		Metadata: json.RawMessage(`{"members":[{"backendUserId":"` + deletedUser.ID.String() +
			`","name":"Postgres Delete","email":"` + email + `"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	expenseID := uuid.New()
	expected := int64(0)
	if _, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: shared.ID, Kind: "expense", ID: expenseID, CreatedBy: deletedUser.ID,
		Payload: json.RawMessage(`{"payer":{"backendUserId":"` + deletedUser.ID.String() +
			`","displayName":"Postgres Delete","email":"` + email + `"}}`),
	}, &expected); err != nil {
		t.Fatal(err)
	}
	unrelatedOutboxEntityID := uuid.New()
	if _, err := persistence.pool.Exec(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload) VALUES
		('entity.updated',$1::uuid,jsonb_build_object(
			'conversation_id',$1::uuid,'kind','expense','id',$2::uuid,'version',1,
			'payload',jsonb_build_object('description',$3::text),'created_by',$5::uuid,
			'created_at','0001-01-01T00:00:00Z','updated_at','0001-01-01T00:00:00Z')),
		('entity.updated',$1::uuid,jsonb_build_object(
			'conversation_id',$1::uuid,'kind','note','id',$4::uuid,'version',1,
			'payload',jsonb_build_object('description','keep unrelated'),'created_by',$5::uuid,
			'created_at','0001-01-01T00:00:00Z','updated_at','0001-01-01T00:00:00Z'))`,
		shared.ID, expenseID, "Postgres Delete", unrelatedOutboxEntityID, remainingUser.ID); err != nil {
		t.Fatal(err)
	}
	choreID, rotationID, financialID := uuid.New(), uuid.New(), uuid.New()
	baseChore := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` +
		shared.ID.String() + `","createdBy":"` + deletedUser.ID.String() +
		`","assignedTo":"` + remainingUser.ID.String() + `"}`)
	chore, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: shared.ID, Kind: "chore", ID: choreID,
		CreatedBy: deletedUser.ID, Payload: baseChore,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotatedChore := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` +
		shared.ID.String() + `","createdBy":"` + deletedUser.ID.String() +
		`","assignedTo":"` + remainingUser.ID.String() +
		`","creatorName":"Postgres Delete","createdByDisplayName":"Postgres Delete",` +
		`"description":"Postgres Delete (` + username + `) ` + email + ` ` + phone + `",` +
		`"financialId":"` + financialID.String() + `","amount":91.5}`)
	rotationFeed := json.RawMessage(`{"id":"` + rotationID.String() + `","groupId":"` +
		shared.ID.String() + `","createdBy":"` + deletedUser.ID.String() +
		`","relatedId":"` + choreID.String() + `","type":"note",` +
		`"creatorDisplayName":"Postgres Delete","createdByName":"Postgres Delete",` +
		`"description":"Postgres Delete <` + email + `> ` + username + ` ` + phone + `",` +
		`"financialId":"` + financialID.String() + `","amount":91.5}`)
	rotationHash := sha256.Sum256(append(append([]byte(nil), rotatedChore...), rotationFeed...))
	if _, err := persistence.RotateChore(ctx, store.RotateChoreParams{
		OperationID: rotationID, ConversationID: shared.ID, ChoreID: choreID,
		ActorID: deletedUser.ID, ExpectedChoreVersion: chore.Version,
		ChorePayload: rotatedChore, FeedPayload: rotationFeed, RequestHash: rotationHash[:],
	}); err != nil {
		t.Fatal(err)
	}
	personal, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", Title: "Personal", CreatedBy: deletedUser.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	mediaObject := domain.MediaObject{
		ID: uuid.New(), OwnerID: deletedUser.ID, ConversationID: personal.ID,
		ObjectKey: "pg/private/" + uuid.NewString(), ContentType: "image/jpeg", ByteSize: 7,
	}
	if _, err := persistence.CreateMedia(ctx, mediaObject, store.DefaultMediaReservationLimits()); err != nil {
		t.Fatal(err)
	}

	if err := persistence.DeleteAccount(ctx, deletedUser.ID); err != nil {
		t.Fatal(err)
	}
	var staleNameCount, unrelatedEventCount int
	if err := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE position(lower($1) in lower(payload::text))>0`, "Postgres Delete").Scan(&staleNameCount); err != nil || staleNameCount != 0 {
		t.Fatalf("display-name-only stale outbox survived: count=%d err=%v", staleNameCount, err)
	}
	if err := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE payload->>'id'=$1`, unrelatedOutboxEntityID.String()).Scan(&unrelatedEventCount); err != nil || unrelatedEventCount != 1 {
		t.Fatalf("unrelated shared-conversation outbox was not preserved: count=%d err=%v", unrelatedEventCount, err)
	}
	var resetCount int
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM password_reset_challenges WHERE user_id=$1`, deletedUser.ID,
	).Scan(&resetCount); err != nil || resetCount != 0 {
		t.Fatalf("password reset challenges remained after deletion: count=%d err=%v", resetCount, err)
	}
	if _, err := persistence.UserByEmail(ctx, email); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted email lookup returned %v, want not found", err)
	}
	active, err := persistence.SessionActive(ctx, session.ID, deletedUser.ID, device.ID)
	if err != nil || active {
		t.Fatalf("deleted session remained active: active=%t err=%v", active, err)
	}
	if _, err := persistence.UserByID(ctx, deletedUser.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted user ID returned %v, want not found", err)
	}
	var tombstone domain.User
	err = persistence.pool.QueryRow(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,
		       password_hash,created_at,updated_at
		FROM users WHERE id=$1`, deletedUser.ID,
	).Scan(&tombstone.ID, &tombstone.Email, &tombstone.Phone, &tombstone.DisplayName,
		&tombstone.AvatarURL, &tombstone.Profile, &tombstone.PasswordHash,
		&tombstone.CreatedAt, &tombstone.UpdatedAt)
	if err != nil || tombstone.DisplayName != store.DeletedUserDisplayName ||
		tombstone.Email != "" || tombstone.Phone != "" || tombstone.PasswordHash != "" {
		t.Fatalf("user tombstone is invalid: user=%+v err=%v", tombstone, err)
	}
	retained, err := persistence.Conversation(ctx, shared.ID, remainingUser.ID)
	if err != nil || retained.CreatedBy != remainingUser.ID ||
		string(retained.Metadata) == string(shared.Metadata) {
		t.Fatalf("shared conversation was not transferred/anonymized: conversation=%+v err=%v", retained, err)
	}
	members, err := persistence.ListConversationMembers(ctx, shared.ID, remainingUser.ID)
	if err != nil || len(members) != 1 || members[0].UserID != remainingUser.ID || members[0].Role != "owner" {
		t.Fatalf("shared membership is invalid: members=%+v err=%v", members, err)
	}
	entities, err := persistence.ListEntities(ctx, shared.ID, remainingUser.ID, "expense", time.Time{}, 10)
	if err != nil || len(entities) != 1 || entities[0].Version != 2 {
		t.Fatalf("shared entity history is invalid: entities=%+v err=%v", entities, err)
	}
	chores, err := persistence.ListEntities(ctx, shared.ID, remainingUser.ID, "chore", time.Time{}, 10)
	if err != nil || len(chores) != 1 {
		t.Fatalf("shared chore history is invalid: entities=%+v err=%v", chores, err)
	}
	feeds, err := persistence.ListEntities(ctx, shared.ID, remainingUser.ID, "feed_item", time.Time{}, 10)
	if err != nil || len(feeds) != 1 {
		t.Fatalf("shared feed history is invalid: entities=%+v err=%v", feeds, err)
	}
	var replayChore, replayFeed json.RawMessage
	if err := persistence.pool.QueryRow(ctx, `
		SELECT chore_result,feed_result FROM chore_rotation_operations
		WHERE operation_id=$1 AND expires_at>now()+interval '89 days'`, rotationID,
	).Scan(&replayChore, &replayFeed); err != nil {
		t.Fatalf("90-day rotation replay row was not retained: %v", err)
	}
	for label, raw := range map[string][]byte{
		"live chore":            chores[0].Payload,
		"live feed":             feeds[0].Payload,
		"rotation chore replay": replayChore,
		"rotation feed replay":  replayFeed,
	} {
		text := string(raw)
		for _, forbidden := range []string{"Postgres Delete", email, phone, username} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
				t.Fatalf("%s retained %q: %s", label, forbidden, text)
			}
		}
		for _, retainedValue := range []string{
			deletedUser.ID.String(), financialID.String(), "91.5",
		} {
			if !strings.Contains(text, retainedValue) {
				t.Fatalf("%s removed shared value %q: %s", label, retainedValue, text)
			}
		}
	}
	if _, err := persistence.Conversation(ctx, personal.ID, remainingUser.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("personal conversation returned %v, want not found", err)
	}
	rows, err := persistence.pool.Query(ctx, `
		SELECT payload FROM outbox_events WHERE topic='media.delete' AND aggregate_id=$1`,
		deletedUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	foundMediaDelete := false
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var payload store.MediaDeletePayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		for _, objectKey := range payload.ObjectKeys {
			if objectKey == mediaObject.ObjectKey {
				foundMediaDelete = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !foundMediaDelete {
		t.Fatal("personal MinIO deletion was not queued")
	}
	if _, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: email}); err != nil {
		t.Fatalf("deleted email was not reusable: %v", err)
	}
}
