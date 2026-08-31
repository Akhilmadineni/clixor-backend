package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresConcurrentOwnershipTransferKeepsOneDeletionAuthority(t *testing.T) {
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
	create := func(label string) uuid.UUID {
		user, err := persistence.CreateUser(ctx, store.CreateUserParams{
			Email: "ownership-" + label + "-" + uuid.NewString() + "@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		return user.ID
	}
	owner, first, second := create("owner"), create("first"), create("second")
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: owner, MemberIDs: []uuid.UUID{first, second},
	})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, target := range []uuid.UUID{first, second} {
		target := target
		go func() {
			<-start
			results <- persistence.TransferConversationOwnership(ctx, conversation.ID, owner, target)
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent ownership transfers succeeded %d times, want exactly one", successes)
	}
	var createdBy uuid.UUID
	var owners int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT c.created_by,count(m.user_id)
		FROM conversations c
		LEFT JOIN conversation_members m ON m.conversation_id=c.id AND m.role='owner'
		WHERE c.id=$1 GROUP BY c.created_by`, conversation.ID,
	).Scan(&createdBy, &owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 || (createdBy != first && createdBy != second) {
		t.Fatalf("ownership invariant: created_by=%s owners=%d", createdBy, owners)
	}
	if err := persistence.DeleteConversation(ctx, conversation.ID, createdBy); err != nil {
		t.Fatalf("current owner could not delete conversation: %v", err)
	}
}

func TestPostgresOwnershipTransferSerializesWithDeleteAndErasure(t *testing.T) {
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
	create := func(label string) uuid.UUID {
		user, err := persistence.CreateUser(ctx, store.CreateUserParams{
			Email: "ownership-race-" + label + "-" + uuid.NewString() + "@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		return user.ID
	}

	t.Run("conversation delete", func(t *testing.T) {
		owner, target := create("delete-owner"), create("delete-target")
		conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
			Kind: "group", CreatedBy: owner, MemberIDs: []uuid.UUID{target},
		})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		transferDone, deleteDone := make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			transferDone <- persistence.TransferConversationOwnership(ctx, conversation.ID, owner, target)
		}()
		go func() {
			<-start
			deleteDone <- persistence.DeleteConversation(ctx, conversation.ID, owner)
		}()
		close(start)
		transferErr, deleteErr := <-transferDone, <-deleteDone
		if (transferErr == nil) == (deleteErr == nil) {
			t.Fatalf("transfer=%v delete=%v, want exactly one winner", transferErr, deleteErr)
		}
		if deleteErr == nil {
			var count int
			if err := persistence.pool.QueryRow(ctx, `
				SELECT count(*) FROM conversations WHERE id=$1`, conversation.ID,
			).Scan(&count); err != nil || count != 0 {
				t.Fatalf("deleted conversation count=%d err=%v", count, err)
			}
			return
		}
		if !errors.Is(deleteErr, domain.ErrForbidden) {
			t.Fatalf("losing old-owner delete=%v", deleteErr)
		}
		assertPostgresConversationAuthority(t, ctx, persistence, conversation.ID, target)
	})

	t.Run("owner erasure", func(t *testing.T) {
		owner, target := create("erase-owner"), create("erase-target")
		conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
			Kind: "group", CreatedBy: owner, MemberIDs: []uuid.UUID{target},
		})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		transferDone, deletionDone := make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			transferDone <- persistence.TransferConversationOwnership(ctx, conversation.ID, owner, target)
		}()
		go func() {
			<-start
			deletionDone <- persistence.DeleteAccount(ctx, owner)
		}()
		close(start)
		transferErr, deletionErr := <-transferDone, <-deletionDone
		if deletionErr != nil {
			t.Fatalf("owner erasure failed: %v (transfer=%v)", deletionErr, transferErr)
		}
		if transferErr != nil && !errors.Is(transferErr, domain.ErrNotFound) &&
			!errors.Is(transferErr, domain.ErrForbidden) {
			t.Fatalf("unexpected losing transfer error: %v", transferErr)
		}
		assertPostgresConversationAuthority(t, ctx, persistence, conversation.ID, target)
	})
}

func assertPostgresConversationAuthority(
	t *testing.T,
	ctx context.Context,
	persistence *Store,
	conversationID uuid.UUID,
	wantOwner uuid.UUID,
) {
	t.Helper()
	var createdBy, owner uuid.UUID
	var owners int
	if err := persistence.pool.QueryRow(ctx, `
		SELECT c.created_by,m.user_id,(
			SELECT count(*) FROM conversation_members counted
			WHERE counted.conversation_id=c.id AND counted.role='owner'
		)
		FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id AND m.role='owner'
		WHERE c.id=$1`, conversationID,
	).Scan(&createdBy, &owner, &owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 || createdBy != wantOwner || owner != wantOwner {
		t.Fatalf(
			"ownership invariant: created_by=%s owner=%s owners=%d want=%s",
			createdBy, owner, owners, wantOwner,
		)
	}
}
