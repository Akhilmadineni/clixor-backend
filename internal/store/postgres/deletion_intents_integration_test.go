package postgres

import (
	"context"
	"crypto/sha256"
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

func TestPostgresAccountDeletionIntentIsDurableAndConcurrent(t *testing.T) {
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
		Email: "delete-intent-" + uuid.NewString() + "@example.com", PasswordHash: "hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	requestID := uuid.New()
	tokenHash := sha256.Sum256([]byte("recovery-token"))
	intent := domain.AccountDeletionIntent{RequestID: requestID, UserID: user.ID, TokenHash: tokenHash[:]}
	if err := persistence.PutAccountDeletionIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := persistence.PutAccountDeletionIntent(ctx, intent); err != nil {
		t.Fatalf("idempotent intent registration: %v", err)
	}
	wrongHash := sha256.Sum256([]byte("wrong"))
	if err := persistence.ExecuteAccountDeletionIntent(ctx, requestID, wrongHash[:], func(uuid.UUID) error { return nil }); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("wrong capability returned %v, want not found", err)
	}
	var fences atomic.Int32
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- persistence.ExecuteAccountDeletionIntent(
				ctx, requestID, tokenHash[:], func(got uuid.UUID) error {
					if got != user.ID {
						t.Errorf("fenced user=%s want %s", got, user.ID)
					}
					fences.Add(1)
					return nil
				},
			)
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent execute failed: %v", err)
		}
	}
	if fences.Load() != 1 {
		t.Fatalf("mutation fenced %d times, want once", fences.Load())
	}
	if _, err := persistence.UserByID(ctx, user.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted account lookup=%v", err)
	}
}
