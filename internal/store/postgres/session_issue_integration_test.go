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

func TestPostgresSessionIssueRejectsResetAndDeleteStaleLogins(t *testing.T) {
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
		Email: "pg-stale-" + uuid.NewString() + "@example.com", PasswordHash: "old-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.pool.Exec(ctx, `UPDATE users SET password_hash='new-hash' WHERE id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := persistence.IssueSession(ctx, postgresTestSessionIssue(user.ID, "old-hash")); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("stale verified hash issued a session: %v", err)
	}
	deleted, _ := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "pg-deleted-" + uuid.NewString() + "@example.com", PasswordHash: "hash",
	})
	if err := persistence.DeleteAccount(ctx, deleted.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := persistence.IssueSession(ctx, postgresTestSessionIssue(deleted.ID, "hash")); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("deleted account issued a session: %v", err)
	}
}

func postgresTestSessionIssue(userID uuid.UUID, expected string) store.SessionIssueParams {
	now := time.Now().UTC()
	deviceID := uuid.New()
	return store.SessionIssueParams{
		UserID: userID, ExpectedPasswordHash: expected, RequirePasswordHashMatch: true,
		Device: domain.Device{ID: deviceID, UserID: userID, Name: "iPhone", Platform: "ios", CreatedAt: now},
		Session: domain.Session{
			ID: uuid.New(), UserID: userID, DeviceID: deviceID,
			RefreshTokenHash: []byte("refresh-hash"), CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		},
	}
}
