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

func TestSessionIssueRejectsStalePasswordAndDeletedUser(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "stale-login@example.com", PasswordHash: "old-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	staleHash := user.PasswordHash // password verification completed here
	persistence.mu.Lock()
	updated := persistence.users[user.ID]
	updated.PasswordHash = "new-hash" // reset wins before issuance
	persistence.users[user.ID] = updated
	persistence.mu.Unlock()
	params := testSessionIssue(user.ID, staleHash)
	if _, _, err := persistence.IssueSession(ctx, params); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("stale verified hash issued a session: %v", err)
	}
	if len(persistence.sessions) != 0 || len(persistence.devices) != 0 {
		t.Fatal("failed stale login partially persisted device or session")
	}

	second, _ := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "deleted-login@example.com", PasswordHash: "hash",
	})
	if err := persistence.DeleteAccount(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := persistence.IssueSession(ctx, testSessionIssue(second.ID, "hash")); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("deleted account issued a session: %v", err)
	}
}

func testSessionIssue(userID uuid.UUID, expectedHash string) store.SessionIssueParams {
	now := time.Now().UTC()
	deviceID := uuid.New()
	return store.SessionIssueParams{
		UserID: userID, ExpectedPasswordHash: expectedHash, RequirePasswordHashMatch: true,
		Device: domain.Device{ID: deviceID, UserID: userID, Name: "iPhone", Platform: "ios", CreatedAt: now},
		Session: domain.Session{
			ID: uuid.New(), UserID: userID, DeviceID: deviceID,
			RefreshTokenHash: []byte("refresh-hash"), CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		},
	}
}
