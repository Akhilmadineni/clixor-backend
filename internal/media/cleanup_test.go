package media

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/google/uuid"
)

func TestPendingCleanupDrainsMoreThanOneBatch(t *testing.T) {
	ctx := context.Background()
	persistence := memory.New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: "cleanup@example.com"})
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
	limits.MaxPendingCountPerUser = 10
	limits.MaxPendingCountConversation = 10
	for index := 0; index < 5; index++ {
		id := uuid.New()
		if _, err := persistence.CreateMedia(ctx, domain.MediaObject{
			ID: id, OwnerID: user.ID, ConversationID: conversation.ID,
			ObjectKey: "cleanup/" + id.String(), ContentType: "application/octet-stream",
			ByteSize: 1, CiphertextSHA256: testSHA256,
		}, limits); err != nil {
			t.Fatal(err)
		}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	expired := cleanupPendingAt(
		ctx, persistence, time.Now().UTC().Add(10*time.Minute), 2, logger,
	)
	if expired != 5 {
		t.Fatalf("expired=%d want=5", expired)
	}
}
