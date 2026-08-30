package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresRotateChoreConcurrentReplayAndRollback(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	owner, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@rotation.test"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@rotation.test"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := persistence.CreateConversation(ctx, store.CreateConversationParams{Kind: "group", CreatedBy: owner.ID, MemberIDs: []uuid.UUID{member.ID}})
	if err != nil {
		t.Fatal(err)
	}
	choreID, op := uuid.New(), uuid.New()
	original := json.RawMessage(`{"assignedTo":"` + owner.ID.String() + `","rotateOrder":["` + owner.ID.String() + `","` + member.ID.String() + `"]}`)
	e, err := persistence.PutEntity(ctx, domain.Entity{ConversationID: c.ID, Kind: "chore", ID: choreID, Payload: original, CreatedBy: owner.ID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	proposed := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + c.ID.String() + `","assignedTo":"` + member.ID.String() + `","rotateOrder":["` + owner.ID.String() + `","` + member.ID.String() + `"]}`)
	feed := json.RawMessage(`{"id":"` + op.String() + `","groupId":"` + c.ID.String() + `","type":"note","relatedId":"` + choreID.String() + `"}`)
	h := sha256.Sum256(append(append([]byte(nil), proposed...), feed...))
	p := store.RotateChoreParams{OperationID: op, ConversationID: c.ID, ChoreID: choreID, ActorID: owner.ID, ExpectedChoreVersion: e.Version, ChorePayload: proposed, FeedPayload: feed, RequestHash: h[:]}
	const racers = 12
	var wg sync.WaitGroup
	errorsCh := make(chan error, racers)
	results := make(chan store.RotateChoreResult, racers)
	for range racers {
		wg.Add(1)
		go func() { defer wg.Done(); r, e := persistence.RotateChore(ctx, p); errorsCh <- e; results <- r }()
	}
	wg.Wait()
	close(errorsCh)
	close(results)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent replay: %v", err)
		}
	}
	for result := range results {
		if result.Chore.Version != 2 || result.FeedItem.ID != op {
			t.Fatalf("wrong replay result: %+v", result)
		}
	}
	var choreCount, feedCount, outboxCount, operationCount int
	if err := persistence.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind='chore'),count(*) FILTER (WHERE kind='feed_item') FROM entities WHERE conversation_id=$1`, c.ID).Scan(&choreCount, &feedCount); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id=$1 AND topic='entity.updated'`, c.ID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM chore_rotation_operations WHERE operation_id=$1`, op).Scan(&operationCount); err != nil {
		t.Fatal(err)
	}
	// One generic chore creation plus exactly two command outbox records.
	if choreCount != 1 || feedCount != 1 || outboxCount != 3 || operationCount != 1 {
		t.Fatalf("counts chore=%d feed=%d outbox=%d operation=%d", choreCount, feedCount, outboxCount, operationCount)
	}
	restarted, err := Open(ctx, databaseURL, false)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.RotateChore(ctx, p)
	restarted.Close()
	if err != nil || replayed.Chore.Version != 2 || replayed.FeedItem.ID != op {
		t.Fatalf("relaunch/lost-response replay=%+v err=%v", replayed, err)
	}
	collisionOp := uuid.New()
	if _, err := persistence.PutEntity(ctx, domain.Entity{ConversationID: c.ID, Kind: "feed_item", ID: collisionOp, CreatedBy: owner.ID, Payload: json.RawMessage(`{"existing":true}`)}, nil); err != nil {
		t.Fatal(err)
	}
	collisionFeed := json.RawMessage(`{"id":"` + collisionOp.String() + `","groupId":"` + c.ID.String() + `","type":"note","relatedId":"` + choreID.String() + `"}`)
	collisionHash := sha256.Sum256(collisionFeed)
	collision := store.RotateChoreParams{OperationID: collisionOp, ConversationID: c.ID, ChoreID: choreID, ActorID: owner.ID, ExpectedChoreVersion: 2, ChorePayload: proposed, FeedPayload: collisionFeed, RequestHash: collisionHash[:]}
	if _, err := persistence.RotateChore(ctx, collision); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("hard failure feed collision=%v", err)
	}
	var version int64
	if err := persistence.pool.QueryRow(ctx, `SELECT version FROM entities WHERE conversation_id=$1 AND kind='chore' AND id=$2`, c.ID, choreID).Scan(&version); err != nil || version != 2 {
		t.Fatalf("hard failure did not roll back chore: version=%d err=%v", version, err)
	}

	changed := p
	changed.ExpectedChoreVersion = 2
	changedHash := sha256.Sum256([]byte("changed"))
	changed.RequestHash = changedHash[:]
	if _, err := persistence.RotateChore(ctx, changed); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("body mismatch=%v", err)
	}
	deletedID := uuid.New()
	deleted, _ := persistence.PutEntity(ctx, domain.Entity{ConversationID: c.ID, Kind: "chore", ID: deletedID, Payload: original, CreatedBy: owner.ID}, nil)
	_, _ = persistence.DeleteEntity(ctx, c.ID, owner.ID, "chore", deletedID, &deleted.Version)
	missing := p
	missing.OperationID = uuid.New()
	missing.ChoreID = deletedID
	missing.ExpectedChoreVersion = deleted.Version
	missing.ChorePayload = json.RawMessage(`{"id":"` + deletedID.String() + `","groupId":"` + c.ID.String() + `"}`)
	missing.FeedPayload = json.RawMessage(`{"id":"` + missing.OperationID.String() + `","groupId":"` + c.ID.String() + `","type":"note","relatedId":"` + deletedID.String() + `"}`)
	missingHash := sha256.Sum256([]byte(missing.OperationID.String()))
	missing.RequestHash = missingHash[:]
	if _, err := persistence.RotateChore(ctx, missing); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete-between-read=%v", err)
	}
	if err := persistence.RemoveConversationMember(ctx, c.ID, owner.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	removed := p
	removed.OperationID = uuid.New()
	removed.ActorID = member.ID
	removed.FeedPayload = json.RawMessage(`{"id":"` + removed.OperationID.String() + `","groupId":"` + c.ID.String() + `","type":"note","relatedId":"` + choreID.String() + `"}`)
	removedHash := sha256.Sum256([]byte(removed.OperationID.String()))
	removed.RequestHash = removedHash[:]
	if _, err := persistence.RotateChore(ctx, removed); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("removed membership=%v", err)
	}
	if _, err := persistence.RotateChore(ctx, p); err != nil {
		t.Fatalf("lost-response replay after ACL change=%v", err)
	}
}
