package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	memberReplay := p
	memberReplay.OperationID = uuid.New()
	memberReplay.ActorID = member.ID
	memberReplay.ExpectedChoreVersion = 2
	memberReplay.FeedPayload = json.RawMessage(`{"id":"` + memberReplay.OperationID.String() + `","groupId":"` + c.ID.String() + `","type":"note","relatedId":"` + choreID.String() + `"}`)
	memberReplayHash := sha256.Sum256(append(append([]byte(nil), memberReplay.ChorePayload...), memberReplay.FeedPayload...))
	memberReplay.RequestHash = memberReplayHash[:]
	if result, err := persistence.RotateChore(ctx, memberReplay); err != nil || result.Chore.Version != 3 {
		t.Fatalf("member rotation=%+v err=%v", result, err)
	}
	if err := persistence.RemoveConversationMember(ctx, c.ID, owner.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RotateChore(ctx, memberReplay); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("removed member replay=%v", err)
	}
	otherActor := memberReplay
	otherActor.ActorID = owner.ID
	if _, err := persistence.RotateChore(ctx, otherActor); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("other actor operation reuse=%v", err)
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

func TestPostgresRotateChoreRechecksMembershipAfterConversationAuthorityLock(t *testing.T) {
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

	owner, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@rotation-race.test"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@rotation-race.test"})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: owner.ID, MemberIDs: []uuid.UUID{member.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	choreID, operationID := uuid.New(), uuid.New()
	original := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + conversation.ID.String() + `","assignedTo":"` + owner.ID.String() + `","rotateOrder":["` + owner.ID.String() + `","` + member.ID.String() + `"]}`)
	chore, err := persistence.PutEntity(ctx, domain.Entity{
		ConversationID: conversation.ID, Kind: "chore", ID: choreID,
		Payload: original, CreatedBy: owner.ID,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	proposed := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + conversation.ID.String() + `","assignedTo":"` + member.ID.String() + `","rotateOrder":["` + owner.ID.String() + `","` + member.ID.String() + `"]}`)
	feed := json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + conversation.ID.String() + `","type":"note","relatedId":"` + choreID.String() + `"}`)
	digest := sha256.Sum256(append(append([]byte(nil), proposed...), feed...))
	command := store.RotateChoreParams{
		OperationID: operationID, ConversationID: conversation.ID, ChoreID: choreID,
		ActorID: member.ID, ExpectedChoreVersion: chore.Version,
		ChorePayload: proposed, FeedPayload: feed, RequestHash: digest[:],
	}

	var baselineOutbox int
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox_events WHERE aggregate_id=$1`, conversation.ID,
	).Scan(&baselineOutbox); err != nil {
		t.Fatal(err)
	}

	// Hold the membership authority while making the removal visible only to
	// its transaction. The old ordering observed the still-committed membership
	// first, then waited here and incorrectly mutated after the removal commit.
	removal, err := persistence.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer removal.Rollback(ctx)
	var lockedConversation uuid.UUID
	if err := removal.QueryRow(ctx,
		`SELECT id FROM conversations WHERE id=$1 FOR UPDATE`, conversation.ID,
	).Scan(&lockedConversation); err != nil {
		t.Fatal(err)
	}
	if _, err := removal.Exec(ctx,
		`DELETE FROM conversation_members WHERE conversation_id=$1 AND user_id=$2`,
		conversation.ID, member.ID,
	); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, rotateErr := persistence.RotateChore(ctx, command)
		done <- rotateErr
	}()
	<-started
	select {
	case rotateErr := <-done:
		t.Fatalf("rotation escaped conversation authority before removal commit: %v", rotateErr)
	case <-time.After(200 * time.Millisecond):
	}
	if err := removal.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case rotateErr := <-done:
		if !errors.Is(rotateErr, domain.ErrForbidden) {
			t.Fatalf("rotation after committed removal=%v", rotateErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rotation did not resume after removal committed")
	}

	var finalVersion int64
	var feedCount, operationCount, finalOutbox int
	if err := persistence.pool.QueryRow(ctx,
		`SELECT version FROM entities WHERE conversation_id=$1 AND kind='chore' AND id=$2`,
		conversation.ID, choreID,
	).Scan(&finalVersion); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM entities WHERE conversation_id=$1 AND kind='feed_item' AND id=$2`,
		conversation.ID, operationID,
	).Scan(&feedCount); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM chore_rotation_operations WHERE operation_id=$1`, operationID,
	).Scan(&operationCount); err != nil {
		t.Fatal(err)
	}
	if err := persistence.pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox_events WHERE aggregate_id=$1`, conversation.ID,
	).Scan(&finalOutbox); err != nil {
		t.Fatal(err)
	}
	if finalVersion != chore.Version || feedCount != 0 || operationCount != 0 || finalOutbox != baselineOutbox {
		t.Fatalf("removed actor mutated state: version=%d feed=%d operation=%d outbox=%d baseline_outbox=%d",
			finalVersion, feedCount, operationCount, finalOutbox, baselineOutbox)
	}
}

func TestPostgresPruneChoreRotationOperationsIsBoundedAndReplaySafe(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	owner, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@rotation-prune.test"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := persistence.CreateConversation(ctx, store.CreateConversationParams{Kind: "group", CreatedBy: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	choreID := uuid.New()
	original := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + c.ID.String() + `","assignedTo":"` + owner.ID.String() + `"}`)
	chore, err := persistence.PutEntity(ctx, domain.Entity{ConversationID: c.ID, Kind: "chore", ID: choreID, Payload: original, CreatedBy: owner.ID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	operations := make([]uuid.UUID, 0, 4)
	var retainedCommand store.RotateChoreParams
	for i := 0; i < 4; i++ {
		op := uuid.New()
		feed := json.RawMessage(`{"id":"` + op.String() + `","groupId":"` + c.ID.String() + `","relatedId":"` + choreID.String() + `","type":"note"}`)
		hash := sha256.Sum256(append(append([]byte(nil), original...), feed...))
		command := store.RotateChoreParams{OperationID: op, ConversationID: c.ID, ChoreID: choreID, ActorID: owner.ID, ExpectedChoreVersion: chore.Version, ChorePayload: original, FeedPayload: feed, RequestHash: hash[:]}
		result, rotateErr := persistence.RotateChore(ctx, command)
		if rotateErr != nil {
			t.Fatal(rotateErr)
		}
		chore = result.Chore
		operations = append(operations, op)
		retainedCommand = command
	}
	cutoff := time.Now().UTC()
	if _, err := persistence.pool.Exec(ctx, `UPDATE chore_rotation_operations SET expires_at=$2 WHERE operation_id=ANY($1)`, operations[:3], cutoff.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.pool.Exec(ctx, `UPDATE chore_rotation_operations SET expires_at=$2 WHERE operation_id=$1`, operations[3], cutoff.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	replayDone := make(chan error, 1)
	go func() {
		_, replayErr := persistence.RotateChore(ctx, retainedCommand)
		replayDone <- replayErr
	}()
	if deleted, err := persistence.PruneChoreRotationOperations(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("concurrent prune deleted=%d err=%v", deleted, err)
	}
	if replayErr := <-replayDone; replayErr != nil {
		t.Fatalf("unexpired concurrent replay=%v", replayErr)
	}
	if deleted, err := persistence.PruneChoreRotationOperations(ctx, cutoff, 2); err != nil || deleted != 2 {
		t.Fatalf("second bounded prune deleted=%d err=%v", deleted, err)
	}
	if deleted, err := persistence.PruneChoreRotationOperations(ctx, cutoff, 2); err != nil || deleted != 0 {
		t.Fatalf("idempotent prune deleted=%d err=%v", deleted, err)
	}
	if deleted, err := persistence.PruneChoreRotationOperations(ctx, cutoff.Add(24*time.Hour), 2); err != nil || deleted != 0 {
		t.Fatalf("future caller cutoff deleted=%d err=%v", deleted, err)
	}
	var surviving int
	if err := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM chore_rotation_operations WHERE operation_id=$1`, operations[3]).Scan(&surviving); err != nil || surviving != 1 {
		t.Fatalf("unexpired operation count=%d err=%v", surviving, err)
	}
}

func TestPostgresRotateChoreSerializesWithDeleteEntityBothWinners(t *testing.T) {
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

	setup := func(t *testing.T) (domain.User, domain.Conversation, domain.Entity, store.RotateChoreParams) {
		owner, createErr := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@rotation-delete.test"})
		if createErr != nil {
			t.Fatal(createErr)
		}
		conversation, createErr := persistence.CreateConversation(ctx, store.CreateConversationParams{Kind: "group", CreatedBy: owner.ID})
		if createErr != nil {
			t.Fatal(createErr)
		}
		choreID, operationID := uuid.New(), uuid.New()
		payload := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + conversation.ID.String() + `","assignedTo":"` + owner.ID.String() + `"}`)
		chore, createErr := persistence.PutEntity(ctx, domain.Entity{ConversationID: conversation.ID, Kind: "chore", ID: choreID, CreatedBy: owner.ID, Payload: payload}, nil)
		if createErr != nil {
			t.Fatal(createErr)
		}
		feed := json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + conversation.ID.String() + `","relatedId":"` + choreID.String() + `","type":"note"}`)
		digest := sha256.Sum256(append(append([]byte(nil), payload...), feed...))
		return owner, conversation, chore, store.RotateChoreParams{OperationID: operationID, ConversationID: conversation.ID, ChoreID: choreID, ActorID: owner.ID, ExpectedChoreVersion: chore.Version, ChorePayload: payload, FeedPayload: feed, RequestHash: digest[:]}
	}
	waitFor := func(t *testing.T, query string, args ...any) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var ready bool
			if queryErr := persistence.pool.QueryRow(ctx, query, args...).Scan(&ready); queryErr == nil && ready {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("timed out waiting for deterministic database lock barrier")
	}

	t.Run("delete wins", func(t *testing.T) {
		owner, conversation, chore, command := setup(t)
		if _, deleteErr := persistence.DeleteEntity(ctx, conversation.ID, owner.ID, "chore", chore.ID, &chore.Version); deleteErr != nil {
			t.Fatal(deleteErr)
		}
		if _, rotateErr := persistence.RotateChore(ctx, command); !errors.Is(rotateErr, domain.ErrNotFound) {
			t.Fatalf("rotation after delete=%v", rotateErr)
		}
		var feedCount, operationCount, updatedOutbox int
		if queryErr := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM entities WHERE conversation_id=$1 AND kind='feed_item' AND id=$2`, conversation.ID, command.OperationID).Scan(&feedCount); queryErr != nil {
			t.Fatal(queryErr)
		}
		if queryErr := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM chore_rotation_operations WHERE operation_id=$1`, command.OperationID).Scan(&operationCount); queryErr != nil {
			t.Fatal(queryErr)
		}
		if queryErr := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id=$1 AND topic='entity.updated'`, conversation.ID).Scan(&updatedOutbox); queryErr != nil {
			t.Fatal(queryErr)
		}
		if feedCount != 0 || operationCount != 0 || updatedOutbox != 1 {
			t.Fatalf("partial rotation feed=%d operation=%d updated_outbox=%d", feedCount, operationCount, updatedOutbox)
		}
	})

	t.Run("rotation wins", func(t *testing.T) {
		owner, conversation, chore, command := setup(t)
		lockKey := int64(734198265)
		name := "rotation_barrier_" + fmt.Sprintf("%x", command.OperationID[:4])
		function := name + "_fn"
		functionDDL := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id='%s'::uuid AND NEW.payload IS DISTINCT FROM OLD.payload THEN PERFORM pg_advisory_xact_lock(%d); END IF; RETURN NEW; END $$`, function, chore.ID, lockKey)
		if _, ddlErr := persistence.pool.Exec(ctx, functionDDL); ddlErr != nil {
			t.Fatal(ddlErr)
		}
		defer persistence.pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, function))
		triggerDDL := fmt.Sprintf(`CREATE TRIGGER %s BEFORE UPDATE ON entities FOR EACH ROW EXECUTE FUNCTION %s()`, name, function)
		if _, ddlErr := persistence.pool.Exec(ctx, triggerDDL); ddlErr != nil {
			t.Fatal(ddlErr)
		}
		defer persistence.pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON entities`, name))
		locker, acquireErr := persistence.pool.Acquire(ctx)
		if acquireErr != nil {
			t.Fatal(acquireErr)
		}
		defer locker.Release()
		if _, acquireErr = locker.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); acquireErr != nil {
			t.Fatal(acquireErr)
		}
		defer locker.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey)
		rotateDone := make(chan error, 1)
		go func() {
			_, rotateErr := persistence.RotateChore(ctx, command)
			rotateDone <- rotateErr
		}()
		waitFor(t, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'UPDATE entities SET version=version+1,payload=%')`)
		deleteDone := make(chan error, 1)
		go func() {
			_, deleteErr := persistence.DeleteEntity(ctx, conversation.ID, owner.ID, "chore", chore.ID, &chore.Version)
			deleteDone <- deleteErr
		}()
		waitFor(t, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%SELECT version FROM entities%')`)
		if _, releaseErr := locker.Exec(ctx, `SELECT pg_advisory_unlock($1)`, lockKey); releaseErr != nil {
			t.Fatal(releaseErr)
		}
		if rotateErr := <-rotateDone; rotateErr != nil {
			t.Fatal(rotateErr)
		}
		if deleteErr := <-deleteDone; !errors.Is(deleteErr, domain.ErrConflict) {
			t.Fatalf("delete after rotation=%v", deleteErr)
		}
		var feedCount, operationCount, rotationOutbox int
		if queryErr := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM entities WHERE conversation_id=$1 AND kind='feed_item' AND id=$2`, conversation.ID, command.OperationID).Scan(&feedCount); queryErr != nil {
			t.Fatal(queryErr)
		}
		if queryErr := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM chore_rotation_operations WHERE operation_id=$1`, command.OperationID).Scan(&operationCount); queryErr != nil {
			t.Fatal(queryErr)
		}
		if queryErr := persistence.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_id=$1 AND topic='entity.updated'`, conversation.ID).Scan(&rotationOutbox); queryErr != nil {
			t.Fatal(queryErr)
		}
		if feedCount != 1 || operationCount != 1 || rotationOutbox != 3 {
			t.Fatalf("feed=%d operation=%d updated_outbox=%d", feedCount, operationCount, rotationOutbox)
		}
	})
}
