package memory

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestRotateChoreIsAtomicAuthoritativeAndReplaySafe(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	owner, _ := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@example.com"})
	member, _ := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@example.com"})
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{Kind: "group", CreatedBy: owner.ID, MemberIDs: []uuid.UUID{member.ID}})
	if err != nil {
		t.Fatal(err)
	}
	choreID, operationID := uuid.New(), uuid.New()
	original := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + conversation.ID.String() + `","createdBy":"` + owner.ID.String() + `","assignedTo":"` + owner.ID.String() + `","rotateOrder":["` + owner.ID.String() + `","` + member.ID.String() + `"]}`)
	chore, err := persistence.PutEntity(ctx, domain.Entity{ConversationID: conversation.ID, Kind: "chore", ID: choreID, Payload: original, CreatedBy: owner.ID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	proposed := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + conversation.ID.String() + `","createdBy":"` + owner.ID.String() + `","assignedTo":"` + member.ID.String() + `","rotateOrder":["` + owner.ID.String() + `","` + member.ID.String() + `"]}`)
	feed := json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + conversation.ID.String() + `","createdBy":"` + owner.ID.String() + `","relatedId":"` + choreID.String() + `","type":"note","title":"rotated"}`)
	hash := sha256.Sum256(append(append([]byte(nil), proposed...), feed...))
	p := store.RotateChoreParams{OperationID: operationID, ConversationID: conversation.ID, ChoreID: choreID, ActorID: owner.ID, ExpectedChoreVersion: chore.Version, ChorePayload: proposed, FeedPayload: feed, RequestHash: hash[:]}
	var wg sync.WaitGroup
	results := make(chan store.RotateChoreResult, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); r, e := persistence.RotateChore(ctx, p); results <- r; errs <- e }()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("concurrent replay: %v", e)
		}
	}
	for r := range results {
		if r.Chore.Version != chore.Version+1 || r.FeedItem.ID != operationID {
			t.Fatalf("non-authoritative replay: %+v", r)
		}
	}
	chores, _ := persistence.ListEntities(ctx, conversation.ID, owner.ID, "chore", time.Time{}, 10)
	feeds, _ := persistence.ListEntities(ctx, conversation.ID, owner.ID, "feed_item", time.Time{}, 10)
	if len(chores) != 1 || chores[0].Version != 2 || len(feeds) != 1 {
		t.Fatalf("duplicate/partial write: chores=%+v feeds=%+v", chores, feeds)
	}

	bad := p
	bad.FeedPayload = json.RawMessage(`{"different":true}`)
	other := sha256.Sum256(bad.FeedPayload)
	bad.RequestHash = other[:]
	if _, err := persistence.RotateChore(ctx, bad); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("operation body reuse=%v", err)
	}
	if err := persistence.RemoveConversationMember(ctx, conversation.ID, owner.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RotateChore(ctx, p); err != nil {
		t.Fatalf("durable replay after membership change: %v", err)
	}
	newOp := p
	newOp.OperationID = uuid.New()
	newOp.ActorID = member.ID
	newOp.FeedPayload = json.RawMessage(`{"id":"` + newOp.OperationID.String() + `","groupId":"` + conversation.ID.String() + `","relatedId":"` + choreID.String() + `","type":"note"}`)
	newHash := sha256.Sum256(newOp.FeedPayload)
	newOp.RequestHash = newHash[:]
	if _, err := persistence.RotateChore(ctx, newOp); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("removed member mutation=%v", err)
	}
}

func TestRotateChoreDeleteAndInvalidParticipantLeaveNoFeed(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	owner, _ := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@x.test"})
	c, _ := persistence.CreateConversation(ctx, store.CreateConversationParams{Kind: "group", CreatedBy: owner.ID})
	id := uuid.New()
	e, _ := persistence.PutEntity(ctx, domain.Entity{ConversationID: c.ID, Kind: "chore", ID: id, CreatedBy: owner.ID, Payload: json.RawMessage(`{"assignedTo":"` + owner.ID.String() + `"}`)}, nil)
	_, _ = persistence.DeleteEntity(ctx, c.ID, owner.ID, "chore", id, &e.Version)
	p := store.RotateChoreParams{OperationID: uuid.New(), ConversationID: c.ID, ChoreID: id, ActorID: owner.ID, ExpectedChoreVersion: e.Version, ChorePayload: json.RawMessage(`{}`), FeedPayload: json.RawMessage(`{}`), RequestHash: make([]byte, 32)}
	p.ChorePayload = json.RawMessage(`{"id":"` + id.String() + `","groupId":"` + c.ID.String() + `"}`)
	p.FeedPayload = json.RawMessage(`{"id":"` + p.OperationID.String() + `","groupId":"` + c.ID.String() + `","relatedId":"` + id.String() + `","type":"note"}`)
	if _, err := persistence.RotateChore(ctx, p); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted chore=%v", err)
	}
	feeds, _ := persistence.ListEntities(ctx, c.ID, owner.ID, "feed_item", time.Time{}, 10)
	if len(feeds) != 0 {
		t.Fatal("partial feed write")
	}
}

func TestRotateChoreFeedConflictRollsBackChore(t *testing.T) {
	ctx := context.Background()
	persistence := New()
	owner, _ := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@x.test"})
	c, _ := persistence.CreateConversation(ctx, store.CreateConversationParams{Kind: "group", CreatedBy: owner.ID})
	choreID, op := uuid.New(), uuid.New()
	base := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + c.ID.String() + `","assignedTo":"` + owner.ID.String() + `"}`)
	chore, _ := persistence.PutEntity(ctx, domain.Entity{ConversationID: c.ID, Kind: "chore", ID: choreID, CreatedBy: owner.ID, Payload: base}, nil)
	_, _ = persistence.PutEntity(ctx, domain.Entity{ConversationID: c.ID, Kind: "feed_item", ID: op, CreatedBy: owner.ID, Payload: json.RawMessage(`{"existing":true}`)}, nil)
	feed := json.RawMessage(`{"id":"` + op.String() + `","groupId":"` + c.ID.String() + `","relatedId":"` + choreID.String() + `","type":"note"}`)
	h := sha256.Sum256(feed)
	_, err := persistence.RotateChore(ctx, store.RotateChoreParams{OperationID: op, ConversationID: c.ID, ChoreID: choreID, ActorID: owner.ID, ExpectedChoreVersion: chore.Version, ChorePayload: base, FeedPayload: feed, RequestHash: h[:]})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("feed collision=%v", err)
	}
	items, _ := persistence.ListEntities(ctx, c.ID, owner.ID, "chore", time.Time{}, 10)
	if len(items) != 1 || items[0].Version != chore.Version {
		t.Fatalf("chore mutated on failure: %+v", items)
	}
}
