package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestMembershipActivityPersistsAndAccountErasureRemovesIt(t *testing.T) {
	db := os.Getenv("TEST_DATABASE_URL")
	if db == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx := context.Background()
	s, err := Open(ctx, db, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner, err := s.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := s.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateConversation(ctx, store.CreateConversationParams{Kind: "group", CreatedBy: owner.ID, MemberIDs: []uuid.UUID{member.ID}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.UpsertDevice(ctx, domain.Device{ID: uuid.New(), UserID: owner.ID, Platform: "ios", PushToken: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveConversationMember(ctx, group.ID, member.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	var eventID int64
	if err := s.pool.QueryRow(ctx, `SELECT id FROM outbox_events WHERE aggregate_id=$1 AND topic='conversation.member_removed' AND payload->>'user_id'=$2`, group.ID, member.ID.String()).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	// The new topic must be compatible with erasure, including durable retries.
	if count, err := s.EnqueuePushDeliveries(ctx, domain.PushDelivery{OutboxEventID: eventID, ConversationID: group.ID, EntityID: group.ID, NotificationID: uuid.NewString(), Title: "Clixor", Body: "You have new activity. Open the app to view it.", Kind: "member_left"}, []uuid.UUID{owner.ID}); err != nil || count != 1 {
		t.Fatalf("enqueue: %d %v", count, err)
	}
	if err := s.DeleteAccount(ctx, member.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE id=$1`, eventID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("erasure left member event: %d %v", count, err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM push_deliveries WHERE outbox_event_id=$1`, eventID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("erasure left retry: %d %v", count, err)
	}
}
