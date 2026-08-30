package events

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

func TestNATSSessionFenceAcrossReplicasAndFailsClosedOnBadOwners(t *testing.T) {
	url := os.Getenv("TEST_NATS_URL")
	if url == "" {
		t.Skip("TEST_NATS_URL is not configured")
	}
	first, err := NewNATS(url, "")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewNATS(url, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	userID, sessionID := uuid.New(), uuid.New()
	var firstFenced, secondFenced atomic.Bool
	one, err := first.RegisterSessionOwner(context.Background(), userID, sessionID, func(*uuid.UUID) { firstFenced.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	two, err := second.RegisterSessionOwner(context.Background(), userID, sessionID, func(*uuid.UUID) { secondFenced.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ticket, err := first.FenceSessions(ctx, userID, &sessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer ticket.Release(context.Background())
	if !firstFenced.Load() || !secondFenced.Load() {
		t.Fatalf("replicas fenced first=%t second=%t", firstFenced.Load(), secondFenced.Load())
	}

	ghost := "ghost-" + uuid.NewString()
	ghostKey := "u." + userID.String() + ".r." + ghost
	if _, err := first.kv.Put(ghostKey, []byte(ghost)); err != nil {
		t.Fatal(err)
	}
	defer first.kv.Delete(ghostKey)
	missingContext, missingCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer missingCancel()
	missingTicket, err := first.FenceSessions(missingContext, userID, &sessionID)
	if missingTicket != nil {
		defer missingTicket.Release(context.Background())
	}
	if err == nil {
		t.Fatalf("missing acknowledgement did not fail closed: %v", err)
	}
	_ = first.kv.Delete(ghostKey)

	badReplica := "bad-" + uuid.NewString()
	badKey := "u." + userID.String() + ".r." + badReplica
	sub, err := first.conn.Subscribe("realtime.control."+badReplica, func(message *nats.Msg) { _ = message.Respond([]byte(`{}`)) })
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := first.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.kv.Put(badKey, []byte(badReplica)); err != nil {
		t.Fatal(err)
	}
	defer first.kv.Delete(badKey)
	badContext, badCancel := context.WithTimeout(context.Background(), time.Second)
	defer badCancel()
	badTicket, err := first.FenceSessions(badContext, userID, &sessionID)
	if badTicket != nil {
		defer badTicket.Release(context.Background())
	}
	if err == nil {
		t.Fatal("malformed acknowledgement did not fail closed")
	}
}
