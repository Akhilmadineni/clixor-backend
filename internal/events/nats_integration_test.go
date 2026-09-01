package events

import (
	"context"
	"encoding/json"
	"os"
	"sync"
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
	ghostGeneration := uuid.NewString()
	ghostKey := "r." + ghost + ".g." + ghostGeneration
	ghostLease, _ := json.Marshal(ownerLease{ReplicaID: ghost, Generation: ghostGeneration})
	if _, err := first.ownerKV.Put(ghostKey, ghostLease); err != nil {
		t.Fatal(err)
	}
	defer first.ownerKV.Delete(ghostKey)
	missingContext, missingCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer missingCancel()
	missingTicket, err := first.FenceSessions(missingContext, userID, &sessionID)
	if missingTicket != nil {
		defer missingTicket.Release(context.Background())
	}
	if err == nil {
		t.Fatalf("missing acknowledgement did not fail closed: %v", err)
	}
	_ = first.ownerKV.Delete(ghostKey)

	badReplica := "bad-" + uuid.NewString()
	badGeneration := uuid.NewString()
	badKey := "r." + badReplica + ".g." + badGeneration
	sub, err := first.conn.Subscribe(controlSubject(badReplica, badGeneration), func(message *nats.Msg) { _ = message.Respond([]byte(`{}`)) })
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := first.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	badLease, _ := json.Marshal(ownerLease{ReplicaID: badReplica, Generation: badGeneration})
	if _, err := first.ownerKV.Put(badKey, badLease); err != nil {
		t.Fatal(err)
	}
	defer first.ownerKV.Delete(badKey)
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

func TestNATSMarkerClosesFirstOwnerRaceAndOutlivesLegacyLeaseWindow(t *testing.T) {
	url := os.Getenv("TEST_NATS_URL")
	if url == "" {
		t.Skip("TEST_NATS_URL is not configured")
	}
	fencer, err := NewNATS(url, "")
	if err != nil {
		t.Fatal(err)
	}
	defer fencer.Close()
	ownerBus, err := NewNATS(url, "")
	if err != nil {
		t.Fatal(err)
	}
	defer ownerBus.Close()
	userID, sessionID := uuid.New(), uuid.New()
	ticket, err := fencer.FenceSessions(context.Background(), userID, &sessionID)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a replica that dies without running Close. Its generation lease
	// must age out of the fanout snapshot instead of blocking later fences.
	abandoned, err := NewNATS(url, "")
	if err != nil {
		t.Fatal(err)
	}
	abandonedKey := abandoned.replicaLeaseKey()
	abandoned.conn.Close()
	defer abandoned.Close()
	// The old shared owner lease expired after 15 seconds. A distinct durable
	// fence bucket must still reject a registration held beyond that window.
	time.Sleep(16 * time.Second)
	var fenced atomic.Bool
	owner, err := ownerBus.RegisterSessionOwner(context.Background(), userID, sessionID, func(*uuid.UUID) {
		fenced.Store(true)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if !fenced.Load() {
		t.Fatal("held fence marker missed first owner registration")
	}
	expiryContext, expiryCancel := context.WithTimeout(context.Background(), time.Second)
	expiryTicket, expiryErr := fencer.FenceSessions(expiryContext, uuid.New(), nil)
	expiryCancel()
	if expiryTicket != nil {
		defer expiryTicket.Release(context.Background())
	}
	if expiryErr != nil {
		t.Fatalf("expired abandoned replica lease remained in fanout (%s): %v", abandonedKey, expiryErr)
	}
	if err := ticket.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNATSGenerationLeasePreventsABAAndRefreshFailureFencesLocally(t *testing.T) {
	url := os.Getenv("TEST_NATS_URL")
	if url == "" {
		t.Skip("TEST_NATS_URL is not configured")
	}
	first, err := NewNATS(url, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewNATS(url, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	userID := uuid.New()
	firstOwner, err := first.RegisterSessionOwner(context.Background(), userID, uuid.New(), func(*uuid.UUID) {})
	if err != nil {
		t.Fatal(err)
	}
	secondOwner, err := second.RegisterSessionOwner(context.Background(), userID, uuid.New(), func(*uuid.UUID) {})
	if err != nil {
		t.Fatal(err)
	}
	defer secondOwner.Close()
	secondKey := second.replicaLeaseKey()
	// Publish a replacement generation under the same replica identity. Closing
	// generation A may remove only its exact key, never generation B (ABA).
	replacementGeneration := uuid.NewString()
	replacementKey := "r." + first.replicaID + ".g." + replacementGeneration
	replacementLease, _ := json.Marshal(ownerLease{
		ReplicaID: first.replicaID, Generation: replacementGeneration,
	})
	if _, err := first.ownerKV.Put(replacementKey, replacementLease); err != nil {
		t.Fatal(err)
	}
	if err := firstOwner.Close(); err != nil {
		t.Fatal(err)
	}
	first.Close()
	if _, err := second.ownerKV.Get(secondKey); err != nil {
		t.Fatalf("old generation cleanup deleted replacement lease: %v", err)
	}
	if _, err := second.ownerKV.Get(replacementKey); err != nil {
		t.Fatalf("generation A cleanup deleted same-replica generation B lease: %v", err)
	}
	if err := second.ownerKV.Delete(replacementKey); err != nil {
		t.Fatalf("remove synthetic replacement lease: %v", err)
	}

	failing, err := NewNATS(url, "")
	if err != nil {
		t.Fatal(err)
	}
	var fenced atomic.Bool
	owner, err := failing.RegisterSessionOwner(context.Background(), uuid.New(), uuid.New(), func(*uuid.UUID) {
		fenced.Store(true)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	failing.conn.Close()
	deadline := time.Now().Add(2 * realtimeOwnerRefresh)
	for !fenced.Load() && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if !fenced.Load() || owner.Valid() {
		t.Fatalf("lease refresh failure did not fail closed: fenced=%t valid=%t", fenced.Load(), owner.Valid())
	}
	// The failed process cannot clean its own lease. Remove the synthetic crash
	// residue through a surviving replica so this test does not poison later
	// fanout snapshots (production relies on the 15-second TTL instead).
	if err := second.ownerKV.Delete(failing.replicaLeaseKey()); err != nil {
		t.Fatalf("remove failed replica lease: %v", err)
	}
	failing.Close()
}

func TestNATSFenceFanoutUsesOneDeadline(t *testing.T) {
	url := os.Getenv("TEST_NATS_URL")
	if url == "" {
		t.Skip("TEST_NATS_URL is not configured")
	}
	bus, err := NewNATS(url, "")
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	userID := uuid.New()
	const replicas = 6
	var subscriptions []*nats.Subscription
	var keys []string
	for range replicas {
		replicaID, generation := uuid.NewString(), uuid.NewString()
		sub, err := bus.conn.Subscribe(controlSubject(replicaID, generation), func(message *nats.Msg) {
			var command fenceCommand
			_ = json.Unmarshal(message.Data, &command)
			time.Sleep(100 * time.Millisecond)
			ack, _ := json.Marshal(fenceAck{
				RequestID: command.RequestID, ReplicaID: replicaID, Generation: generation,
			})
			_ = message.Respond(ack)
		})
		if err != nil {
			t.Fatal(err)
		}
		subscriptions = append(subscriptions, sub)
		key := "r." + replicaID + ".g." + generation
		encoded, _ := json.Marshal(ownerLease{ReplicaID: replicaID, Generation: generation})
		if _, err := bus.ownerKV.Put(key, encoded); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	defer func() {
		for _, subscription := range subscriptions {
			_ = subscription.Unsubscribe()
		}
		for _, key := range keys {
			_ = bus.ownerKV.Delete(key)
		}
	}()
	if err := bus.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ticket, err := bus.FenceSessions(ctx, userID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ticket.Release(context.Background())
	if elapsed := time.Since(started); elapsed > 350*time.Millisecond {
		t.Fatalf("fence ACKs were serialized: elapsed=%s", elapsed)
	}
}

func TestNATSConcurrentFirstOwnerAndFenceCannotEscape(t *testing.T) {
	url := os.Getenv("TEST_NATS_URL")
	if url == "" {
		t.Skip("TEST_NATS_URL is not configured")
	}
	for range 20 {
		fencer, err := NewNATS(url, "")
		if err != nil {
			t.Fatal(err)
		}
		ownerBus, err := NewNATS(url, "")
		if err != nil {
			fencer.Close()
			t.Fatal(err)
		}
		userID, sessionID := uuid.New(), uuid.New()
		var fenced atomic.Bool
		start := make(chan struct{})
		var owner SessionOwner
		var ticket SessionFenceTicket
		var registerErr, fenceErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			owner, registerErr = ownerBus.RegisterSessionOwner(
				context.Background(), userID, sessionID, func(*uuid.UUID) { fenced.Store(true) },
			)
		}()
		go func() {
			defer wait.Done()
			<-start
			ticket, fenceErr = fencer.FenceSessions(context.Background(), userID, &sessionID)
		}()
		close(start)
		wait.Wait()
		if registerErr != nil || fenceErr != nil || !fenced.Load() {
			t.Fatalf("first-owner race escaped: register=%v fence=%v fenced=%t", registerErr, fenceErr, fenced.Load())
		}
		if ticket != nil {
			_ = ticket.Release(context.Background())
		}
		if owner != nil {
			_ = owner.Close()
		}
		ownerBus.Close()
		fencer.Close()
	}
}
