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

func TestMarkOutboxPublishedRetainsEventUntilRetentionPrune(t *testing.T) {
	persistence := New()
	persistence.appendOutbox("test.created", uuid.New(), []byte(`{"safe":true}`))
	batch, err := persistence.LockOutboxBatch(context.Background(), 1)
	if err != nil || len(batch) != 1 {
		t.Fatalf("lock initial outbox: batch=%+v error=%v", batch, err)
	}
	if err := persistence.MarkOutboxPublished(context.Background(), []int64{batch[0].ID}); err != nil {
		t.Fatal(err)
	}
	batch, err = persistence.LockOutboxBatch(context.Background(), 1)
	if err != nil || len(batch) != 0 {
		t.Fatalf("published outbox was claimable: batch=%+v error=%v", batch, err)
	}
	deleted, err := persistence.PrunePublishedOutbox(
		context.Background(), time.Now().UTC().Add(time.Hour), 1,
	)
	if err != nil || deleted != 1 {
		t.Fatalf("prune published outbox: deleted=%d error=%v", deleted, err)
	}
}

func TestRetentionPrunesTerminalPushBeforeReferencedOutbox(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-60 * 24 * time.Hour)
	recent := now.Add(-time.Hour)
	pendingSourceID := int64(1)
	terminalSourceID := int64(2)
	pendingPushSourceID := int64(3)
	recentSourceID := int64(4)
	persistence := New()
	persistence.outbox = []domain.OutboxEvent{
		{ID: pendingSourceID, Topic: "pending", CreatedAt: old},
		{ID: terminalSourceID, Topic: "terminal", CreatedAt: old, PublishedAt: retentionTime(old)},
		{ID: pendingPushSourceID, Topic: "pending_push", CreatedAt: old, PublishedAt: retentionTime(old)},
		{ID: recentSourceID, Topic: "recent", CreatedAt: recent, PublishedAt: retentionTime(recent)},
	}
	terminalDeviceID := uuid.New()
	pendingDeviceID := uuid.New()
	persistence.pushDeliveries[1] = domain.PushDelivery{
		ID: 1, OutboxEventID: terminalSourceID, DeviceID: terminalDeviceID,
		Status: domain.PushDeliveryDelivered, DeliveredAt: retentionTime(old),
	}
	persistence.pushDeliveryByEventDevice[pushDeliveryKey(terminalSourceID, terminalDeviceID)] = 1
	persistence.pushDeliveries[2] = domain.PushDelivery{
		ID: 2, OutboxEventID: pendingPushSourceID, DeviceID: pendingDeviceID,
		Status: domain.PushDeliveryPending,
	}
	persistence.pushDeliveryByEventDevice[pushDeliveryKey(pendingPushSourceID, pendingDeviceID)] = 2

	deleted, err := persistence.PrunePublishedOutbox(
		context.Background(), now.Add(-30*24*time.Hour), store.MaxRetentionPruneBatchSize,
	)
	if err != nil || deleted != 0 {
		t.Fatalf("referenced outbox pruned early: deleted=%d error=%v", deleted, err)
	}
	deleted, err = persistence.PrunePushDeliveries(
		context.Background(), now.Add(-24*time.Hour), now.Add(-30*24*time.Hour),
		store.MaxRetentionPruneBatchSize,
	)
	if err != nil || deleted != 1 {
		t.Fatalf("terminal push prune: deleted=%d error=%v", deleted, err)
	}
	if _, retained := persistence.pushDeliveries[2]; !retained {
		t.Fatal("pending push delivery was pruned")
	}
	deleted, err = persistence.PrunePublishedOutbox(
		context.Background(), now.Add(-30*24*time.Hour), store.MaxRetentionPruneBatchSize,
	)
	if err != nil || deleted != 1 {
		t.Fatalf("unreferenced source prune: deleted=%d error=%v", deleted, err)
	}
	for _, event := range persistence.outbox {
		if event.ID == terminalSourceID {
			t.Fatal("terminal source remained after its push delivery was pruned")
		}
	}
	if len(persistence.outbox) != 3 {
		t.Fatalf("retained outbox rows = %d, want 3", len(persistence.outbox))
	}
}

func TestRetentionPruningUsesBoundedOldestFirstBatches(t *testing.T) {
	now := time.Now().UTC()
	persistence := New()
	for id := int64(1); id <= 5; id++ {
		publishedAt := now.Add(-time.Duration(10-id) * time.Hour)
		persistence.outbox = append(persistence.outbox, domain.OutboxEvent{
			ID: id, Topic: "published", CreatedAt: publishedAt,
			PublishedAt: retentionTime(publishedAt),
		})
	}
	deleted, err := persistence.PrunePublishedOutbox(context.Background(), now, 2)
	if err != nil || deleted != 2 {
		t.Fatalf("first bounded prune: deleted=%d error=%v", deleted, err)
	}
	if len(persistence.outbox) != 3 || persistence.outbox[0].ID != 3 {
		t.Fatalf("oldest rows were not pruned first: %+v", persistence.outbox)
	}
	deleted, err = persistence.PrunePublishedOutbox(context.Background(), now, 2)
	if err != nil || deleted != 2 || len(persistence.outbox) != 1 {
		t.Fatalf("second bounded prune: deleted=%d retained=%d error=%v", deleted, len(persistence.outbox), err)
	}
}

func TestRetentionCanDrainMoreThanOneThousandMemoryRowsInBoundedBatches(t *testing.T) {
	now := time.Now().UTC()
	persistence := New()
	const rows = 2501
	for id := int64(1); id <= rows; id++ {
		publishedAt := now.Add(-time.Hour)
		persistence.outbox = append(persistence.outbox, domain.OutboxEvent{
			ID: id, Topic: "published", CreatedAt: publishedAt,
			PublishedAt: retentionTime(publishedAt),
		})
	}
	var total int64
	var batches []int64
	for {
		deleted, err := persistence.PrunePublishedOutbox(
			context.Background(), now, store.MaxRetentionPruneBatchSize,
		)
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, deleted)
		total += deleted
		if deleted < store.MaxRetentionPruneBatchSize {
			break
		}
	}
	if total != rows || len(persistence.outbox) != 0 {
		t.Fatalf("drained=%d retained=%d batches=%v", total, len(persistence.outbox), batches)
	}
	want := []int64{1000, 1000, 501}
	if len(batches) != len(want) {
		t.Fatalf("batches=%v want=%v", batches, want)
	}
	for index := range want {
		if batches[index] != want[index] {
			t.Fatalf("batches=%v want=%v", batches, want)
		}
	}
}

func TestRetentionPruneRejectsUnboundedLimits(t *testing.T) {
	persistence := New()
	for _, limit := range []int{0, -1, store.MaxRetentionPruneBatchSize + 1} {
		if _, err := persistence.PrunePushDeliveries(
			context.Background(), time.Now(), time.Now(), limit,
		); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("push prune limit %d returned %v", limit, err)
		}
		if _, err := persistence.PrunePublishedOutbox(
			context.Background(), time.Now(), limit,
		); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("outbox prune limit %d returned %v", limit, err)
		}
	}
}

func retentionTime(value time.Time) *time.Time {
	copy := value
	return &copy
}
