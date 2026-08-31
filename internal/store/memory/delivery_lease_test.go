package memory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestRealtimeDeliveryLeaseSerializesAccountErasure(t *testing.T) {
	t.Run("publish first", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		persistence, user, event := memoryRealtimeErasureFixture(t, ctx)
		callbackStarted := make(chan struct{})
		releaseCallback := make(chan struct{})
		deliveryDone := make(chan error, 1)
		go func() {
			deliveryDone <- persistence.DeliverRealtimeOutbox(
				ctx, event.ID, event.Attempts,
				func(callbackContext context.Context, leased domain.OutboxEvent) error {
					if leased.ID != event.ID {
						return fmt.Errorf("leased event=%d want=%d", leased.ID, event.ID)
					}
					if _, err := persistence.UserByID(callbackContext, user.ID); err != nil {
						return err
					}
					close(callbackStarted)
					select {
					case <-callbackContext.Done():
						return callbackContext.Err()
					case <-releaseCallback:
						return nil
					}
				},
			)
		}()
		<-callbackStarted
		deletionStarted := make(chan struct{})
		deletionDone := make(chan error, 1)
		go func() {
			close(deletionStarted)
			deletionDone <- persistence.DeleteAccount(ctx, user.ID)
		}()
		<-deletionStarted
		select {
		case err := <-deletionDone:
			t.Fatalf("erasure crossed an active realtime callback: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
		close(releaseCallback)
		if err := <-deliveryDone; err != nil {
			t.Fatal(err)
		}
		if err := <-deletionDone; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("erasure first", func(t *testing.T) {
		ctx := context.Background()
		persistence, user, event := memoryRealtimeErasureFixture(t, ctx)
		if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
			t.Fatal(err)
		}
		called := false
		err := persistence.DeliverRealtimeOutbox(
			ctx, event.ID, event.Attempts,
			func(context.Context, domain.OutboxEvent) error {
				called = true
				return nil
			},
		)
		if !errors.Is(err, domain.ErrNotFound) || called {
			t.Fatalf("delivery after erasure: called=%t err=%v", called, err)
		}
	})
}

func TestPushDeliveryLeaseSerializesAccountErasure(t *testing.T) {
	t.Run("publish first", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		persistence, user, delivery := memoryPushErasureFixture(t, ctx)
		callbackStarted := make(chan struct{})
		releaseCallback := make(chan struct{})
		deliveryDone := make(chan error, 1)
		go func() {
			deliveryDone <- persistence.WithPushDeliveryLease(
				ctx, delivery.ID, delivery.LeaseToken,
				func(callbackContext context.Context, leased domain.PushDelivery) error {
					if leased.ID != delivery.ID || leased.PushToken == "" {
						return fmt.Errorf("invalid leased push: %+v", leased)
					}
					if _, err := persistence.UserByID(callbackContext, user.ID); err != nil {
						return err
					}
					close(callbackStarted)
					select {
					case <-callbackContext.Done():
						return callbackContext.Err()
					case <-releaseCallback:
						return nil
					}
				},
			)
		}()
		<-callbackStarted
		deletionStarted := make(chan struct{})
		deletionDone := make(chan error, 1)
		go func() {
			close(deletionStarted)
			deletionDone <- persistence.DeleteAccount(ctx, user.ID)
		}()
		<-deletionStarted
		select {
		case err := <-deletionDone:
			t.Fatalf("erasure crossed an active APNs callback: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
		close(releaseCallback)
		if err := <-deliveryDone; err != nil {
			t.Fatal(err)
		}
		if err := <-deletionDone; err != nil {
			t.Fatal(err)
		}
		persistence.mu.RLock()
		_, survived := persistence.pushDeliveries[delivery.ID]
		persistence.mu.RUnlock()
		if survived {
			t.Fatal("push delivery to erased account survived")
		}
	})

	t.Run("erasure first", func(t *testing.T) {
		ctx := context.Background()
		persistence, user, delivery := memoryPushErasureFixture(t, ctx)
		if err := persistence.DeleteAccount(ctx, user.ID); err != nil {
			t.Fatal(err)
		}
		called := false
		err := persistence.WithPushDeliveryLease(
			ctx, delivery.ID, delivery.LeaseToken,
			func(context.Context, domain.PushDelivery) error {
				called = true
				return nil
			},
		)
		if !errors.Is(err, domain.ErrNotFound) || called {
			t.Fatalf("push after erasure: called=%t err=%v", called, err)
		}
	})
}

func TestPushDeliveryLeasePinsDeviceTokenOwnershipThroughCallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	persistence, _, delivery := memoryPushErasureFixture(t, ctx)
	newOwner, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "New owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	newDevice := domain.Device{
		ID: uuid.New(), UserID: newOwner.ID, Name: "new iPhone", Platform: "ios",
		PushToken: delivery.PushToken, IdentityKey: "new-identity", CreatedAt: time.Now().UTC(),
	}
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	deliveryDone := make(chan error, 1)
	go func() {
		deliveryDone <- persistence.WithPushDeliveryLease(
			ctx, delivery.ID, delivery.LeaseToken,
			func(callbackContext context.Context, leased domain.PushDelivery) error {
				if leased.PushToken != delivery.PushToken {
					return fmt.Errorf("leased token=%q want=%q", leased.PushToken, delivery.PushToken)
				}
				close(callbackStarted)
				select {
				case <-callbackContext.Done():
					return callbackContext.Err()
				case <-releaseCallback:
					return nil
				}
			},
		)
	}()
	<-callbackStarted
	transferDone := make(chan error, 1)
	go func() {
		_, transferErr := persistence.UpsertDevice(ctx, newDevice)
		transferDone <- transferErr
	}()
	select {
	case err := <-transferDone:
		t.Fatalf("token ownership changed during APNs callback: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseCallback)
	if err := <-deliveryDone; err != nil {
		t.Fatal(err)
	}
	if err := <-transferDone; err != nil {
		t.Fatal(err)
	}
	transferred, err := persistence.Device(ctx, newOwner.ID, newDevice.ID)
	if err != nil || transferred.PushToken != delivery.PushToken {
		t.Fatalf("token transfer after callback: device=%+v err=%v", transferred, err)
	}
}

func memoryRealtimeErasureFixture(
	t *testing.T,
	ctx context.Context,
) (*Store, domain.User, domain.OutboxEvent) {
	t.Helper()
	persistence := New()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: uuid.NewString() + "@example.com", DisplayName: "Lease User",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	}); err != nil {
		t.Fatal(err)
	}
	batch, err := persistence.LockRealtimeOutboxBatch(ctx, 1)
	if err != nil || len(batch) != 1 {
		t.Fatalf("claim realtime: batch=%+v err=%v", batch, err)
	}
	return persistence, user, batch[0]
}

func memoryPushErasureFixture(
	t *testing.T,
	ctx context.Context,
) (*Store, domain.User, domain.PushDelivery) {
	t.Helper()
	persistence, user, event := memoryRealtimeErasureFixture(t, ctx)
	device, err := persistence.UpsertDevice(ctx, domain.Device{
		ID: uuid.New(), UserID: user.ID, Name: "iPhone", Platform: "ios",
		PushToken: "lease-push-token", IdentityKey: "identity", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := persistence.EnqueuePushDeliveries(ctx, domain.PushDelivery{
		OutboxEventID: event.ID, ConversationID: event.AggregateID, EntityID: uuid.New(),
		NotificationID: uuid.NewString(), Title: "generic", Body: "generic", Kind: "activity",
	}, []uuid.UUID{user.ID})
	if err != nil || inserted != 1 {
		t.Fatalf("enqueue push: inserted=%d err=%v device=%s", inserted, err, device.ID)
	}
	batch, err := persistence.LockPushDeliveryBatch(ctx, 1)
	if err != nil || len(batch) != 1 {
		t.Fatalf("claim push: batch=%+v err=%v", batch, err)
	}
	return persistence, user, batch[0]
}
