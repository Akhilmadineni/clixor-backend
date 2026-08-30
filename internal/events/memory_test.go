package events

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestMemorySessionFenceTargetsEveryOwnerAndClosesRegistrationRace(t *testing.T) {
	for range 100 {
		bus := NewMemoryBus()
		userID, sessionID := uuid.New(), uuid.New()
		var fenced atomic.Bool
		start := make(chan struct{})
		var owner SessionOwner
		var ticket SessionFenceTicket
		var registerErr, fenceErr error
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			owner, registerErr = bus.RegisterSessionOwner(context.Background(), userID, sessionID, func(got *uuid.UUID) {
				if got != nil && *got == sessionID {
					fenced.Store(true)
				}
			})
		}()
		go func() {
			defer group.Done()
			<-start
			var err error
			ticket, err = bus.FenceSessions(context.Background(), userID, &sessionID)
			fenceErr = err
		}()
		close(start)
		group.Wait()
		if registerErr != nil || fenceErr != nil || !fenced.Load() {
			t.Fatalf("register/fence race escaped: register=%v fence=%v fenced=%t", registerErr, fenceErr, fenced.Load())
		}
		if ticket != nil {
			_ = ticket.Release(context.Background())
		}
		_ = owner.Close()
		bus.Close()
	}
}

func TestMemorySessionFenceDoesNotFenceDifferentSession(t *testing.T) {
	bus := NewMemoryBus()
	userID, first, second := uuid.New(), uuid.New(), uuid.New()
	var firstFenced, secondFenced atomic.Bool
	one, _ := bus.RegisterSessionOwner(context.Background(), userID, first, func(got *uuid.UUID) {
		if got == nil || *got == first {
			firstFenced.Store(true)
		}
	})
	two, _ := bus.RegisterSessionOwner(context.Background(), userID, second, func(got *uuid.UUID) {
		if got == nil || *got == second {
			secondFenced.Store(true)
		}
	})
	defer one.Close()
	defer two.Close()
	ticket, err := bus.FenceSessions(context.Background(), userID, &first)
	if err != nil {
		t.Fatal(err)
	}
	defer ticket.Release(context.Background())
	if !firstFenced.Load() || secondFenced.Load() {
		t.Fatalf("targeting first=%t second=%t", firstFenced.Load(), secondFenced.Load())
	}
}

func TestConcurrentScopedFenceTicketsDoNotOverwriteAndReleasePromptly(t *testing.T) {
	bus := NewMemoryBus()
	userID, first, second := uuid.New(), uuid.New(), uuid.New()
	firstTicket, err := bus.FenceSessions(context.Background(), userID, &first)
	if err != nil {
		t.Fatal(err)
	}
	secondTicket, err := bus.FenceSessions(context.Background(), userID, &second)
	if err != nil {
		t.Fatal(err)
	}
	var firstFenced, secondFenced atomic.Bool
	one, _ := bus.RegisterSessionOwner(context.Background(), userID, first, func(*uuid.UUID) { firstFenced.Store(true) })
	two, _ := bus.RegisterSessionOwner(context.Background(), userID, second, func(*uuid.UUID) { secondFenced.Store(true) })
	defer one.Close()
	defer two.Close()
	if !firstFenced.Load() || !secondFenced.Load() {
		t.Fatal("concurrent fence marker was overwritten")
	}
	_ = firstTicket.Release(context.Background())
	var replacementFenced atomic.Bool
	replacement, _ := bus.RegisterSessionOwner(context.Background(), userID, first, func(*uuid.UUID) { replacementFenced.Store(true) })
	defer replacement.Close()
	if replacementFenced.Load() {
		t.Fatal("released session fence blocked an immediate replacement session")
	}
	_ = secondTicket.Release(context.Background())

	allTicket, err := bus.FenceSessions(context.Background(), userID, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = allTicket.Release(context.Background())
	var newSessionFenced atomic.Bool
	newOwner, _ := bus.RegisterSessionOwner(context.Background(), userID, uuid.New(), func(*uuid.UUID) { newSessionFenced.Store(true) })
	defer newOwner.Close()
	if newSessionFenced.Load() {
		t.Fatal("released reset fence blocked a new post-reset session")
	}
}
