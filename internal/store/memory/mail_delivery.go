package memory

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

const mailDeliveryLease = 2 * time.Minute

func (s *Store) LockMailDeliveryBatch(
	_ context.Context,
	limit int,
) ([]domain.MailDelivery, error) {
	if limit < 1 || limit > store.MaxRetentionPruneBatchSize {
		return nil, domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for id, delivery := range s.mailDeliveries {
		challenge, exists := s.passwordResets[delivery.ChallengeID]
		if delivery.Purpose != domain.MailDeliveryPasswordReset ||
			delivery.Status != domain.MailDeliveryPending || !exists ||
			(challenge.ConsumedAt == nil && challenge.ExpiresAt.After(now)) {
			continue
		}
		delivery.Status = domain.MailDeliveryCanceled
		delivery.LeaseToken = uuid.Nil
		delivery.LockedUntil = time.Time{}
		delivery.CanceledAt = &now
		delivery.LastErrorClass = "challenge_inactive"
		s.mailDeliveries[id] = delivery
	}
	candidates := make([]domain.MailDelivery, 0, len(s.mailDeliveries))
	for _, delivery := range s.mailDeliveries {
		if delivery.Status != domain.MailDeliveryPending || delivery.NextAttemptAt.After(now) ||
			(!delivery.LockedUntil.IsZero() && delivery.LockedUntil.After(now)) {
			continue
		}
		candidates = append(candidates, delivery)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].NextAttemptAt.Equal(candidates[j].NextAttemptAt) {
			return candidates[i].ID.String() < candidates[j].ID.String()
		}
		return candidates[i].NextAttemptAt.Before(candidates[j].NextAttemptAt)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	leaseToken := uuid.New()
	for index := range candidates {
		delivery := candidates[index]
		delivery.Attempts++
		delivery.LeaseToken = leaseToken
		delivery.LockedUntil = now.Add(mailDeliveryLease)
		delivery.Ciphertext = append([]byte(nil), delivery.Ciphertext...)
		s.mailDeliveries[delivery.ID] = delivery
		candidates[index] = delivery
	}
	return candidates, nil
}

func (s *Store) FinishMailDelivery(
	_ context.Context,
	id uuid.UUID,
	leaseToken uuid.UUID,
	result string,
	nextAttemptAt time.Time,
	errorClass string,
) error {
	switch result {
	case domain.MailDeliveryPending, domain.MailDeliveryDelivered,
		domain.MailDeliveryDeadLetter, domain.MailDeliveryCanceled:
	default:
		return domain.ErrInvalid
	}
	if id == uuid.Nil || leaseToken == uuid.Nil || !validMailErrorClass(errorClass) {
		return domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delivery, ok := s.mailDeliveries[id]
	if !ok || delivery.Status != domain.MailDeliveryPending || delivery.LeaseToken != leaseToken {
		return domain.ErrConflict
	}
	now := time.Now().UTC()
	if nextAttemptAt.IsZero() {
		nextAttemptAt = now
	}
	delivery.Status = result
	delivery.LeaseToken = uuid.Nil
	delivery.LockedUntil = time.Time{}
	delivery.LastErrorClass = errorClass
	delivery.DeliveredAt = nil
	delivery.DeadLetteredAt = nil
	delivery.CanceledAt = nil
	switch result {
	case domain.MailDeliveryPending:
		delivery.NextAttemptAt = nextAttemptAt
	case domain.MailDeliveryDelivered:
		delivery.DeliveredAt = &now
	case domain.MailDeliveryDeadLetter:
		delivery.DeadLetteredAt = &now
		if delivery.Purpose == domain.MailDeliveryPasswordReset {
			if challenge, exists := s.passwordResets[delivery.ChallengeID]; exists && challenge.ConsumedAt == nil {
				challenge.ConsumedAt = &now
				s.passwordResets[delivery.ChallengeID] = challenge
			}
		}
	case domain.MailDeliveryCanceled:
		delivery.CanceledAt = &now
	}
	s.mailDeliveries[id] = delivery
	return nil
}

func (s *Store) PruneMailDeliveries(
	_ context.Context,
	deliveredBefore, deadLetterBefore, canceledBefore time.Time,
	limit int,
) (int64, error) {
	if limit < 1 || limit > store.MaxRetentionPruneBatchSize {
		return 0, domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	type candidate struct {
		id uuid.UUID
		at time.Time
	}
	candidates := make([]candidate, 0, len(s.mailDeliveries))
	for id, delivery := range s.mailDeliveries {
		var eligibleAt time.Time
		switch {
		case delivery.Status == domain.MailDeliveryDelivered && delivery.DeliveredAt != nil &&
			delivery.DeliveredAt.Before(deliveredBefore):
			eligibleAt = *delivery.DeliveredAt
		case delivery.Status == domain.MailDeliveryDeadLetter && delivery.DeadLetteredAt != nil &&
			delivery.DeadLetteredAt.Before(deadLetterBefore):
			eligibleAt = *delivery.DeadLetteredAt
		case delivery.Status == domain.MailDeliveryCanceled && delivery.CanceledAt != nil &&
			delivery.CanceledAt.Before(canceledBefore):
			eligibleAt = *delivery.CanceledAt
		default:
			continue
		}
		candidates = append(candidates, candidate{id: id, at: eligibleAt})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].id.String() < candidates[j].id.String()
		}
		return candidates[i].at.Before(candidates[j].at)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	for _, candidate := range candidates {
		delete(s.mailDeliveries, candidate.id)
	}
	return int64(len(candidates)), nil
}

func validMailErrorClass(value string) bool {
	if len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && character != '_' {
			return false
		}
	}
	return true
}
