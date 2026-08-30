package memory

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func (s *Store) CreatePasswordResetChallenge(_ context.Context, challenge domain.PasswordResetChallenge) error {
	return s.createPasswordResetChallenge(challenge, nil)
}

func (s *Store) CreatePasswordResetChallengeWithMail(
	_ context.Context,
	challenge domain.PasswordResetChallenge,
	buildMail store.MailDeliveryBuilder,
) error {
	if buildMail == nil {
		return domain.ErrInvalid
	}
	return s.createPasswordResetChallenge(challenge, buildMail)
}

func (s *Store) createPasswordResetChallenge(
	challenge domain.PasswordResetChallenge,
	buildMail store.MailDeliveryBuilder,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[challenge.UserID]
	if !ok {
		return domain.ErrNotFound
	}
	var delivery *domain.MailDelivery
	if buildMail != nil {
		built, err := buildMail(user.Email)
		if err != nil {
			return err
		}
		if !validMailDelivery(built, domain.MailDeliveryPasswordReset, challenge.ID) {
			return domain.ErrInvalid
		}
		delivery = &built
	}
	now := time.Now().UTC()
	for id, existing := range s.passwordResets {
		if existing.UserID == challenge.UserID && existing.ConsumedAt == nil {
			existing.ConsumedAt = &now
			s.passwordResets[id] = existing
			for deliveryID, queued := range s.mailDeliveries {
				if queued.ChallengeID == id && queued.Status == domain.MailDeliveryPending {
					queued.Status = domain.MailDeliveryCanceled
					queued.LeaseToken = uuid.Nil
					queued.LockedUntil = time.Time{}
					queued.CanceledAt = &now
					queued.LastErrorClass = "superseded"
					s.mailDeliveries[deliveryID] = queued
				}
			}
		}
	}
	s.passwordResets[challenge.ID] = challenge
	if delivery != nil {
		copyDelivery := *delivery
		copyDelivery.Ciphertext = append([]byte(nil), delivery.Ciphertext...)
		s.mailDeliveries[delivery.ID] = copyDelivery
	}
	return nil
}

func (s *Store) CancelPasswordResetChallenge(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.passwordResets, id)
	for deliveryID, delivery := range s.mailDeliveries {
		if delivery.ChallengeID == id {
			delete(s.mailDeliveries, deliveryID)
		}
	}
	return nil
}

func (s *Store) ConsumePasswordResetChallenge(
	_ context.Context,
	id uuid.UUID,
	codeHash []byte,
	newPasswordHash string,
	maxAttempts int,
) (string, error) {
	return s.consumePasswordResetChallenge(id, codeHash, newPasswordHash, maxAttempts, nil)
}

func (s *Store) ConsumePasswordResetChallengeWithMail(
	_ context.Context,
	id uuid.UUID,
	codeHash []byte,
	newPasswordHash string,
	maxAttempts int,
	buildMail store.MailDeliveryBuilder,
) (string, error) {
	if buildMail == nil {
		return "", domain.ErrInvalid
	}
	return s.consumePasswordResetChallenge(id, codeHash, newPasswordHash, maxAttempts, buildMail)
}

func (s *Store) consumePasswordResetChallenge(
	id uuid.UUID,
	codeHash []byte,
	newPasswordHash string,
	maxAttempts int,
	buildMail store.MailDeliveryBuilder,
) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	challenge, ok := s.passwordResets[id]
	now := time.Now().UTC()
	if !ok || challenge.ConsumedAt != nil || !challenge.ExpiresAt.After(now) ||
		challenge.Attempts >= maxAttempts {
		return "", domain.ErrUnauthenticated
	}
	if len(challenge.CodeHash) != len(codeHash) ||
		subtle.ConstantTimeCompare(challenge.CodeHash, codeHash) != 1 {
		challenge.Attempts++
		s.passwordResets[id] = challenge
		return "", domain.ErrUnauthenticated
	}
	user, ok := s.users[challenge.UserID]
	if !ok || user.PasswordHash == "" {
		return "", domain.ErrUnauthenticated
	}
	var delivery *domain.MailDelivery
	if buildMail != nil {
		built, err := buildMail(user.Email)
		if err != nil {
			return "", err
		}
		if !validMailDelivery(built, domain.MailDeliveryPasswordChanged, id) {
			return "", domain.ErrInvalid
		}
		delivery = &built
	}
	for deliveryID, queued := range s.mailDeliveries {
		if queued.ChallengeID == id && queued.Purpose == domain.MailDeliveryPasswordReset &&
			queued.Status == domain.MailDeliveryPending {
			queued.Status = domain.MailDeliveryCanceled
			queued.LeaseToken = uuid.Nil
			queued.LockedUntil = time.Time{}
			queued.CanceledAt = &now
			queued.LastErrorClass = "challenge_consumed"
			s.mailDeliveries[deliveryID] = queued
		}
	}
	user.PasswordHash = newPasswordHash
	user.UpdatedAt = now
	s.users[user.ID] = user
	for sessionID, session := range s.sessions {
		if session.UserID == user.ID && session.RevokedAt == nil {
			session.RevokedAt = &now
			s.sessions[sessionID] = session
		}
	}
	for deviceID, device := range s.devices {
		if device.UserID == user.ID {
			device.PushToken = ""
			s.devices[deviceID] = device
		}
	}
	for challengeID, existing := range s.passwordResets {
		if existing.UserID == user.ID && existing.ConsumedAt == nil {
			existing.ConsumedAt = &now
			s.passwordResets[challengeID] = existing
		}
	}
	if delivery != nil {
		copyDelivery := *delivery
		copyDelivery.Ciphertext = append([]byte(nil), delivery.Ciphertext...)
		s.mailDeliveries[delivery.ID] = copyDelivery
	}
	return user.Email, nil
}

func validMailDelivery(delivery domain.MailDelivery, purpose string, challengeID uuid.UUID) bool {
	return delivery.ID != uuid.Nil && delivery.ChallengeID == challengeID &&
		delivery.Purpose == purpose && len(delivery.Ciphertext) >= 29
}
