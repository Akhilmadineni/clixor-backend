package memory

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func (s *Store) CreatePasswordResetChallenge(_ context.Context, challenge domain.PasswordResetChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[challenge.UserID]; !ok {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	for id, existing := range s.passwordResets {
		if existing.UserID == challenge.UserID && existing.ConsumedAt == nil {
			existing.ConsumedAt = &now
			s.passwordResets[id] = existing
		}
	}
	s.passwordResets[challenge.ID] = challenge
	return nil
}

func (s *Store) CancelPasswordResetChallenge(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.passwordResets, id)
	return nil
}

func (s *Store) ConsumePasswordResetChallenge(
	_ context.Context,
	id uuid.UUID,
	codeHash []byte,
	newPasswordHash string,
	maxAttempts int,
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
	user.PasswordHash = newPasswordHash
	user.UpdatedAt = now
	s.users[user.ID] = user
	for sessionID, session := range s.sessions {
		if session.UserID == user.ID && session.RevokedAt == nil {
			session.RevokedAt = &now
			s.sessions[sessionID] = session
		}
	}
	for challengeID, existing := range s.passwordResets {
		if existing.UserID == user.ID && existing.ConsumedAt == nil {
			existing.ConsumedAt = &now
			s.passwordResets[challengeID] = existing
		}
	}
	return user.Email, nil
}
