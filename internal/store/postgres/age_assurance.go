package postgres

import (
	"context"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func (s *Store) AgeAssurance(ctx context.Context, userID uuid.UUID) (domain.AgeAssurance, error) {
	var assurance domain.AgeAssurance
	err := s.pool.QueryRow(ctx, `
		SELECT user_id,status,minimum_age,source,declaration,policy_version,checked_at,expires_at
		FROM age_assurances WHERE user_id=$1`, userID,
	).Scan(
		&assurance.UserID, &assurance.Status, &assurance.MinimumAge, &assurance.Source,
		&assurance.Declaration, &assurance.PolicyVersion, &assurance.CheckedAt, &assurance.ExpiresAt,
	)
	return assurance, mapError(err)
}

func (s *Store) UpsertAgeAssurance(ctx context.Context, assurance domain.AgeAssurance) (domain.AgeAssurance, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO age_assurances(
			user_id,status,minimum_age,source,declaration,policy_version,checked_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT(user_id) DO UPDATE SET
			status=EXCLUDED.status,
			minimum_age=EXCLUDED.minimum_age,
			source=EXCLUDED.source,
			declaration=EXCLUDED.declaration,
			policy_version=EXCLUDED.policy_version,
			checked_at=EXCLUDED.checked_at,
			expires_at=EXCLUDED.expires_at
		RETURNING user_id,status,minimum_age,source,declaration,policy_version,checked_at,expires_at`,
		assurance.UserID, assurance.Status, assurance.MinimumAge, assurance.Source,
		assurance.Declaration, assurance.PolicyVersion, assurance.CheckedAt, assurance.ExpiresAt,
	).Scan(
		&assurance.UserID, &assurance.Status, &assurance.MinimumAge, &assurance.Source,
		&assurance.Declaration, &assurance.PolicyVersion, &assurance.CheckedAt, &assurance.ExpiresAt,
	)
	return assurance, mapError(err)
}
