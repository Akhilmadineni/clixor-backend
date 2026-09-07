package compliance

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct{ pool *pgxpool.Pool }

func NewPostgres(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }
func dbError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func (p *Postgres) Accept(ctx context.Context, a Acceptance) (Acceptance, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Acceptance{}, err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	// Serialize with account deletion, preventing new receipts for a tombstone.
	if err = tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, a.UserID).Scan(&id); err != nil {
		return Acceptance{}, dbError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO legal_acceptances(user_id,version,document_sha256,age_group,guardian_permission)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT(user_id,version) DO NOTHING`, a.UserID, a.Version, a.DocumentSHA256, a.AgeGroup, a.GuardianPermission)
	if err != nil {
		return Acceptance{}, err
	}
	old, err := scanAcceptance(tx.QueryRow(ctx, `SELECT user_id,version,document_sha256,age_group,guardian_permission,accepted_at
		FROM legal_acceptances WHERE user_id=$1 AND version=$2`, a.UserID, a.Version))
	if err != nil {
		return Acceptance{}, err
	}
	if old.DocumentSHA256 != a.DocumentSHA256 || old.AgeGroup != a.AgeGroup || old.GuardianPermission != a.GuardianPermission {
		return Acceptance{}, domain.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return Acceptance{}, err
	}
	return old, nil
}
func scanAcceptance(row pgx.Row) (Acceptance, error) {
	var a Acceptance
	err := row.Scan(&a.UserID, &a.Version, &a.DocumentSHA256, &a.AgeGroup, &a.GuardianPermission, &a.AcceptedAt)
	a.Agreed = true
	return a, dbError(err)
}
func (p *Postgres) Acceptance(ctx context.Context, id uuid.UUID, version string) (Acceptance, error) {
	return scanAcceptance(p.pool.QueryRow(ctx, `SELECT a.user_id,a.version,a.document_sha256,a.age_group,a.guardian_permission,a.accepted_at
		FROM legal_acceptances a JOIN users u ON u.id=a.user_id WHERE a.user_id=$1 AND a.version=$2 AND u.deleted_at IS NULL`, id, version))
}
func (p *Postgres) Submit(ctx context.Context, c Case) (CaseStatus, error) {
	submission, err := json.Marshal(c.Submission)
	if err != nil {
		return CaseStatus{}, err
	}
	// Conditional no-op UPDATE returns the original receipt on a genuine retry.
	// A collision cannot overwrite a report or transfer its status capability.
	status, err := scanStatus(p.pool.QueryRow(ctx, `INSERT INTO compliance_cases(id,token_hash,request_hash,submission,received_at,review_due_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$5) ON CONFLICT(id) DO UPDATE SET id=compliance_cases.id
		WHERE compliance_cases.token_hash=EXCLUDED.token_hash AND compliance_cases.request_hash=EXCLUDED.request_hash
		RETURNING id,status,received_at,review_due_at,updated_at,public_update`, c.ID, c.TokenHash, c.RequestHash, submission, c.ReceivedAt, c.ReviewDueAt))
	if errors.Is(err, domain.ErrNotFound) {
		return CaseStatus{}, domain.ErrConflict
	}
	return status, err
}
func scanStatus(row pgx.Row) (CaseStatus, error) {
	var c CaseStatus
	err := row.Scan(&c.ID, &c.Status, &c.ReceivedAt, &c.ReviewDueAt, &c.UpdatedAt, &c.PublicUpdate)
	return c, dbError(err)
}
func (p *Postgres) Status(ctx context.Context, id uuid.UUID, hash []byte) (CaseStatus, error) {
	return scanStatus(p.pool.QueryRow(ctx, `SELECT id,status,received_at,review_due_at,updated_at,public_update FROM compliance_cases WHERE id=$1 AND token_hash=$2`, id, hash))
}
func (p *Postgres) ListCases(ctx context.Context, limit int) ([]Case, error) {
	if limit < 1 || limit > 100 {
		return nil, domain.ErrInvalid
	}
	rows, err := p.pool.Query(ctx, `SELECT id,submission,status,received_at,review_due_at,updated_at,public_update
		FROM compliance_cases WHERE status NOT IN ('resolved','declined') ORDER BY review_due_at NULLS LAST,received_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cases := make([]Case, 0)
	for rows.Next() {
		var c Case
		var raw []byte
		if err = rows.Scan(&c.ID, &raw, &c.Status, &c.ReceivedAt, &c.ReviewDueAt, &c.UpdatedAt, &c.PublicUpdate); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &c.Submission); err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, rows.Err()
}
func (p *Postgres) Review(ctx context.Context, r Review) error {
	if err := r.Validate(); err != nil {
		return err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `UPDATE compliance_cases SET status=$3,public_update=$4,updated_at=now() WHERE id=$1 AND status=$2`, r.CaseID, r.ExpectedStatus, r.Status, r.PublicUpdate)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return domain.ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO compliance_reviews(case_id,operator_id,previous_status,next_status,reason,public_update) VALUES($1,$2,$3,$4,$5,$6)`, r.CaseID, r.Operator, r.ExpectedStatus, r.Status, r.Reason, r.PublicUpdate)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
