package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/compliance"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresComplianceDurabilityAndAtomicRegistration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := Open(ctx, dsn, true)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	repo := p.Compliance()
	a := compliance.Acceptance{Version: "integration-1", DocumentSHA256: strings.Repeat("a", 64), AgeGroup: "minor_13_plus", GuardianPermission: true, Agreed: true}
	email := "legal-" + uuid.NewString() + "@example.com"
	user, err := p.CreateUser(ctx, store.CreateUserParams{Email: email, LegalAcceptance: &a})
	if err != nil {
		t.Fatal(err)
	}
	a.UserID = user.ID
	other, err := p.CreateUser(ctx, store.CreateUserParams{Email: "block-" + uuid.NewString() + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.DeleteAccount(context.Background(), other.ID)
	if err = repo.SetBlock(ctx, user.ID, other.ID, true); err != nil {
		t.Fatal(err)
	}
	if blocked, err := repo.Blocked(ctx, other.ID, user.ID); err != nil || !blocked {
		t.Fatal("block was not bidirectional")
	}
	called := false
	if allowed, err := repo.DeliverIfAllowed(ctx, other.ID, user.ID, func() error { called = true; return nil }); err != nil || allowed || called {
		t.Fatal("blocked external delivery was allowed")
	}
	if ids, err := repo.Blocks(ctx, user.ID); err != nil || len(ids) != 1 || ids[0] != other.ID {
		t.Fatal("block list was not durable")
	}
	if err = repo.SetBlock(ctx, user.ID, other.ID, false); err != nil {
		t.Fatal(err)
	}
	if allowed, err := repo.DeliverIfAllowed(ctx, other.ID, user.ID, func() error { called = true; return nil }); err != nil || !allowed || !called {
		t.Fatal("unblock did not restore delivery")
	}
	first, err := repo.Acceptance(ctx, user.ID, a.Version)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := repo.Accept(ctx, a)
	if err != nil || !replayed.AcceptedAt.Equal(first.AcceptedAt) {
		t.Fatal("receipt not idempotent")
	}
	a.GuardianPermission = false
	badEmail := "legal-invalid-" + uuid.NewString() + "@example.com"
	if _, err = p.CreateUser(ctx, store.CreateUserParams{Email: badEmail, LegalAcceptance: &a}); err == nil {
		t.Fatal("invalid receipt transaction succeeded")
	}
	if _, err = p.UserByEmail(ctx, badEmail); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("failed legal receipt left a user behind")
	}
	if err = p.DeleteAccount(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	a.GuardianPermission = true
	if _, err = repo.Accept(ctx, a); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("deleted identity accepted terms")
	}
	id := uuid.New()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	c, err := compliance.NewCase(id, token, compliance.Submission{Category: "intimate_imagery", Contact: "reporter@example.com", ContentReference: "test-content-id", Details: "Nonconsensual content test report", Signature: "Test Reporter", GoodFaith: true, Authorized: true}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = p.pool.Exec(context.Background(), `DELETE FROM compliance_reviews WHERE case_id=$1`, id)
		_, _ = p.pool.Exec(context.Background(), `DELETE FROM compliance_cases WHERE id=$1`, id)
	}()
	status, err := repo.Submit(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Submit(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.RequestHash = make([]byte, 32)
	if _, err = repo.Submit(ctx, c); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("changed idempotency request accepted")
	}
	if _, err = repo.Status(ctx, id, make([]byte, 32)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("wrong secret disclosed report")
	}
	r := compliance.Review{CaseID: id, ExpectedStatus: "received", Status: "reviewing", Operator: "test-operator", Reason: "Reviewing the test notice", PublicUpdate: "Review started"}
	if err = repo.Review(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err = repo.Review(ctx, r); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("stale operator update accepted")
	}
	var count int
	if err = p.pool.QueryRow(ctx, `SELECT count(*) FROM compliance_reviews WHERE case_id=$1`, id).Scan(&count); err != nil || count != 1 {
		t.Fatal("audit log is not atomic")
	}
	updated, err := p.Compliance().Status(ctx, id, c.TokenHash)
	if err != nil || updated.Status != "reviewing" || !updated.ReceivedAt.Equal(status.ReceivedAt) {
		t.Fatal("case was not durable across repository objects")
	}
}
