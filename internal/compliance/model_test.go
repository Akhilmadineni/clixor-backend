package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func testRelease() Release {
	doc := "<!doctype html><html><body><h1>Test policy</h1><p>" + strings.Repeat("Test text. ", 20) + "</p></body></html>"
	h := sha256.Sum256([]byte(doc))
	return Release{Policy: Policy{Enabled: true, Version: "test-1", DocumentSHA256: hex.EncodeToString(h[:]), TermsURL: "https://clixor.atlanteanz.com/terms", PrivacyURL: "https://clixor.atlanteanz.com/privacy", MinimumAge: 13, IntakeEnabled: true}, Operator: "Test Operator", State: "Test state", ContactEmail: "test@clixor.test", Reviewed: true, MonitoringReady: true, Document: doc}
}
func TestReleaseFailsClosed(t *testing.T) {
	if err := testRelease().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Release){
		"unreviewed": func(r *Release) { r.Reviewed = false }, "unmonitored": func(r *Release) { r.MonitoringReady = false },
		"placeholder": func(r *Release) { r.ContactEmail = "[SUPPORT_EMAIL]" }, "digest": func(r *Release) { r.Document += "x" },
		"draft": func(r *Release) { r.Document = "DRAFT" + r.Document }, "wrong age": func(r *Release) { r.MinimumAge = 18 },
		"host": func(r *Release) { r.TermsURL = "https://attacker.test/terms" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := testRelease()
			mutate(&r)
			if r.Validate() == nil {
				t.Fatal("invalid release accepted")
			}
		})
	}
}
func TestAcceptanceAgeAndVersionBoundaries(t *testing.T) {
	p := testRelease().Policy
	a := Acceptance{UserID: uuid.New(), Version: p.Version, DocumentSHA256: p.DocumentSHA256, AgeGroup: "minor_13_plus", GuardianPermission: true, Agreed: true}
	if err := a.Validate(p); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"under_13", "", "13_to_17", "adult"} {
		b := a
		b.AgeGroup = group
		if b.Validate(p) == nil {
			t.Fatalf("accepted %q", group)
		}
	}
	b := a
	b.GuardianPermission = false
	if b.Validate(p) == nil {
		t.Fatal("minor without permission accepted")
	}
	b = a
	b.Version = "old"
	if b.Validate(p) == nil {
		t.Fatal("stale version accepted")
	}
	b = a
	b.Agreed = false
	if b.Validate(p) == nil {
		t.Fatal("no affirmative agreement accepted")
	}
	b = a
	b.AgeGroup = "age_of_majority"
	b.GuardianPermission = false
	if err := b.Validate(p); err != nil {
		t.Fatal(err)
	}
}
func TestMemoryReceiptsAreIdempotentAndPrivate(t *testing.T) {
	ctx := context.Background()
	repo := NewMemory()
	now := time.Now().UTC()
	token := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	s := Submission{Category: "intimate_imagery", Contact: "reporter@clixor.test", ContentReference: "message identifier", Details: "Nonconsensual imagery report test", Signature: "Test Person", GoodFaith: true, Authorized: true}
	c, err := NewCase(uuid.New(), token, s, now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := repo.Submit(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	c.ReceivedAt = now.Add(time.Hour)
	retry, err := repo.Submit(ctx, c)
	if err != nil || !retry.ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatal("retry changed receipt")
	}
	if first.ReviewDueAt == nil || !first.ReviewDueAt.Equal(now.Add(48*time.Hour)) {
		t.Fatal("intimate imagery timer incorrect")
	}
	wrong, _ := TokenHash(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("y", 32))))
	if _, err = repo.Status(ctx, c.ID, wrong); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("wrong capability disclosed status")
	}
	c.RequestHash = make([]byte, 32)
	if _, err = repo.Submit(ctx, c); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("changed retry accepted")
	}
	r := Review{CaseID: c.ID, ExpectedStatus: "received", Status: "reviewing", Operator: "operator-1", Reason: "Taking ownership of test report"}
	if err = repo.Review(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err = repo.Review(ctx, r); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("stale review accepted")
	}
	if len(repo.reviews) != 1 {
		t.Fatal("review audit incorrect")
	}
}
func TestIntimateImageryRequiresStatutoryFields(t *testing.T) {
	s := Submission{Category: "intimate_imagery", Contact: "someone@clixor.test", Details: "A sufficiently detailed report"}
	if s.Validate() == nil {
		t.Fatal("incomplete intimate imagery notice accepted")
	}
	s.Category = "privacy_deletion"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Details = strings.Repeat("x", 8001)
	if s.Validate() == nil {
		t.Fatal("oversized report accepted")
	}
}
