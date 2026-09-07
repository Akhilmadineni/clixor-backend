// Package compliance implements intake and legal receipts, not legal adjudication.
// Reports never authorize deletion, disclosure, or account enforcement by themselves.
package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

type Policy struct {
	Enabled        bool   `json:"enabled"`
	Version        string `json:"version"`
	DocumentSHA256 string `json:"document_sha256"`
	TermsURL       string `json:"terms_url"`
	PrivacyURL     string `json:"privacy_url"`
	MinimumAge     int    `json:"minimum_age"`
	IntakeEnabled  bool   `json:"intake_enabled"`
}

// Release is an operator-controlled file, never supplied by an API client.
// Separate approvals make an accidental environment toggle insufficient to
// publish unfinished documents or open an unattended reporting inbox.
type Release struct {
	Policy
	Operator        string `json:"operator"`
	State           string `json:"state"`
	ContactEmail    string `json:"contact_email"`
	Reviewed        bool   `json:"reviewed"`
	MonitoringReady bool   `json:"monitoring_ready"`
	Document        string `json:"document_html"`
}

func (r Release) Validate() error {
	if !r.Enabled && !r.IntakeEnabled {
		return nil
	}
	for _, value := range []string{r.Operator, r.State, r.ContactEmail} {
		if placeholder(value) {
			return errors.New("legal release requires real operator and contact details")
		}
	}
	address, err := mail.ParseAddress(r.ContactEmail)
	if err != nil || address.Address != r.ContactEmail || strings.ContainsAny(r.ContactEmail, "\r\n") {
		return errors.New("legal release contact email is invalid")
	}
	if r.IntakeEnabled && !r.MonitoringReady {
		return errors.New("support intake requires monitored operations")
	}
	if !r.Enabled {
		return nil
	}
	if !r.Reviewed || r.MinimumAge != 13 || placeholder(r.Version) || len(r.Version) > 80 {
		return errors.New("legal policy requires reviewed version and minimum age 13")
	}
	if len(r.Document) < 100 || len(r.Document) > 256<<10 ||
		strings.Contains(strings.ToUpper(r.Document), "DRAFT") || strings.Contains(r.Document, "[EFFECTIVE_DATE]") {
		return errors.New("legal document is incomplete")
	}
	for _, token := range []string{"[SUPPORT_", "[PRIVACY_", "[SAFETY_", "[DMCA_", "[BUSINESS_", "[OPERATOR_", "[TRACKING_", "[Release note:"} {
		if strings.Contains(r.Document, token) {
			return errors.New("legal document contains placeholders")
		}
	}
	for path, raw := range map[string]string{"/terms": r.TermsURL, "/privacy": r.PrivacyURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host != "clixor.atlanteanz.com" || u.User != nil || u.RawQuery != "" ||
			u.Path != path || u.Fragment != "" {
			return errors.New("legal URL must use the existing public legal hostname")
		}
	}
	digest := sha256.Sum256([]byte(r.Document))
	if r.DocumentSHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("legal document digest does not match")
	}
	return nil
}

func placeholder(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "" || strings.ContainsAny(v, "[]<>\r\n") || strings.Contains(v, "replace") || strings.Contains(v, "placeholder") || strings.Contains(v, "example.")
}

type Acceptance struct {
	UserID             uuid.UUID `json:"user_id"`
	Version            string    `json:"version"`
	DocumentSHA256     string    `json:"document_sha256"`
	AgeGroup           string    `json:"age_group"`
	GuardianPermission bool      `json:"guardian_permission"`
	Agreed             bool      `json:"agreed"`
	AcceptedAt         time.Time `json:"accepted_at"`
}

// Declaration contains only client-controlled statements. It intentionally has
// no date of birth, government ID, user ID, or client-supplied acceptance time.
type Declaration struct {
	Version            string `json:"version"`
	DocumentSHA256     string `json:"document_sha256"`
	AgeGroup           string `json:"age_group"`
	GuardianPermission bool   `json:"guardian_permission"`
	Agreed             bool   `json:"agreed"`
}

func (d Declaration) Receipt(id uuid.UUID, now time.Time) Acceptance {
	return Acceptance{UserID: id, Version: d.Version, DocumentSHA256: d.DocumentSHA256, AgeGroup: d.AgeGroup, GuardianPermission: d.GuardianPermission, Agreed: d.Agreed, AcceptedAt: now}
}

func (a Acceptance) Validate(p Policy) error {
	if !p.Enabled || a.UserID == uuid.Nil || !a.Agreed || a.Version != p.Version || a.DocumentSHA256 != p.DocumentSHA256 {
		return domain.ErrInvalid
	}
	switch a.AgeGroup {
	case "minor_13_plus":
		if !a.GuardianPermission {
			return domain.ErrInvalid
		}
	case "age_of_majority":
		if a.GuardianPermission {
			return domain.ErrInvalid
		}
	default:
		return domain.ErrInvalid
	}
	return nil
}

type Submission struct {
	Category         string `json:"category"`
	Contact          string `json:"contact"`
	ContentReference string `json:"content_reference"`
	Details          string `json:"details"`
	Signature        string `json:"signature"`
	GoodFaith        bool   `json:"good_faith"`
	Authorized       bool   `json:"authorized"`
}

func (s Submission) Validate() error {
	if len(strings.TrimSpace(s.Contact)) < 3 || len(s.Contact) > 320 ||
		len(strings.TrimSpace(s.Details)) < 10 || len(s.Details) > 8000 ||
		len(s.ContentReference) > 2000 || len(s.Signature) > 200 || strings.ContainsRune(s.Contact, '\x00') {
		return domain.ErrInvalid
	}
	switch s.Category {
	case "safety", "privacy_access", "privacy_correction", "privacy_deletion", "privacy_appeal", "copyright", "copyright_counter_notice":
	case "intimate_imagery":
		if strings.TrimSpace(s.ContentReference) == "" || strings.TrimSpace(s.Signature) == "" || !s.GoodFaith || !s.Authorized {
			return domain.ErrInvalid
		}
	default:
		return domain.ErrInvalid
	}
	return nil
}

func TokenHash(token string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(b) != 32 {
		return nil, domain.ErrInvalid
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

type Case struct {
	ID uuid.UUID `json:"id"`
	Submission
	TokenHash    []byte     `json:"-"`
	RequestHash  []byte     `json:"-"`
	Status       string     `json:"status"`
	ReceivedAt   time.Time  `json:"received_at"`
	ReviewDueAt  *time.Time `json:"review_due_at,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at"`
	PublicUpdate string     `json:"public_update"`
}

func NewCase(id uuid.UUID, token string, submission Submission, now time.Time) (Case, error) {
	if id == uuid.Nil {
		return Case{}, domain.ErrInvalid
	}
	if err := submission.Validate(); err != nil {
		return Case{}, err
	}
	hash, err := TokenHash(token)
	if err != nil {
		return Case{}, err
	}
	b, _ := json.Marshal(submission)
	digest := sha256.Sum256(b)
	c := Case{ID: id, Submission: submission, TokenHash: hash, RequestHash: digest[:], Status: "received", ReceivedAt: now, UpdatedAt: now}
	if submission.Category == "intimate_imagery" {
		// Conservative triage timer starts at receipt, not after an operator
		// eventually marks the notice valid. It is not a claim of validity.
		due := now.Add(48 * time.Hour)
		c.ReviewDueAt = &due
	}
	return c, nil
}

type CaseStatus struct {
	ID           uuid.UUID  `json:"id"`
	Status       string     `json:"status"`
	ReceivedAt   time.Time  `json:"received_at"`
	ReviewDueAt  *time.Time `json:"review_due_at,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at"`
	PublicUpdate string     `json:"public_update"`
}

func (c Case) Public() CaseStatus {
	return CaseStatus{c.ID, c.Status, c.ReceivedAt, c.ReviewDueAt, c.UpdatedAt, c.PublicUpdate}
}

type Review struct {
	CaseID         uuid.UUID
	ExpectedStatus string
	Status         string
	Operator       string
	Reason         string
	PublicUpdate   string
}

func (r Review) Validate() error {
	if r.CaseID == uuid.Nil || len(strings.TrimSpace(r.Operator)) < 3 || len(r.Operator) > 200 ||
		len(strings.TrimSpace(r.Reason)) < 10 || len(r.Reason) > 4000 || len(r.PublicUpdate) > 2000 {
		return domain.ErrInvalid
	}
	allowed := map[string]bool{"received": true, "reviewing": true, "awaiting_information": true, "resolved": true, "declined": true}
	if !allowed[r.Status] || !allowed[r.ExpectedStatus] || r.Status == r.ExpectedStatus {
		return domain.ErrInvalid
	}
	return nil
}

type Repository interface {
	SetBlock(context.Context, uuid.UUID, uuid.UUID, bool) error
	Blocks(context.Context, uuid.UUID) ([]uuid.UUID, error)
	Blocked(context.Context, uuid.UUID, uuid.UUID) (bool, error)
	DeliverIfAllowed(context.Context, uuid.UUID, uuid.UUID, func() error) (bool, error)
	Accept(context.Context, Acceptance) (Acceptance, error)
	Acceptance(context.Context, uuid.UUID, string) (Acceptance, error)
	Submit(context.Context, Case) (CaseStatus, error)
	Status(context.Context, uuid.UUID, []byte) (CaseStatus, error)
	ListCases(context.Context, int) ([]Case, error)
	Review(context.Context, Review) error
}

// Shared with the backend's account erasure / external-delivery fencing.
const AccountDeliveryBarrierKey int64 = 0x436c69786f724552
