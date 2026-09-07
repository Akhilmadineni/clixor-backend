package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/compliance"
	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ConfigureLegalRelease must be called before serving requests. Omission keeps
// publication/acceptance and public intake disabled; existing clients are unchanged.
func (s *Server) ConfigureLegalRelease(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 512<<10))
	d.DisallowUnknownFields()
	var release compliance.Release
	if err = d.Decode(&release); err != nil {
		return err
	}
	if err = d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("legal release must contain exactly one JSON document")
	}
	if err = release.Validate(); err != nil {
		return err
	}
	s.legalRelease = release
	return nil
}
func (s *Server) complianceRepository() (compliance.Repository, error) {
	p, ok := s.store.(interface{ Compliance() compliance.Repository })
	if !ok {
		return nil, errors.New("compliance persistence unavailable")
	}
	return p.Compliance(), nil
}

func (s *Server) registrationAcceptance(w http.ResponseWriter, d *compliance.Declaration) (*compliance.Acceptance, bool) {
	if !s.legalRelease.Enabled {
		return nil, true
	}
	if d == nil {
		writeError(w, 422, "legal_acceptance_required", "Review the current terms and eligibility requirements before creating an account.")
		return nil, false
	}
	// The persistence layer assigns the actual newly-created user ID atomically.
	a := d.Receipt(uuid.New(), time.Now().UTC())
	if err := a.Validate(s.legalRelease.Policy); err != nil {
		writeError(w, 422, "legal_acceptance_required", "Confirm eligibility, any required guardian permission, and agreement to the current terms.")
		return nil, false
	}
	return &a, true
}
func (s *Server) getLegalPolicy(w http.ResponseWriter, r *http.Request) {
	p := s.legalRelease.Policy
	if p.TermsURL == "" {
		p.TermsURL = "https://clixor.atlanteanz.com/terms"
		p.PrivacyURL = "https://clixor.atlanteanz.com/privacy"
		p.MinimumAge = 13
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, p)
}
func (s *Server) acceptLegalPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.legalRelease.Enabled {
		writeError(w, 503, "legal_policy_unavailable", "The new legal policy is not published yet.")
		return
	}
	id, _ := identityFrom(r.Context())
	var a compliance.Acceptance
	// Identity and acceptance time are always determined by the server.
	var request struct {
		Version            string `json:"version"`
		DocumentSHA256     string `json:"document_sha256"`
		AgeGroup           string `json:"age_group"`
		GuardianPermission bool   `json:"guardian_permission"`
		Agreed             bool   `json:"agreed"`
	}
	if !decodeComplianceJSON(w, r, &request) {
		return
	}
	a = compliance.Acceptance{UserID: id.UserID, Version: request.Version, DocumentSHA256: request.DocumentSHA256, AgeGroup: request.AgeGroup, GuardianPermission: request.GuardianPermission, Agreed: request.Agreed, AcceptedAt: time.Now().UTC()}
	if err := a.Validate(s.legalRelease.Policy); err != nil {
		writeDomainError(w, err)
		return
	}
	repo, err := s.complianceRepository()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	a, err = repo.Accept(r.Context(), a)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 200, a)
}
func (s *Server) getLegalAcceptance(w http.ResponseWriter, r *http.Request) {
	if !s.legalRelease.Enabled {
		writeError(w, 503, "legal_policy_unavailable", "The new legal policy is not published yet.")
		return
	}
	id, _ := identityFrom(r.Context())
	repo, err := s.complianceRepository()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	a, err := repo.Acceptance(r.Context(), id.UserID, s.legalRelease.Version)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 200, a)
}
func decodeComplianceJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	return decodeJSON(w, r, dest)
}
func (s *Server) submitSupportCase(w http.ResponseWriter, r *http.Request) {
	if !s.legalRelease.IntakeEnabled {
		writeError(w, 503, "support_intake_unavailable", "Online reporting is not available yet. No report has been submitted.")
		return
	}
	var request struct {
		AccessToken string `json:"access_token"`
		compliance.Submission
	}
	if !decodeComplianceJSON(w, r, &request) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "caseID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	c, err := compliance.NewCase(id, request.AccessToken, request.Submission, time.Now().UTC())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	repo, err := s.complianceRepository()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	receipt, err := repo.Submit(r.Context(), c)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, receipt)
}
func (s *Server) supportCaseStatus(w http.ResponseWriter, r *http.Request) {
	if !s.legalRelease.IntakeEnabled {
		writeError(w, 503, "support_intake_unavailable", "Online reporting is not available yet.")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "caseID"))
	if err != nil {
		writeDomainError(w, domain.ErrNotFound)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	hash, err := compliance.TokenHash(token)
	if err != nil {
		writeDomainError(w, domain.ErrNotFound)
		return
	}
	repo, err := s.complianceRepository()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	status, err := repo.Status(r.Context(), id, hash)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, status)
}
