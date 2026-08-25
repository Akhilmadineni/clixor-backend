package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

const (
	minimumAccountAge     = 18
	adultAgePolicyVersion = "adult-v1"
	ageAssuranceLifetime  = 365 * 24 * time.Hour
	ageRecheckCooldown    = 24 * time.Hour
)

type ageAssuranceRequest struct {
	Source      string `json:"source"`
	LowerBound  *int   `json:"lower_bound,omitempty"`
	UpperBound  *int   `json:"upper_bound,omitempty"`
	Declaration string `json:"declaration,omitempty"`
	DateOfBirth string `json:"date_of_birth,omitempty"`
}

func (s *Server) getAgeAssurance(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	assurance, err := s.store.AgeAssurance(r.Context(), id.UserID)
	if errors.Is(err, domain.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":         "pending",
			"minimum_age":    minimumAccountAge,
			"policy_version": adultAgePolicyVersion,
		})
		return
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assurance)
}

func (s *Server) putAgeAssurance(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	var request ageAssuranceRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	now := time.Now().UTC()
	assurance, err := evaluateAgeAssurance(id.UserID, request, now)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_age_assurance", err.Error())
		return
	}
	if existing, existingErr := s.store.AgeAssurance(r.Context(), id.UserID); existingErr == nil &&
		existing.Status == "underage" && assurance.Status == "adult" &&
		now.Sub(existing.CheckedAt) < ageRecheckCooldown {
		w.Header().Set("Retry-After", "86400")
		writeError(w, http.StatusTooManyRequests, "age_recheck_cooldown", "Age information cannot be changed yet.")
		return
	} else if existingErr != nil && !errors.Is(existingErr, domain.ErrNotFound) {
		writeDomainError(w, existingErr)
		return
	}
	assurance, err = s.store.UpsertAgeAssurance(r.Context(), assurance)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assurance)
}

func evaluateAgeAssurance(userID uuid.UUID, request ageAssuranceRequest, now time.Time) (domain.AgeAssurance, error) {
	// Kept as a separate pure function so every accepted source and boundary is
	// covered without retaining the submitted date of birth.
	if userID == uuid.Nil {
		return domain.AgeAssurance{}, domain.ErrInvalid
	}
	request.Source = strings.TrimSpace(request.Source)
	request.Declaration = strings.TrimSpace(request.Declaration)
	status := ""
	declaration := request.Declaration

	switch request.Source {
	case "apple_declared_age_range":
		if request.DateOfBirth != "" || !validAppleAgeRange(request.LowerBound, request.UpperBound) ||
			!validAgeDeclaration(declaration) {
			return domain.AgeAssurance{}, domain.ErrInvalid
		}
		if request.LowerBound != nil && *request.LowerBound >= minimumAccountAge {
			status = "adult"
		} else {
			status = "underage"
		}
	case "self_attested_date_of_birth":
		if request.LowerBound != nil || request.UpperBound != nil || declaration != "self_declared" {
			return domain.AgeAssurance{}, domain.ErrInvalid
		}
		birthDate, parseErr := time.Parse("2006-01-02", request.DateOfBirth)
		if parseErr != nil || birthDate.After(now) || birthDate.Before(now.AddDate(-125, 0, 0)) {
			return domain.AgeAssurance{}, domain.ErrInvalid
		}
		if !birthDate.After(now.AddDate(-minimumAccountAge, 0, 0)) {
			status = "adult"
		} else {
			status = "underage"
		}
	default:
		return domain.AgeAssurance{}, domain.ErrInvalid
	}

	assurance := domain.AgeAssurance{
		UserID: userID, Status: status, MinimumAge: minimumAccountAge,
		Source: request.Source, Declaration: declaration, PolicyVersion: adultAgePolicyVersion,
		CheckedAt: now,
	}
	if status == "adult" {
		expiresAt := now.Add(ageAssuranceLifetime)
		assurance.ExpiresAt = &expiresAt
	}
	return assurance, nil
}

func validAppleAgeRange(lower, upper *int) bool {
	if lower == nil && upper == nil {
		return false
	}
	if lower != nil && (*lower < 0 || *lower > 125) {
		return false
	}
	if upper != nil && (*upper < 1 || *upper > 126) {
		return false
	}
	if lower != nil && upper != nil && *lower >= *upper {
		return false
	}
	// An Apple response to a single age gate of 18 is either <18 (nil,18)
	// or 18+ (18,nil). Reject invented ranges that did not come from that request.
	return (lower == nil && upper != nil && *upper == minimumAccountAge) ||
		(lower != nil && *lower == minimumAccountAge && upper == nil)
}

func validAgeDeclaration(value string) bool {
	switch value {
	case "not_provided", "self_declared", "guardian_declared", "confirmed", "checked_by_other_method",
		"guardian_checked_by_other_method", "government_id_checked",
		"guardian_government_id_checked", "payment_checked", "guardian_payment_checked":
		return true
	default:
		return false
	}
}

func (s *Server) requireAdultAgeAssurance(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := identityFrom(r.Context())
		if !ok {
			writeDomainError(w, domain.ErrUnauthenticated)
			return
		}
		assurance, err := s.store.AgeAssurance(r.Context(), id.UserID)
		if errors.Is(err, domain.ErrNotFound) || (err == nil && !currentAdultAssurance(assurance, time.Now().UTC())) {
			if err == nil && assurance.Status == "underage" && assurance.PolicyVersion == adultAgePolicyVersion {
				writeError(w, http.StatusForbidden, "adults_only", "Clixor is available only to people age 18 or older.")
				return
			}
			writeError(w, http.StatusForbidden, "age_assurance_required", "Confirm that you are age 18 or older to continue.")
			return
		}
		if err != nil {
			s.logger.Error("age_assurance_check_failed", "error", err, "user_id", id.UserID)
			writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Please try again shortly.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func currentAdultAssurance(assurance domain.AgeAssurance, now time.Time) bool {
	return assurance.Status == "adult" && assurance.MinimumAge == minimumAccountAge &&
		assurance.PolicyVersion == adultAgePolicyVersion && assurance.ExpiresAt != nil &&
		assurance.ExpiresAt.After(now)
}
