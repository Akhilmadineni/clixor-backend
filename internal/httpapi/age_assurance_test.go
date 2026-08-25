package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func TestEvaluateAgeAssuranceAdultBoundaries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	adultDOB := ageAssuranceRequest{
		Source: "self_attested_date_of_birth", Declaration: "self_declared", DateOfBirth: "2008-08-24",
	}
	assurance, err := evaluateAgeAssurance(uuid.New(), adultDOB, now)
	if err != nil || assurance.Status != "adult" || assurance.ExpiresAt == nil {
		t.Fatalf("18th birthday should be accepted: assurance=%+v err=%v", assurance, err)
	}
	minorDOB := adultDOB
	minorDOB.DateOfBirth = "2008-08-25"
	assurance, err = evaluateAgeAssurance(uuid.New(), minorDOB, now)
	if err != nil || assurance.Status != "underage" || assurance.ExpiresAt != nil {
		t.Fatalf("day before 18th birthday should be blocked: assurance=%+v err=%v", assurance, err)
	}

	lower := 18
	appleAdult := ageAssuranceRequest{
		Source: "apple_declared_age_range", LowerBound: &lower, Declaration: "confirmed",
	}
	assurance, err = evaluateAgeAssurance(uuid.New(), appleAdult, now)
	if err != nil || assurance.Status != "adult" {
		t.Fatalf("Apple 18+ range should be accepted: assurance=%+v err=%v", assurance, err)
	}
	upper := 18
	appleMinor := ageAssuranceRequest{
		Source: "apple_declared_age_range", UpperBound: &upper, Declaration: "guardian_declared",
	}
	assurance, err = evaluateAgeAssurance(uuid.New(), appleMinor, now)
	if err != nil || assurance.Status != "underage" {
		t.Fatalf("Apple under-18 range should be blocked: assurance=%+v err=%v", assurance, err)
	}
}

func TestAgeAssuranceIsOptionalWhileProductGateIsDisabled(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	var response authResponse
	client.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": "age-gate@example.com", "password": "very-secure-test-password",
		"device_name": "Test iPhone", "platform": "ios",
	}, http.StatusCreated, &response)
	client.token = response.Tokens.AccessToken

	var pending map[string]any
	client.do(t, http.MethodGet, "/v1/me/age-assurance", nil, http.StatusOK, &pending)
	if pending["status"] != "pending" || pending["minimum_age"] != float64(18) {
		t.Fatalf("unexpected pending response: %#v", pending)
	}
	client.do(t, http.MethodGet, "/v1/conversations/", nil, http.StatusOK, nil)
	var updated domain.User
	client.do(t, http.MethodPatch, "/v1/me", map[string]any{
		"displayName": "Age-gate rollback user", "username": "age_gate_rollback",
	}, http.StatusOK, &updated)
	if updated.Profile == nil {
		t.Fatal("freshly registered user could not complete profile without age assurance")
	}

	var adult domain.AgeAssurance
	client.do(t, http.MethodPut, "/v1/me/age-assurance", map[string]any{
		"source": "self_attested_date_of_birth", "declaration": "self_declared",
		"date_of_birth": "1990-01-01",
	}, http.StatusOK, &adult)
	if adult.Status != "adult" || adult.MinimumAge != 18 || adult.PolicyVersion != adultAgePolicyVersion {
		t.Fatalf("unexpected adult assurance: %+v", adult)
	}
	client.do(t, http.MethodGet, "/v1/conversations/", nil, http.StatusOK, nil)
}

func TestUnderageAssuranceDoesNotBlockProductRoutesWhileGateIsDisabled(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	client := testClient{baseURL: server.URL, client: http.DefaultClient}
	var response authResponse
	client.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": "underage@example.com", "password": "very-secure-test-password",
		"device_name": "Test iPhone", "platform": "ios",
	}, http.StatusCreated, &response)
	client.token = response.Tokens.AccessToken

	upper := 18
	var underage domain.AgeAssurance
	client.do(t, http.MethodPut, "/v1/me/age-assurance", map[string]any{
		"source": "apple_declared_age_range", "upper_bound": upper,
		"declaration": "guardian_declared",
	}, http.StatusOK, &underage)
	if underage.Status != "underage" {
		t.Fatalf("unexpected underage assurance: %+v", underage)
	}
	client.do(t, http.MethodGet, "/v1/conversations/", nil, http.StatusOK, nil)
	client.do(t, http.MethodPut, "/v1/me/age-assurance", map[string]any{
		"source": "self_attested_date_of_birth", "declaration": "self_declared",
		"date_of_birth": "1990-01-01",
	}, http.StatusTooManyRequests, nil)
}
