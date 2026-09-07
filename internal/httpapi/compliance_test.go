package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/appleauth"
	"github.com/Akhilmadineni/clixor-backend/internal/auth"
	"github.com/Akhilmadineni/clixor-backend/internal/compliance"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/Akhilmadineni/clixor-backend/internal/presence"
	"github.com/Akhilmadineni/clixor-backend/internal/ratelimit"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/Akhilmadineni/clixor-backend/internal/verification"
	"github.com/google/uuid"
)

func complianceTestServer(t *testing.T, enabled bool) (*httptest.Server, *memory.Store) {
	return complianceTestServerTLS(t, enabled, false)
}

func complianceTestServerTLS(t *testing.T, enabled, tls bool) (*httptest.Server, *memory.Store) {
	t.Helper()
	p := memory.New()
	bus := events.NewMemoryBus()
	limiter := ratelimit.NewMemory()
	ps := presence.NewMemory()
	s := New(p, auth.NewTokenManager("test", strings.Repeat("s", 48), 15*time.Minute, 30*24*time.Hour, p), bus, limiter, media.Unavailable{}, verification.Unavailable{}, appleauth.Unavailable{}, ps, nil, PasswordResetPolicy{}, MediaPolicy{}, nil, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.legalRelease.Policy = compliance.Policy{Enabled: enabled, Version: "test-version", DocumentSHA256: strings.Repeat("a", 64), MinimumAge: 13, IntakeEnabled: enabled}
	s.legalRelease.ContactEmail = "test@clixor.test"
	srv := httptest.NewUnstartedServer(s.Router())
	if tls {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(func() { srv.Close(); ps.Close(); limiter.Close(); bus.Close(); p.Close() })
	return srv, p
}

// Explicit opt-in local simulator fixture. No production persistence or providers.
// It exits successfully only after checking the exact harmless report written
// through the UI; the ordinary test suite skips this interactive fixture.
func TestComplianceSimulatorFixture(t *testing.T) {
	certPath := os.Getenv("CLIXOR_SIMULATOR_FIXTURE_CERT")
	if certPath == "" {
		t.Skip("interactive simulator fixture not requested")
	}
	srv, p := complianceTestServerTLS(t, true, true)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("SIMULATOR_FIXTURE_URL=%s", srv.URL)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(10 * time.Minute)
	defer timeout.Stop()
	for {
		select {
		case <-timeout.C:
			t.Fatal("simulator never persisted the expected report")
		case <-ticker.C:
			cases, err := p.Compliance().ListCases(context.Background(), 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cases {
				if c.Contact == "simulator-fixture@example.com" {
					if c.Details != "Harmless simulator end to end report" || c.Category != "safety" || c.ContentReference != "simulator-content-fixture" || c.Status != "received" {
						t.Fatal("incorrect UI report persisted")
					}
					t.Log("Verified exact simulator report fields in the backend store")
					// Keep receipt/status responses available until the UI test ends.
					<-time.After(20 * time.Second)
					return
				}
			}
		}
	}
}
func TestSupportPublicIntakeAndPrivateStatus(t *testing.T) {
	srv, p := complianceTestServer(t, true)
	client := testClient{baseURL: srv.URL, client: http.DefaultClient}
	id := uuid.New()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	body := map[string]any{"access_token": token, "category": "intimate_imagery", "contact": "private@clixor.test", "content_reference": "test-message-id", "details": "This test image is shared without consent.", "signature": "Test Person", "good_faith": true, "authorized": true}
	var receipt compliance.CaseStatus
	path := "/v1/support/cases/" + id.String()
	client.do(t, http.MethodPut, path, body, http.StatusOK, &receipt)
	if receipt.ID != id || receipt.ReviewDueAt == nil || receipt.Status != "received" {
		t.Fatal("missing durable receipt")
	}
	first := receipt.ReceivedAt
	client.do(t, http.MethodPut, path, body, http.StatusOK, &receipt)
	if !receipt.ReceivedAt.Equal(first) {
		t.Fatal("retry changed receipt")
	}
	client.do(t, http.MethodGet, path, nil, http.StatusNotFound, nil)
	client.token = token
	client.do(t, http.MethodGet, path, nil, http.StatusOK, &receipt)
	cases, err := p.Compliance().ListCases(context.Background(), 10)
	if err != nil || len(cases) != 1 {
		t.Fatal("report not durably acknowledged")
	}
	request, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if bytes.Contains(raw, []byte("private@")) || bytes.Contains(raw, []byte("shared without")) || bytes.Contains(raw, []byte(token)) {
		t.Fatal("status disclosed sensitive report data")
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("status is cacheable")
	}
}
func TestComplianceDisabledDoesNotAcknowledgeReports(t *testing.T) {
	srv, p := complianceTestServer(t, false)
	client := testClient{baseURL: srv.URL, client: http.DefaultClient}
	client.do(t, http.MethodPut, "/v1/support/cases/"+uuid.NewString(), map[string]any{}, 503, nil)
	cases, err := p.Compliance().ListCases(context.Background(), 10)
	if err != nil || len(cases) != 0 {
		t.Fatal("disabled intake persisted data")
	}
	r, err := http.Get(srv.URL + "/support")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 503 {
		t.Fatal("disabled form looks enabled")
	}
	user := registerTestUser(t, srv.URL, "legacy@clixor.test")
	user.client.do(t, http.MethodGet, "/me", nil, http.StatusNotFound, nil)
	user.client.do(t, http.MethodGet, "/v1/me", nil, http.StatusOK, nil)
}
func TestLegalAcceptanceIdentityVersionAndAge(t *testing.T) {
	srv, p := complianceTestServer(t, true)
	user := legacyComplianceUser(t, srv, p, "legal@clixor.test")
	body := map[string]any{"version": "test-version", "document_sha256": strings.Repeat("a", 64), "age_group": "minor_13_plus", "guardian_permission": false, "agreed": true}
	user.client.do(t, http.MethodPut, "/v1/me/legal-acceptance", body, 422, nil)
	body["guardian_permission"] = true
	var receipt compliance.Acceptance
	user.client.do(t, http.MethodPut, "/v1/me/legal-acceptance", body, 200, &receipt)
	if receipt.UserID != user.user.ID || receipt.AcceptedAt.IsZero() {
		t.Fatal("server-bound receipt missing")
	}
	stored, err := p.Compliance().Acceptance(context.Background(), user.user.ID, "test-version")
	if err != nil || !stored.GuardianPermission {
		t.Fatal("receipt missing from persistence")
	}
	first := receipt.AcceptedAt
	user.client.do(t, http.MethodPut, "/v1/me/legal-acceptance", body, 200, &receipt)
	if !first.Equal(receipt.AcceptedAt) {
		t.Fatal("retry rewrote acceptance")
	}
	body["user_id"] = uuid.NewString()
	user.client.do(t, http.MethodPut, "/v1/me/legal-acceptance", body, 400, nil)
	delete(body, "user_id")
	body["version"] = "old"
	user.client.do(t, http.MethodPut, "/v1/me/legal-acceptance", body, 422, nil)
	other := legacyComplianceUser(t, srv, p, "other-legal@clixor.test")
	other.client.do(t, http.MethodGet, "/v1/me/legal-acceptance", nil, 404, nil)
}
func legacyComplianceUser(t *testing.T, srv *httptest.Server, p *memory.Store, email string) registeredUser {
	t.Helper()
	hash, err := auth.HashPassword("very-secure-test-password")
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.CreateUser(context.Background(), store.CreateUserParams{Email: email, PasswordHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	client := testClient{baseURL: srv.URL, client: http.DefaultClient}
	var response authResponse
	client.do(t, http.MethodPost, "/v1/auth/login", map[string]any{"email": email, "password": "very-secure-test-password", "device_name": "Legal test", "platform": "ios"}, 200, &response)
	client.token = response.Tokens.AccessToken
	return registeredUser{user: response.User, device: response.Device, tokens: response.Tokens, client: client}
}

func TestPublishedPolicyRequiresAcceptanceBeforeRegistration(t *testing.T) {
	srv, p := complianceTestServer(t, true)
	client := testClient{baseURL: srv.URL, client: http.DefaultClient}
	body := map[string]any{"email": "new-legal@clixor.test", "password": "very-secure-test-password", "device_name": "Legal test", "platform": "ios"}
	client.do(t, http.MethodPost, "/v1/auth/register", body, 422, nil)
	if _, err := p.UserByEmail(context.Background(), "new-legal@clixor.test"); err == nil {
		t.Fatal("ineligible registration persisted identity")
	}
	declaration := map[string]any{"version": "test-version", "document_sha256": strings.Repeat("a", 64), "age_group": "under_13", "guardian_permission": true, "agreed": true}
	body["legal"] = declaration
	client.do(t, http.MethodPost, "/v1/auth/register", body, 422, nil)
	declaration["age_group"] = "minor_13_plus"
	var response authResponse
	client.do(t, http.MethodPost, "/v1/auth/register", body, 201, &response)
	stored, err := p.Compliance().Acceptance(context.Background(), response.User.ID, "test-version")
	if err != nil || stored.AgeGroup != "minor_13_plus" {
		t.Fatal("registration did not persist receipt")
	}
}

func TestSupportRejectsIncompleteAndOversizedReports(t *testing.T) {
	srv, _ := complianceTestServer(t, true)
	client := testClient{baseURL: srv.URL, client: http.DefaultClient}
	body := map[string]any{"access_token": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "category": "intimate_imagery", "contact": "test@clixor.test", "details": "A long enough test description"}
	client.do(t, http.MethodPut, "/v1/support/cases/"+uuid.NewString(), body, 422, nil)
	body["category"] = "safety"
	body["details"] = strings.Repeat("a", 17000)
	raw, _ := json.Marshal(body)
	r, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/support/cases/"+uuid.NewString(), bytes.NewReader(raw))
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatalf("oversized body status %d", response.StatusCode)
	}
}
