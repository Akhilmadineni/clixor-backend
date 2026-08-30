package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestAccountDeletionCapabilityReconcilesLostResponseAndHidesInvalidTokens(t *testing.T) {
	server := newTestHTTPServer(t)
	registered := registerTestUser(t, server.URL, "deletion-capability@example.com")
	requestID := uuid.New()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	registered.client.do(t, http.MethodPut, "/v1/me/deletion-intents/"+requestID.String(),
		map[string]any{"recovery_token": token}, http.StatusNoContent, nil)
	// Identical registration is idempotent while the account is live.
	registered.client.do(t, http.MethodPut, "/v1/me/deletion-intents/"+requestID.String(),
		map[string]any{"recovery_token": token}, http.StatusNoContent, nil)

	unauthenticated := testClient{baseURL: server.URL, client: http.DefaultClient}
	unauthenticated.do(t, http.MethodPost, "/v1/account-deletions/"+requestID.String()+"/execute",
		map[string]any{"recovery_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		http.StatusNotFound, nil)
	unauthenticated.do(t, http.MethodPost, "/v1/account-deletions/"+uuid.NewString()+"/execute",
		map[string]any{"recovery_token": token}, http.StatusNotFound, nil)
	unauthenticated.do(t, http.MethodPost, "/v1/account-deletions/"+requestID.String()+"/execute",
		map[string]any{"recovery_token": token}, http.StatusNoContent, nil)
	// A client that lost the first 204 can retry the same capability forever.
	unauthenticated.do(t, http.MethodPost, "/v1/account-deletions/"+requestID.String()+"/execute",
		map[string]any{"recovery_token": token}, http.StatusNoContent, nil)

	registered.client.do(t, http.MethodGet, "/v1/me", nil, http.StatusUnauthorized, nil)
}

func TestAccountDeletionCapabilityInteroperatesWithLegacyDeleteAndConcurrentExecute(t *testing.T) {
	server := newTestHTTPServer(t)
	registered := registerTestUser(t, server.URL, "deletion-legacy@example.com")
	requestID := uuid.New()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32))
	registered.client.do(t, http.MethodPut, "/v1/me/deletion-intents/"+requestID.String(),
		map[string]any{"recovery_token": token}, http.StatusNoContent, nil)
	registered.client.do(t, http.MethodDelete, "/v1/me", nil, http.StatusNoContent, nil)
	unauthenticated := testClient{baseURL: server.URL, client: http.DefaultClient}
	unauthenticated.do(t, http.MethodPost, "/v1/account-deletions/"+requestID.String()+"/execute",
		map[string]any{"recovery_token": token}, http.StatusNoContent, nil)

	// Exercise the live mutation race independently of legacy reconciliation.
	concurrent := registerTestUser(t, server.URL, "deletion-concurrent@example.com")
	concurrentRequestID := uuid.New()
	concurrentToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x25}, 32))
	concurrent.client.do(t, http.MethodPut, "/v1/me/deletion-intents/"+concurrentRequestID.String(),
		map[string]any{"recovery_token": concurrentToken}, http.StatusNoContent, nil)

	var wait sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			encoded, _ := json.Marshal(map[string]any{"recovery_token": concurrentToken})
			request, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
				server.URL+"/v1/account-deletions/"+concurrentRequestID.String()+"/execute", bytes.NewReader(encoded))
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				statuses <- 0
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	wait.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusNoContent {
			t.Fatalf("concurrent reconciliation status=%d, want 204", status)
		}
	}
	concurrent.client.do(t, http.MethodGet, "/v1/me", nil, http.StatusUnauthorized, nil)
}
