package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestTimeoutByRoute(t *testing.T) {
	const defaultTimeout = 5 * time.Millisecond
	const mediaCompletionTimeout = 50 * time.Millisecond
	timeouts := requestTimeoutByRoute(defaultTimeout, mediaCompletionTimeout)

	realtime := timeouts(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, hasDeadline := r.Context().Deadline(); hasDeadline {
			t.Error("realtime request unexpectedly has an HTTP deadline")
		}
		time.Sleep(3 * defaultTimeout)
		w.WriteHeader(http.StatusNoContent)
	}))
	realtimeResponse := httptest.NewRecorder()
	realtime.ServeHTTP(
		realtimeResponse,
		httptest.NewRequest(http.MethodGet, "/v1/realtime?transport=websocket", nil),
	)
	if realtimeResponse.Code != http.StatusNoContent {
		t.Fatalf("realtime response status = %d, want %d", realtimeResponse.Code, http.StatusNoContent)
	}

	mediaCompletion := timeouts(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, hasDeadline := r.Context().Deadline()
		if !hasDeadline || time.Until(deadline) <= defaultTimeout {
			t.Error("media completion request is missing its extended deadline")
		}
		time.Sleep(3 * defaultTimeout)
		w.WriteHeader(http.StatusNoContent)
	}))
	mediaCompletionResponse := httptest.NewRecorder()
	mediaCompletion.ServeHTTP(
		mediaCompletionResponse,
		httptest.NewRequest(
			http.MethodPost,
			"/v1/media/777a9411-22be-4ca9-87b3-ea3ed1603290/complete",
			nil,
		),
	)
	if mediaCompletionResponse.Code != http.StatusNoContent {
		t.Fatalf(
			"media completion response status = %d, want %d",
			mediaCompletionResponse.Code,
			http.StatusNoContent,
		)
	}

	normal := timeouts(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, hasDeadline := r.Context().Deadline(); !hasDeadline {
			t.Error("normal request is missing an HTTP deadline")
		}
		<-r.Context().Done()
	}))
	normalResponse := httptest.NewRecorder()
	normal.ServeHTTP(normalResponse, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	if normalResponse.Code != http.StatusGatewayTimeout {
		t.Fatalf("normal response status = %d, want %d", normalResponse.Code, http.StatusGatewayTimeout)
	}
}
