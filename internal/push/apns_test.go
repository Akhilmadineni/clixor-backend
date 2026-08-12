package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestAPNSRetriesProviderFailureAndSetsRequiredHeaders(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		if request.Header.Get("apns-topic") != "com.example.Clixor" ||
			request.Header.Get("apns-push-type") != "alert" ||
			request.Header.Get("apns-collapse-id") != "c5657319-cb6c-4f95-ab8d-10d6d365450b" {
			t.Errorf("unexpected APNs headers: %#v", request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		if payload["type"] != "message" {
			t.Errorf("type = %#v", payload["type"])
		}
		if call < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"reason":"InternalServerError"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	provider := &APNS{
		teamID: "team", keyID: "key", bundleID: "com.example.Clixor",
		endpoint: server.URL, key: key, client: client,
	}
	err = provider.Send(
		context.Background(), "device-token", "Group 1", "Akhil sent a message",
		map[string]string{"type": "message", "groupId": "group", "entityId": "entity"},
		"c5657319-cb6c-4f95-ab8d-10d6d365450b",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("APNs calls = %d, want 3", got)
	}
}

func TestAPNSDoesNotRetryInvalidToken(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"reason":"Unregistered"}`))
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider := &APNS{
		teamID: "team", keyID: "key", bundleID: "com.example.Clixor",
		endpoint: server.URL, key: key, client: server.Client(),
	}
	err = provider.Send(
		context.Background(), "device-token", "title", "body", nil,
		"c5657319-cb6c-4f95-ab8d-10d6d365450b",
	)
	if !IsInvalidToken(err) {
		t.Fatalf("expected invalid token, received %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("APNs calls = %d, want 1", got)
	}
}
