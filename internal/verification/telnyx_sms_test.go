package verification

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTelnyxSMSSendsOneSegmentHardenedRequest(t *testing.T) {
	t.Parallel()
	fixedNow := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	var received struct {
		From               string   `json:"from"`
		To                 string   `json:"to"`
		Text               string   `json:"text"`
		Type               string   `json:"type"`
		Encoding           string   `json:"encoding"`
		MessagingProfileID string   `json:"messaging_profile_id"`
		WebhookURL         string   `json:"webhook_url"`
		UseProfileWebhooks bool     `json:"use_profile_webhooks"`
		ValidUntil         string   `json:"valid_until"`
		Tags               []string `json:"tags"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Fatalf("unexpected request method/auth: %s %q", r.Method, r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"message-123"}}`))
	}))
	defer server.Close()

	sender, err := NewTelnyxSMS(
		"test-api-key", "+13125550100", "profile-123",
		"https://clustr-api.atlanteanz.com/v1/webhooks/telnyx/messaging",
	)
	if err != nil {
		t.Fatal(err)
	}
	sender.endpoint = server.URL
	sender.now = func() time.Time { return fixedNow }
	messageID, err := sender.SendCode(context.Background(), "+13125550101", "123456", 10*time.Minute)
	if err != nil || messageID != "message-123" {
		t.Fatalf("messageID=%q err=%v", messageID, err)
	}
	if received.From != "+13125550100" || received.To != "+13125550101" ||
		received.Type != "SMS" || received.Encoding != "gsm7" ||
		received.MessagingProfileID != "profile-123" || received.UseProfileWebhooks ||
		received.ValidUntil != fixedNow.Add(10*time.Minute).Format(time.RFC3339) ||
		len(received.Tags) != 1 || received.Tags[0] != "clustr-otp" {
		t.Fatalf("unexpected Telnyx payload: %+v", received)
	}
	if !strings.Contains(received.Text, "123456") || len(received.Text) > 160 {
		t.Fatalf("OTP message is invalid or multi-segment: %q", received.Text)
	}
}

func TestTelnyxSMSProviderErrorsDoNotLeakResponseDetails(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"code":"40301","detail":"secret destination +13125550101"}]}`))
	}))
	defer server.Close()
	sender, err := NewTelnyxSMS("api-key", "+13125550100", "profile", "")
	if err != nil {
		t.Fatal(err)
	}
	sender.endpoint = server.URL
	_, err = sender.SendCode(context.Background(), "+13125550101", "123456", 10*time.Minute)
	var providerError *ProviderError
	if !errors.As(err, &providerError) || providerError.StatusCode != http.StatusForbidden ||
		providerError.Code != "40301" {
		t.Fatalf("unexpected provider error: %v", err)
	}
	if strings.Contains(err.Error(), "+13125550101") || strings.Contains(err.Error(), "secret destination") {
		t.Fatalf("provider response detail leaked: %v", err)
	}
}

func TestProviderCodeSanitization(t *testing.T) {
	t.Parallel()
	if got := safeProviderCode("40301"); got != "40301" {
		t.Fatalf("valid provider code was rejected: %q", got)
	}
	if got := safeProviderCode("40301\nforged-log-line"); got != "" {
		t.Fatalf("unsafe provider code was retained: %q", got)
	}
}
