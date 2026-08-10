package verification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingSender struct {
	mu        sync.Mutex
	code      string
	messageID string
	err       error
	sends     int
}

func (s *recordingSender) SendCode(_ context.Context, _ string, code string, _ time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sends++
	s.code = code
	if s.err != nil {
		return "", s.err
	}
	if s.messageID == "" {
		s.messageID = fmt.Sprintf("message-%d", s.sends)
	}
	return s.messageID, nil
}

func (s *recordingSender) currentCode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.code
}

func TestOTPChallengeLifecycleAndFraudControls(t *testing.T) {
	service, sender := newIntegrationOTP(t, nil)
	ctx := context.Background()
	phone := "+13125550123"
	if err := service.Send(ctx, phone); err != nil {
		t.Fatal(err)
	}
	code := sender.currentCode()
	if !numericCode(code, 6) {
		t.Fatalf("generated invalid code %q", code)
	}

	destinationID := service.digest("destination:" + phone)
	keys := service.keys(destinationID)
	redisKeys, err := service.client.Keys(ctx, service.prefix+"*").Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range redisKeys {
		if strings.Contains(key, phone) || strings.Contains(key, code) {
			t.Fatalf("sensitive value appeared in Redis key %q", key)
		}
	}
	challenge, err := service.client.HGetAll(ctx, keys.challenge).Result()
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range challenge {
		if strings.Contains(value, phone) || strings.Contains(value, code) {
			t.Fatalf("sensitive value appeared in Redis challenge field %s", field)
		}
	}
	if err := service.Send(ctx, phone); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("resend cooldown returned %v", err)
	}

	var successes atomic.Int32
	var expired atomic.Int32
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			err := service.Check(ctx, phone, code)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrExpiredCode):
				expired.Add(1)
			default:
				t.Errorf("unexpected concurrent check result: %v", err)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || expired.Load() != 1 {
		t.Fatalf("single-use check results: successes=%d expired=%d", successes.Load(), expired.Load())
	}

	lockedPhone := "+13125550124"
	if err := service.Send(ctx, lockedPhone); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt < service.policy.MaxAttempts; attempt++ {
		if err := service.Check(ctx, lockedPhone, "999999"); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("attempt %d returned %v", attempt, err)
		}
	}
	err = service.Check(ctx, lockedPhone, "999999")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("final invalid attempt returned %v", err)
	}
	if err := service.Send(ctx, lockedPhone); !errors.Is(err, ErrLocked) {
		t.Fatalf("send during lockout returned %v", err)
	}
}

func TestOTPProviderFailureRollsBackChallengeButConsumesBudget(t *testing.T) {
	service, sender := newIntegrationOTP(t, nil)
	sender.err = errors.New("provider unavailable")
	ctx := context.Background()
	phone := "+13125550125"
	if err := service.Send(ctx, phone); err == nil {
		t.Fatal("expected provider failure")
	}
	keys := service.keys(service.digest("destination:" + phone))
	if count, _ := service.client.Exists(ctx, keys.challenge, keys.cooldown).Result(); count != 0 {
		t.Fatal("failed provider call left an active challenge or cooldown")
	}
	if count, _ := service.client.Get(ctx, keys.phoneHour).Int(); count != 1 {
		t.Fatalf("provider failure did not consume abuse budget: %d", count)
	}
}

func TestSignedTelnyxWebhookAndReplayProtection(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, _ := newIntegrationOTP(t, publicKey)
	fixedNow := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return fixedNow }
	event := map[string]any{"data": map[string]any{
		"id": "event-123", "event_type": "message.finalized",
		"payload": map[string]any{
			"id": "message-123", "direction": "outbound", "tags": []string{"clustr-otp"},
			"to": []map[string]string{{"status": "delivered"}},
		},
	}}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := fmt.Sprintf("%d", fixedNow.Unix())
	signature := ed25519.Sign(privateKey, []byte(timestamp+"|"+string(body)))
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	if err := service.HandleWebhook(context.Background(), encodedSignature, timestamp, body); err != nil {
		t.Fatal(err)
	}
	if err := service.HandleWebhook(context.Background(), encodedSignature, timestamp, body); err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
	status, err := service.client.HGet(context.Background(), service.prefix+"delivery:message-123", "status").Result()
	if err != nil || status != "delivered" {
		t.Fatalf("delivery status=%q err=%v", status, err)
	}
	stale := fmt.Sprintf("%d", fixedNow.Add(-6*time.Minute).Unix())
	staleSignature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(stale+"|"+string(body))))
	if err := service.HandleWebhook(context.Background(), staleSignature, stale, body); !errors.Is(err, ErrInvalidWebhook) {
		t.Fatalf("stale webhook returned %v", err)
	}
	extremeFuture := "9223372036854775807"
	if err := service.HandleWebhook(context.Background(), encodedSignature, extremeFuture, body); !errors.Is(err, ErrInvalidWebhook) {
		t.Fatalf("extreme timestamp returned %v", err)
	}
}

func newIntegrationOTP(t *testing.T, webhookPublicKey ed25519.PublicKey) (*OTP, *recordingSender) {
	t.Helper()
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL is not configured")
	}
	secretBytes := make([]byte, 48)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	policy := DefaultPolicy()
	encodedPublicKey := ""
	if webhookPublicKey != nil {
		encodedPublicKey = base64.StdEncoding.EncodeToString(webhookPublicKey)
	}
	service, err := NewOTP(
		context.Background(), redisURL, "", sender,
		base64.StdEncoding.EncodeToString(secretBytes), policy, encodedPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		keys, _ := service.client.Keys(context.Background(), service.prefix+"*").Result()
		if len(keys) > 0 {
			_ = service.client.Del(context.Background(), keys...).Err()
		}
		_ = service.Close()
	})
	return service, sender
}
