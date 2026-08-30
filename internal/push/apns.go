package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type APNS struct {
	teamID   string
	keyID    string
	bundleID string
	endpoint string
	key      *ecdsa.PrivateKey
	client   *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

const notificationRetention = 24 * time.Hour

func NewAPNS(teamID, keyID, bundleID, privateKeyFile, environment string) (*APNS, error) {
	keyData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read APNs private key: %w", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("APNs private key is not PEM encoded")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse APNs private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("APNs private key is not ECDSA")
	}
	endpoint := "https://api.push.apple.com"
	if environment == "sandbox" {
		endpoint = "https://api.sandbox.push.apple.com"
	}
	return &APNS{
		teamID: teamID, keyID: keyID, bundleID: bundleID, endpoint: endpoint, key: key,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				MaxIdleConns:      100, MaxIdleConnsPerHost: 100,
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}, nil
}

func (a *APNS) Send(ctx context.Context, deviceToken, title, body string, data map[string]string, notificationID string) error {
	payload, err := EncodePayload(title, body, data)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			delay := time.Duration(attempt*attempt) * 250 * time.Millisecond
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		lastErr = a.sendOnce(ctx, deviceToken, payload, notificationID)
		if lastErr == nil || !IsRetryable(lastErr) {
			return lastErr
		}
	}
	return lastErr
}

func (a *APNS) sendOnce(ctx context.Context, deviceToken string, payload []byte, notificationID string) error {
	token, err := a.providerToken()
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, a.endpoint+"/3/device/"+strings.TrimSpace(deviceToken), bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	request.Header.Set("authorization", "bearer "+token)
	request.Header.Set("apns-topic", a.bundleID)
	request.Header.Set("apns-push-type", "alert")
	request.Header.Set("apns-priority", "10")
	// A zero expiration tells APNs to try only once and never store the alert,
	// which loses notifications whenever a phone is temporarily offline. Keep a
	// bounded window instead; the app still catches up authoritative state after
	// reconnect, so older alerts are deliberately allowed to expire.
	request.Header.Set(
		"apns-expiration",
		strconv.FormatInt(time.Now().UTC().Add(notificationRetention).Unix(), 10),
	)
	request.Header.Set("apns-id", notificationID)
	// APNs coalesces pending retries for the same entity instead of displaying
	// a burst if the durable outbox is replayed after a transient failure.
	request.Header.Set("apns-collapse-id", notificationID)
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	var failure struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(raw, &failure)
	return &DeliveryError{StatusCode: response.StatusCode, Reason: failure.Reason}
}

func (a *APNS) providerToken() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	if a.cachedToken != "" && now.Before(a.tokenExpiry) {
		return a.cachedToken, nil
	}
	claims := jwt.MapClaims{"iss": a.teamID, "iat": now.Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = a.keyID
	signed, err := token.SignedString(a.key)
	if err != nil {
		return "", err
	}
	a.cachedToken = signed
	a.tokenExpiry = now.Add(50 * time.Minute)
	return signed, nil
}

func (a *APNS) Close() {
	if transport, ok := a.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
