package verification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const telnyxMessagesEndpoint = "https://api.telnyx.com/v2/messages"

type SMSSender interface {
	SendCode(context.Context, string, string, time.Duration) (string, error)
}

type ProviderError struct {
	StatusCode int
	Code       string
}

func (e *ProviderError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("SMS provider returned status %d", e.StatusCode)
	}
	return fmt.Sprintf("SMS provider returned status %d (%s)", e.StatusCode, e.Code)
}

type TelnyxSMS struct {
	apiKey             string
	fromNumber         string
	messagingProfileID string
	webhookURL         string
	endpoint           string
	client             *http.Client
	now                func() time.Time
}

func NewTelnyxSMS(apiKey, fromNumber, messagingProfileID, webhookURL string) (*TelnyxSMS, error) {
	apiKey = strings.TrimSpace(apiKey)
	fromNumber = strings.TrimSpace(fromNumber)
	if apiKey == "" || fromNumber == "" {
		return nil, ErrUnavailable
	}
	return &TelnyxSMS{
		apiKey:             apiKey,
		fromNumber:         fromNumber,
		messagingProfileID: strings.TrimSpace(messagingProfileID),
		webhookURL:         strings.TrimSpace(webhookURL),
		endpoint:           telnyxMessagesEndpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}, nil
}

func (t *TelnyxSMS) SendCode(ctx context.Context, destination, code string, ttl time.Duration) (string, error) {
	payload := struct {
		From               string   `json:"from"`
		To                 string   `json:"to"`
		Text               string   `json:"text"`
		Type               string   `json:"type"`
		Encoding           string   `json:"encoding"`
		MessagingProfileID string   `json:"messaging_profile_id,omitempty"`
		WebhookURL         string   `json:"webhook_url,omitempty"`
		UseProfileWebhooks bool     `json:"use_profile_webhooks"`
		ValidUntil         string   `json:"valid_until"`
		Tags               []string `json:"tags"`
	}{
		From: t.fromNumber, To: destination,
		Text: fmt.Sprintf(
			"Clustr code: %s. Expires in %d minutes. Do not share it. Reply STOP to opt out.",
			code, int(ttl.Round(time.Minute)/time.Minute),
		),
		Type: "SMS", Encoding: "gsm7", MessagingProfileID: t.messagingProfileID,
		WebhookURL: t.webhookURL, UseProfileWebhooks: false,
		ValidUntil: t.now().Add(ttl).UTC().Format(time.RFC3339), Tags: []string{"clustr-otp"},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode SMS request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create SMS request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+t.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := t.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("SMS provider request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read SMS provider response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var providerResponse struct {
			Errors []struct {
				Code string `json:"code"`
			} `json:"errors"`
		}
		_ = json.Unmarshal(responseBody, &providerResponse)
		providerCode := ""
		if len(providerResponse.Errors) > 0 {
			providerCode = safeProviderCode(providerResponse.Errors[0].Code)
		}
		return "", &ProviderError{StatusCode: response.StatusCode, Code: providerCode}
	}
	var providerResponse struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(responseBody, &providerResponse); err != nil {
		return "", fmt.Errorf("decode SMS provider response: %w", err)
	}
	if strings.TrimSpace(providerResponse.Data.ID) == "" {
		return "", errorsNoMessageID
	}
	return providerResponse.Data.ID, nil
}

var errorsNoMessageID = fmt.Errorf("SMS provider response did not contain a message ID")

func safeProviderCode(value string) string {
	if len(value) > 32 {
		return ""
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return ""
		}
	}
	return value
}
