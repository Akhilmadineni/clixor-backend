package verification

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/redis/go-redis/v9"
)

const webhookReplayWindow = 5 * time.Minute

func decodeWebhookPublicKey(encoded string) (ed25519.PublicKey, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errorsInvalidPublicKey
	}
	return ed25519.PublicKey(decoded), nil
}

var errorsInvalidPublicKey = fmt.Errorf("Telnyx webhook public key must be a base64-encoded Ed25519 key")

func (o *OTP) HandleWebhook(ctx context.Context, signatureHeader, timestampHeader string, body []byte) error {
	if len(o.webhookPublicKey) != ed25519.PublicKeySize {
		return ErrUnavailable
	}
	timestamp, err := strconv.ParseInt(strings.TrimSpace(timestampHeader), 10, 64)
	if err != nil {
		return ErrInvalidWebhook
	}
	eventTime := time.Unix(timestamp, 0)
	now := o.now()
	if eventTime.Before(now.Add(-webhookReplayWindow)) || eventTime.After(now.Add(webhookReplayWindow)) {
		return ErrInvalidWebhook
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureHeader))
	if err != nil {
		return ErrInvalidWebhook
	}
	signedPayload := []byte(timestampHeader + "|" + string(body))
	if !ed25519.Verify(o.webhookPublicKey, signedPayload, signature) {
		return ErrInvalidWebhook
	}

	var event struct {
		Data struct {
			ID        string `json:"id"`
			EventType string `json:"event_type"`
			Payload   struct {
				ID        string   `json:"id"`
				Direction string   `json:"direction"`
				Tags      []string `json:"tags"`
				To        []struct {
					Status string `json:"status"`
				} `json:"to"`
			} `json:"payload"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &event); err != nil || event.Data.ID == "" {
		return ErrInvalidWebhook
	}
	if event.Data.EventType != "message.sent" && event.Data.EventType != "message.finalized" {
		return nil
	}
	if event.Data.Payload.ID == "" || event.Data.Payload.Direction != "outbound" ||
		!contains(event.Data.Payload.Tags, "clustr-otp") {
		return nil
	}
	status := "sent"
	if len(event.Data.Payload.To) > 0 {
		status = event.Data.Payload.To[0].Status
	}
	if !validDeliveryStatus(status) {
		status = "unknown"
	}

	dedupeKey := o.prefix + "webhook:event:" + event.Data.ID
	deliveryKey := o.prefix + "delivery:" + event.Data.Payload.ID
	stored, err := recordDeliveryScript.Run(
		ctx, o.client, []string{dedupeKey, deliveryKey},
		event.Data.ID, status, (24 * time.Hour).Milliseconds(),
	).Int()
	if err != nil {
		return fmt.Errorf("record Telnyx delivery: %w", err)
	}
	if stored == 0 {
		return nil
	}
	observability.VerificationDeliveryEvents.WithLabelValues(status).Inc()
	return nil
}

var recordDeliveryScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
redis.call('HSET', KEYS[2], 'status', ARGV[2], 'event_id', ARGV[1])
redis.call('PEXPIRE', KEYS[2], ARGV[3])
return 1
`)

func validDeliveryStatus(status string) bool {
	switch status {
	case "queued", "sent", "delivered", "delivery_failed", "delivery_unconfirmed":
		return true
	default:
		return false
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
