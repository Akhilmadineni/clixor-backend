package push

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

type Service interface {
	Send(context.Context, string, string, string, map[string]string, string) error
	Close()
}

type Disabled struct{}

func (Disabled) Send(context.Context, string, string, string, map[string]string, string) error {
	return nil
}
func (Disabled) Close() {}

type APS struct {
	Alert Alert  `json:"alert"`
	Sound string `json:"sound,omitempty"`
	Badge int    `json:"badge,omitempty"`
}

type Alert struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func EncodePayload(title, body string, data map[string]string) ([]byte, error) {
	// APNs custom data belongs at the top level. The iOS client reads type,
	// groupId, and entityId directly from UNNotificationContent.userInfo.
	payload := make(map[string]any, len(data)+1)
	payload["aps"] = APS{
		Alert: Alert{Title: title, Body: body}, Sound: "default", Badge: 1,
	}
	for key, value := range data {
		if key != "aps" {
			payload[key] = value
		}
	}
	return json.Marshal(payload)
}

// DeliveryError is an APNs rejection. Callers use it to distinguish an
// invalid device token from transient provider failures without inspecting
// error strings or logging the token itself.
type DeliveryError struct {
	StatusCode int
	Reason     string
}

func (e *DeliveryError) Error() string {
	return fmt.Sprintf("APNs status %d: %s", e.StatusCode, e.Reason)
}

func IsInvalidToken(err error) bool {
	var delivery *DeliveryError
	if !errors.As(err, &delivery) {
		return false
	}
	if delivery.StatusCode == 410 {
		return true
	}
	switch delivery.Reason {
	case "BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered":
		return true
	default:
		return false
	}
}

// EnvironmentFallback supports both production and sandbox device tokens
// without changing the existing device-registration API. APNs rejects a token
// sent to the wrong environment; only when both environments reject it as an
// invalid token do we allow the relay to prune it.
type EnvironmentFallback struct {
	Primary  Service
	Fallback Service
}

func (s *EnvironmentFallback) Send(
	ctx context.Context,
	deviceToken, title, body string,
	data map[string]string,
	notificationID string,
) error {
	primaryErr := s.Primary.Send(ctx, deviceToken, title, body, data, notificationID)
	if primaryErr == nil || !IsInvalidToken(primaryErr) || s.Fallback == nil {
		return primaryErr
	}
	fallbackErr := s.Fallback.Send(ctx, deviceToken, title, body, data, notificationID)
	if fallbackErr == nil {
		return nil
	}
	if IsInvalidToken(fallbackErr) {
		return &DeliveryError{StatusCode: 410, Reason: "Unregistered"}
	}
	return fallbackErr
}

func (s *EnvironmentFallback) Close() {
	if s.Primary != nil {
		s.Primary.Close()
	}
	if s.Fallback != nil {
		s.Fallback.Close()
	}
}
