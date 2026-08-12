package push

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestEncodePayloadUsesTopLevelClientKeys(t *testing.T) {
	raw, err := EncodePayload("Group 1", "Akhil sent a message", map[string]string{
		"type": "message", "groupId": "group-id", "entityId": "message-id",
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if _, nested := payload["data"]; nested {
		t.Fatal("custom APNs fields must not be nested under data")
	}
	for key, want := range map[string]string{
		"type": "message", "groupId": "group-id", "entityId": "message-id",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %q", key, got, want)
		}
	}
	aps, ok := payload["aps"].(map[string]any)
	if !ok {
		t.Fatalf("aps = %#v", payload["aps"])
	}
	if aps["sound"] != "default" || aps["badge"] != float64(1) {
		t.Fatalf("aps = %#v", aps)
	}
	alert, ok := aps["alert"].(map[string]any)
	if !ok || alert["title"] != "Group 1" || alert["body"] != "Akhil sent a message" {
		t.Fatalf("alert = %#v", aps["alert"])
	}
}

func TestEnvironmentFallbackRoutesWrongEnvironmentToken(t *testing.T) {
	primary := &fakeService{err: &DeliveryError{StatusCode: 400, Reason: "BadDeviceToken"}}
	fallback := &fakeService{}
	service := &EnvironmentFallback{Primary: primary, Fallback: fallback}

	err := service.Send(context.Background(), "token", "title", "body", nil, "notification")
	if err != nil {
		t.Fatal(err)
	}
	if primary.calls != 1 || fallback.calls != 1 {
		t.Fatalf("calls primary=%d fallback=%d", primary.calls, fallback.calls)
	}
}

func TestEnvironmentFallbackOnlyInvalidatesAfterBothEndpointsRejectToken(t *testing.T) {
	service := &EnvironmentFallback{
		Primary:  &fakeService{err: &DeliveryError{StatusCode: 400, Reason: "BadDeviceToken"}},
		Fallback: &fakeService{err: &DeliveryError{StatusCode: 410, Reason: "Unregistered"}},
	}
	err := service.Send(context.Background(), "token", "title", "body", nil, "notification")
	if !IsInvalidToken(err) {
		t.Fatalf("expected invalid token error, received %v", err)
	}

	service.Fallback = &fakeService{err: errors.New("sandbox credentials unavailable")}
	err = service.Send(context.Background(), "token", "title", "body", nil, "notification")
	if IsInvalidToken(err) {
		t.Fatalf("must not prune token when sandbox could not authenticate: %v", err)
	}
}

type fakeService struct {
	calls int
	err   error
}

func (f *fakeService) Send(context.Context, string, string, string, map[string]string, string) error {
	f.calls++
	return f.err
}

func (*fakeService) Close() {}
