package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestRotationPayloadBindingsRejectCrossResourceAndNonDeterministicFeed(t *testing.T) {
	conversationID, choreID, operationID := uuid.New(), uuid.New(), uuid.New()
	chore := json.RawMessage(`{"id":"` + choreID.String() + `","groupId":"` + conversationID.String() + `"}`)
	feed := json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + conversationID.String() + `","relatedId":"` + choreID.String() + `","type":"note"}`)
	if !rotationPayloadBindings(chore, feed, conversationID, choreID, operationID) {
		t.Fatal("valid bindings rejected")
	}
	for name, bad := range map[string]json.RawMessage{
		"foreign conversation": json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + uuid.NewString() + `","relatedId":"` + choreID.String() + `","type":"note"}`),
		"foreign chore":        json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + conversationID.String() + `","relatedId":"` + uuid.NewString() + `","type":"note"}`),
		"random feed id":       json.RawMessage(`{"id":"` + uuid.NewString() + `","groupId":"` + conversationID.String() + `","relatedId":"` + choreID.String() + `","type":"note"}`),
		"wrong type":           json.RawMessage(`{"id":"` + operationID.String() + `","groupId":"` + conversationID.String() + `","relatedId":"` + choreID.String() + `","type":"expense"}`),
	} {
		if rotationPayloadBindings(chore, bad, conversationID, choreID, operationID) {
			t.Fatalf("accepted %s", name)
		}
	}
}
