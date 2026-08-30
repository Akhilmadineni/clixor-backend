package store

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func TestValidateEntityParticipantsRequiresCurrentActiveRoster(t *testing.T) {
	activeBackend, activeLocal := uuid.New(), uuid.New()
	removedBackend, removedLocal := uuid.New(), uuid.New()
	metadata := json.RawMessage(`{"members":[` +
		`{"id":"` + activeLocal.String() + `","backendUserId":"` + activeBackend.String() + `","rosterState":"active"},` +
		`{"id":"` + removedLocal.String() + `","backendUserId":"` + removedBackend.String() + `","isDeleted":true,"rosterState":"inactiveTombstone"}` +
		`]}`)
	members := []domain.ConversationMember{{UserID: activeBackend}}
	valid := []struct {
		kind    string
		payload json.RawMessage
	}{
		{"expense", json.RawMessage(`{"paidBy":"` + activeLocal.String() + `","split_between":["` + activeBackend.String() + `"],"customAmounts":{"` + activeLocal.String() + `":10}}`)},
		{"task", json.RawMessage(`{"assignedTo":"` + activeLocal.String() + `","created_by":"` + activeBackend.String() + `"}`)},
		{"chore", json.RawMessage(`{"assigned_to":null,"rotateOrder":["` + activeLocal.String() + `"]}`)},
		{"settlement", json.RawMessage(`{"from":"` + activeLocal.String() + `","to":"` + activeBackend.String() + `"}`)},
		{"expense", json.RawMessage(`{"payer":{"backendUserId":"` + activeBackend.String() + `","displayName":"safe"}}`)},
	}
	for _, test := range valid {
		if err := ValidateEntityParticipants(test.kind, test.payload, metadata, members); err != nil {
			t.Fatalf("valid %s rejected: %v", test.kind, err)
		}
	}
	for _, stale := range []uuid.UUID{removedBackend, removedLocal, uuid.New()} {
		for _, payload := range []json.RawMessage{
			json.RawMessage(`{"paidBy":"` + stale.String() + `"}`),
			json.RawMessage(`{"splitBetween":["` + stale.String() + `"]}`),
			json.RawMessage(`{"assignedTo":"` + stale.String() + `"}`),
			json.RawMessage(`{"rotate_order":["` + stale.String() + `"]}`),
			json.RawMessage(`{"from":"` + activeLocal.String() + `","to":"` + stale.String() + `"}`),
		} {
			if err := ValidateEntityParticipants("expense", payload, metadata, members); !errors.Is(err, domain.ErrInvalid) {
				t.Fatalf("stale participant %s accepted in %s: %v", stale, payload, err)
			}
		}
	}
}
