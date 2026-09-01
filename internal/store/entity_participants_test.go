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
	for _, malformed := range []json.RawMessage{
		json.RawMessage(`{"customAmounts":{"` + activeLocal.String() + `":"10"}}`),
		json.RawMessage(`{"customAmounts":{"` + activeLocal.String() + `":null}}`),
		json.RawMessage(`{"customAmounts":{"not-a-uuid":10}}`),
		json.RawMessage(`{"customAmounts":{"` + activeLocal.String() + `":-1}}`),
		json.RawMessage(`{"paidBy":["` + activeLocal.String() + `"]}`),
		json.RawMessage(`{"splitBetween":"` + activeLocal.String() + `"}`),
		json.RawMessage(`{"payer":{"backendUserId":"` + activeBackend.String() + `","user_id":"` + activeBackend.String() + `"}}`),
		json.RawMessage(`{"payer":{"backendUserId":"` + activeBackend.String() + `","unknownIdentity":"` + activeBackend.String() + `"}}`),
		json.RawMessage(`{"participants":["` + activeBackend.String() + `",{"backendUserId":"` + activeBackend.String() + `"}]}`),
		json.RawMessage(`{"paidBy":"` + activeLocal.String() + `","paid_by":"` + activeLocal.String() + `"}`),
	} {
		if err := ValidateEntityParticipants("expense", malformed, metadata, members); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("malformed participant shape accepted: %s: %v", malformed, err)
		}
	}
}

func TestValidateEntityParticipantsAcceptsCanonicalSwiftUUIDCase(t *testing.T) {
	userID := uuid.MustParse("12345678-1234-4234-9234-123456789abc")
	members := []domain.ConversationMember{{UserID: userID}}
	payload := json.RawMessage(`{"paidBy":"12345678-1234-4234-9234-123456789ABC","splitBetween":["12345678-1234-4234-9234-123456789ABC"],"customAmounts":{"12345678-1234-4234-9234-123456789ABC":1.25}}`)
	if err := ValidateEntityParticipants("expense", payload, nil, members); err != nil {
		t.Fatalf("canonical uppercase Foundation UUID rejected: %v", err)
	}
	for _, invalid := range []json.RawMessage{
		json.RawMessage(`{"paidBy":" 12345678-1234-4234-9234-123456789ABC"}`),
		json.RawMessage(`{"paidBy":"12345678123442349234123456789ABC"}`),
		json.RawMessage(`{"paidBy":"urn:uuid:12345678-1234-4234-9234-123456789ABC"}`),
	} {
		if err := ValidateEntityParticipants("expense", invalid, nil, members); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("non-canonical UUID accepted: payload=%s err=%v", invalid, err)
		}
	}
}
