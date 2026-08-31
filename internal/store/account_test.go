package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func TestAnonymizeAccountJSONPreservesStableIDsAndRemovesIdentity(t *testing.T) {
	userID := uuid.New()
	raw := json.RawMessage(`{
		"members":[{
			"id":"local-member-7",
			"backendUserId":"` + userID.String() + `",
			"displayName":"Akhil",
			"email":"akhil@example.com",
			"username":"@akhil",
			"profileImageURL":"https://media.example/private.jpg"
		}],
		"unrelated":{"name":"Keep me","email":"other@example.com"}
	}`)
	anonymized, changed, err := AnonymizeAccountJSON(raw, AccountIdentity{
		UserID: userID, Email: "akhil@example.com", DisplayName: "Akhil", Username: "@akhil",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("identity-bearing JSON was not changed")
	}
	text := string(anonymized)
	for _, forbidden := range []string{"Akhil", "akhil@example.com", "@akhil", "private.jpg"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("anonymized JSON retained %q: %s", forbidden, text)
		}
	}
	for _, retained := range []string{userID.String(), "local-member-7", "Deleted user", "Keep me", "other@example.com"} {
		if !strings.Contains(text, retained) {
			t.Fatalf("anonymized JSON removed required %q: %s", retained, text)
		}
	}
}

func TestAnonymizeAccountJSONCoversCreatorAliasesAndIdentityInProse(t *testing.T) {
	userID := uuid.New()
	expenseID := uuid.New()
	raw := json.RawMessage(`{
		"createdBy":"` + userID.String() + `",
		"creatorName":"Akhil Madineni",
		"creatorDisplayName":"Akhil Madineni",
		"createdByName":"Akhil Madineni",
		"createdByDisplayName":"Akhil Madineni",
		"actorName":"Akhil Madineni",
		"actorDisplayName":"Akhil Madineni",
		"ownerName":"Akhil Madineni",
		"ownerDisplayName":"Akhil Madineni",
		"description":"Akhil Madineni / Akhil Madineni (@akhil) paid 42.75; email akhil@example.com or call +13125550177.",
		"mentions":["@akhil","contact akhil@example.com"],
		"expenseId":"` + expenseID.String() + `",
		"amount":42.75,
		"currency":"USD"
	}`)
	anonymized, changed, err := AnonymizeAccountJSON(raw, AccountIdentity{
		UserID: userID, Email: "akhil@example.com", Phone: "+13125550177",
		DisplayName: "Akhil Madineni", Username: "@akhil",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("creator-owned JSON was not anonymized")
	}
	text := string(anonymized)
	for _, forbidden := range []string{
		"Akhil Madineni", "@akhil", "akhil@example.com", "+13125550177",
	} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("anonymized creator JSON retained %q: %s", forbidden, text)
		}
	}
	for _, retained := range []string{
		userID.String(), expenseID.String(), `"amount":42.75`, `"currency":"USD"`,
		DeletedUserDisplayName,
	} {
		if !strings.Contains(text, retained) {
			t.Fatalf("anonymized creator JSON removed required %q: %s", retained, text)
		}
	}
}

func TestAnonymizeAccountJSONDoesNotBlankCommonNameOutsideIdentitySchema(t *testing.T) {
	userID := uuid.New()
	settlementID := uuid.New()
	raw := json.RawMessage(`{
		"createdBy":"` + userID.String() + `",
		"creatorDisplayName":"\u0041",
		"description":"A paid the settlement",
		"grade":"A",
		"label":"A",
		"settlementId":"` + settlementID.String() + `",
		"amount":18.5
	}`)
	anonymized, changed, err := AnonymizeAccountJSON(raw, AccountIdentity{
		UserID: userID, DisplayName: "A",
	})
	if err != nil || !changed {
		t.Fatalf("changed=%t err=%v", changed, err)
	}
	var value map[string]any
	if err := json.Unmarshal(anonymized, &value); err != nil {
		t.Fatal(err)
	}
	if value["creatorDisplayName"] != DeletedUserDisplayName ||
		value["description"] != "Deleted user paid the settlement" {
		t.Fatalf("identity fields were not sanitized: %s", anonymized)
	}
	if value["grade"] != "A" || value["label"] != "A" {
		t.Fatalf("common-name collision corrupted unrelated fields: %s", anonymized)
	}
	if value["settlementId"] != settlementID.String() || value["amount"] != 18.5 {
		t.Fatalf("financial history changed: %s", anonymized)
	}
}

func TestAnonymizeAccountJSONRedactsStrongScalarIdentity(t *testing.T) {
	raw := json.RawMessage(`"deleted@example.com"`)
	anonymized, changed, err := AnonymizeAccountJSONWithAuthority(raw, AccountIdentity{
		Email: "deleted@example.com", DisplayName: "A",
	})
	if err != nil || !changed || string(anonymized) != `"Deleted user"` {
		t.Fatalf("scalar anonymized=%s changed=%t err=%v", anonymized, changed, err)
	}
	common, changed, err := AnonymizeAccountJSONWithAuthority(
		json.RawMessage(`"A"`), AccountIdentity{DisplayName: "A"},
	)
	if err != nil || changed || string(common) != `"A"` {
		t.Fatalf("common scalar changed: value=%s changed=%t err=%v", common, changed, err)
	}
}

func TestDecodeAccountOutboxPayloadValidatesOwnedSchemas(t *testing.T) {
	conversationID := uuid.New()
	userID := uuid.New()
	actorID := uuid.New()
	valid := []struct {
		topic string
		raw   json.RawMessage
		user  uuid.UUID
		actor uuid.UUID
	}{
		{
			topic: "receipt.updated",
			raw: mustAccountJSON(t, domain.Receipt{
				ConversationID: conversationID, UserID: userID, DeliveredSeq: 1,
			}),
			user: userID,
		},
		{
			topic: "conversation.member_added",
			raw: mustAccountJSON(t, domain.ConversationMemberAdded{
				ConversationID: conversationID, ActorID: actorID, UserID: userID,
			}),
			user: userID, actor: actorID,
		},
		{
			topic: "entity.updated",
			raw: mustAccountJSON(t, domain.Entity{
				ConversationID: conversationID, Kind: "note", ID: uuid.New(), Version: 1,
				Payload: json.RawMessage(`{}`), CreatedBy: actorID,
			}),
		},
		{
			topic: "conversation.created",
			raw: mustAccountJSON(t, domain.Conversation{
				ID: conversationID, Kind: "group", CreatedBy: actorID,
			}),
		},
		{
			topic: "conversation.updated",
			raw: mustAccountJSON(t, domain.Conversation{
				ID: conversationID, Kind: "group", CreatedBy: actorID,
			}),
		},
	}
	for _, test := range valid {
		decoded, err := DecodeAccountOutboxPayload(test.topic, conversationID, test.raw)
		if err != nil || decoded.ConversationID != conversationID || decoded.UserID != test.user ||
			decoded.ActorID != test.actor {
			t.Fatalf("topic=%s decoded=%+v err=%v", test.topic, decoded, err)
		}
	}
	for _, test := range []struct {
		topic string
		raw   json.RawMessage
	}{
		{"receipt.updated", json.RawMessage(`{"user_id":"` + userID.String() + `"}`)},
		{"conversation.member_added", json.RawMessage(`{"conversation_id":"` + conversationID.String() + `"}`)},
		{"entity.updated", json.RawMessage(`{"email":"deleted@example.com"}`)},
		{"conversation.created", json.RawMessage(`"deleted@example.com"`)},
		{"conversation.updated", json.RawMessage(`"deleted@example.com"`)},
		{"receipt.updated", json.RawMessage(`{"conversation_id":"` + conversationID.String() +
			`","user_id":"` + userID.String() + `","delivered_seq":1,"read_seq":0,` +
			`"updated_at":"0001-01-01T00:00:00Z","unknown":true}`)},
	} {
		if _, err := DecodeAccountOutboxPayload(test.topic, conversationID, test.raw); err == nil {
			t.Fatalf("wrong-shaped %s payload was accepted: %s", test.topic, test.raw)
		}
	}
}

func mustAccountJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
