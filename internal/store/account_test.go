package store

import (
	"encoding/json"
	"strings"
	"testing"

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
