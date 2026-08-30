package store

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func TestProjectConversationMembersUsesACLAndPreservesStableLocalObjects(t *testing.T) {
	ownerID := uuid.New()
	memberID := uuid.New()
	removedID := uuid.New()
	deletedID := uuid.New()
	ownerLocalID := uuid.NewString()
	deletedLocalID := uuid.NewString()
	pendingLocalID := uuid.NewString()
	joined := time.Now().UTC()
	metadata := json.RawMessage(`{
		"theme":"trip",
		"members":[
			{"id":"` + ownerLocalID + `","backendUserId":"` + ownerID.String() + `","name":"Spoofed owner","email":"private@example.com","phone":"+13125550199","username":"@spoof","avatarColor":"#111111","profileImageData":"private-blob","custom":"drop"},
			{"id":"duplicate-owner","backendUserId":"` + ownerID.String() + `","name":"Duplicate"},
			{"id":"removed-local","backendUserId":"` + removedID.String() + `","name":"Removed"},
			{"id":"` + deletedLocalID + `","backendUserId":"` + deletedID.String() + `","name":"Spoofed tombstone","email":"deleted@example.com","phone":"+13125550198","isDeleted":true},
			{"id":"` + pendingLocalID + `","name":"Pending contact","phone":"+13125550123","avatarColor":"#222222"}
			,{"id":"` + uuid.NewString() + `","backendUserId":"not-a-uuid","name":"Malformed"}
			,{"id":"` + uuid.NewString() + `","backendUserId":"` + ownerID.String() + `","backend_user_id":"` + memberID.String() + `","name":"Ambiguous"}
			,{"id":"contact@example.com","name":"Unsafe local ID"}
		]
	}`)
	projected, err := ProjectConversationMembers(metadata, []domain.ConversationMember{
		{
			ConversationID: uuid.New(), UserID: ownerID, Role: "owner", JoinedAt: joined,
			DisplayName: "Server owner", Username: "@owner", AvatarColor: "#AAAAAA",
			AvatarURL: "clustr-media://owner", Bio: "public bio",
		},
		{
			ConversationID: uuid.New(), UserID: memberID, Role: "member", JoinedAt: joined.Add(time.Second),
			DisplayName: "New member", Username: "@member", AvatarColor: "#BBBBBB",
		},
	}, ConversationMemberTombstone{UserID: deletedID, LocalID: uuid.MustParse(deletedLocalID)})
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Theme   string                   `json:"theme"`
		Members []map[string]interface{} `json:"members"`
	}
	if err := json.Unmarshal(projected, &root); err != nil {
		t.Fatal(err)
	}
	if root.Theme != "trip" || len(root.Members) != 3 {
		t.Fatalf("unexpected projection: %s", projected)
	}
	byID := make(map[string]map[string]interface{}, len(root.Members))
	for _, member := range root.Members {
		byID[member["id"].(string)] = member
	}
	owner := byID[ownerLocalID]
	if owner == nil || owner["name"] != "Server owner" || owner["username"] != "@owner" ||
		owner["avatarColor"] != "#AAAAAA" || owner["profileImageURL"] != "clustr-media://owner" ||
		owner["bio"] != nil || owner["rosterState"] != "active" {
		t.Fatalf("owner was not rebuilt from authoritative identity: %+v", owner)
	}
	if _, duplicate := byID["duplicate-owner"]; duplicate {
		t.Fatalf("duplicate ACL projection was retained: %+v", root.Members)
	}
	if _, removed := byID["removed-local"]; removed {
		t.Fatalf("removed ACL user remained projected: %+v", root.Members)
	}
	deleted := byID[deletedLocalID]
	if deleted == nil || deleted["name"] != DeletedUserDisplayName || deleted["isDeleted"] != true ||
		byID[pendingLocalID] != nil {
		t.Fatalf("trusted history or private contact handling failed: %+v", root.Members)
	}
	if len(deleted) != 6 || deleted["backendUserId"] != deletedID.String() ||
		deleted["avatarColor"] != defaultMemberAvatarColor ||
		deleted["rosterState"] != "inactiveTombstone" {
		t.Fatalf("deleted member was not reduced to a minimal server tombstone: %+v", deleted)
	}
	synthesized := byID[memberID.String()]
	if synthesized == nil || synthesized["backendUserId"] != memberID.String() ||
		synthesized["name"] != "New member" || synthesized["avatarColor"] != "#BBBBBB" {
		t.Fatalf("missing ACL member was not safely synthesized: %+v", synthesized)
	}
	encoded := string(projected)
	for _, forbidden := range []string{
		"private@example.com", "+13125550199", "@spoof", "private-blob", "custom",
		"deleted@example.com", "+13125550198", "+13125550123", "Malformed", "Ambiguous",
		"contact@example.com", "Unsafe local ID",
		"public bio", "Pending contact",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("member projection retained forbidden value %q: %s", forbidden, projected)
		}
	}
	for range 100 {
		repeated, repeatErr := ProjectConversationMembers(metadata, []domain.ConversationMember{
			{
				ConversationID: uuid.New(), UserID: ownerID, Role: "owner", JoinedAt: joined,
				DisplayName: "Server owner", Username: "@owner", AvatarColor: "#AAAAAA",
				AvatarURL: "clustr-media://owner", Bio: "public bio",
			},
			{
				ConversationID: uuid.New(), UserID: memberID, Role: "member", JoinedAt: joined.Add(time.Second),
				DisplayName: "New member", Username: "@member", AvatarColor: "#BBBBBB",
			},
		}, ConversationMemberTombstone{UserID: deletedID, LocalID: uuid.MustParse(deletedLocalID)})
		if repeatErr != nil {
			t.Fatal(repeatErr)
		}
		if !bytes.Equal(repeated, projected) {
			t.Fatalf("ambiguous identity handling was nondeterministic:\nfirst: %s\nnext:  %s", projected, repeated)
		}
	}
}

func TestConversationMemberLocalIDsRejectCollisionsAndRemainImmutable(t *testing.T) {
	conversationID, first, second := uuid.New(), uuid.New(), uuid.New()
	firstStable := uuid.New()
	members := []domain.ConversationMember{
		{ConversationID: conversationID, UserID: first},
		{ConversationID: conversationID, UserID: second},
	}
	malicious := json.RawMessage(`{"members":[` +
		`{"id":"` + second.String() + `","backendUserId":"` + first.String() + `"},` +
		`{"id":"` + second.String() + `","backendUserId":"` + second.String() + `"}` +
		`]}`)
	derived := DeriveConversationMemberLocalIDs(malicious, members, []ConversationMemberLocalID{
		{UserID: first, LocalID: firstStable},
	})
	byUser := make(map[uuid.UUID]uuid.UUID)
	byLocal := make(map[uuid.UUID]uuid.UUID)
	for _, mapping := range derived {
		if owner, collision := byLocal[mapping.LocalID]; collision && owner != mapping.UserID {
			t.Fatalf("local ID collision survived: %+v", derived)
		}
		byUser[mapping.UserID] = mapping.LocalID
		byLocal[mapping.LocalID] = mapping.UserID
	}
	if byUser[first] != firstStable {
		t.Fatalf("metadata remapped immutable local ID: got %s want %s", byUser[first], firstStable)
	}
	if byUser[second] != second {
		t.Fatalf("colliding proposal was not replaced with safe baseline: %+v", derived)
	}
	projected, err := ProjectConversationMembersWithLocalIDs(malicious, members, derived)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(projected, []byte(firstStable.String())) {
		t.Fatalf("projection did not use server-owned mapping: %s", projected)
	}
}

func TestPublicUserFromUserNeverLeaksPrivateDirectoryFields(t *testing.T) {
	user := domain.User{
		ID: uuid.New(), Email: "secret@example.com", Phone: "+13125550123",
		DisplayName: "Akhil", AvatarURL: "clustr-media://profile/avatar",
		Profile: json.RawMessage(`{
			"username":"@akhil","bio":"hello","avatar_color":"#123456",
			"contact_email":"private@example.com","contact_phone":"+13125550999",
			"auto_settle_settings":{"secret":true}
		}`),
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	usernameResult, err := json.Marshal(PublicUserFromUser(user, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"secret@example.com", "+13125550123", "private@example.com", "+13125550999", "auto_settle_settings",
	} {
		if strings.Contains(string(usernameResult), forbidden) {
			t.Fatalf("username discovery leaked %q: %s", forbidden, usernameResult)
		}
	}
	phoneResult, err := json.Marshal(PublicUserFromUser(user, true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(phoneResult), user.Phone) || strings.Contains(string(phoneResult), user.Email) {
		t.Fatalf("exact phone lookup correlation is incorrect: %s", phoneResult)
	}
}

func TestJSONValuesEqualIgnoresJSONBWireFormatting(t *testing.T) {
	if !JSONValuesEqual(
		json.RawMessage(`{"members":[{"id":"one"}],"theme":"trip"}`),
		json.RawMessage(`{ "theme": "trip", "members": [ { "id": "one" } ] }`),
	) {
		t.Fatal("semantically equal JSON values compared unequal")
	}
	if JSONValuesEqual(json.RawMessage(`{"members":[]}`), json.RawMessage(`{"members":[{}]}`)) {
		t.Fatal("different JSON values compared equal")
	}
}
