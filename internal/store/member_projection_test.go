package store

import (
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
	joined := time.Now().UTC()
	metadata := json.RawMessage(`{
		"theme":"trip",
		"members":[
			{"id":"local-owner-id","backendUserId":"` + ownerID.String() + `","name":"Local owner","avatarColor":"#111111","custom":"keep"},
			{"id":"duplicate-owner","backendUserId":"` + ownerID.String() + `","name":"Duplicate"},
			{"id":"removed-local","backendUserId":"` + removedID.String() + `","name":"Removed"},
			{"id":"deleted-local","backendUserId":"` + deletedID.String() + `","name":"Deleted user","isDeleted":true},
			{"id":"pending-contact","name":"Pending contact","phone":"+13125550123","avatarColor":"#222222"}
		]
	}`)
	projected, err := ProjectConversationMembers(metadata, []domain.ConversationMember{
		{
			ConversationID: uuid.New(), UserID: ownerID, Role: "owner", JoinedAt: joined,
			DisplayName: "Server owner", Username: "@owner", AvatarColor: "#AAAAAA",
		},
		{
			ConversationID: uuid.New(), UserID: memberID, Role: "member", JoinedAt: joined.Add(time.Second),
			DisplayName: "New member", Username: "@member", AvatarColor: "#BBBBBB",
		},
	})
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
	if root.Theme != "trip" || len(root.Members) != 4 {
		t.Fatalf("unexpected projection: %s", projected)
	}
	byID := make(map[string]map[string]interface{}, len(root.Members))
	for _, member := range root.Members {
		byID[member["id"].(string)] = member
	}
	owner := byID["local-owner-id"]
	if owner == nil || owner["custom"] != "keep" || owner["name"] != "Local owner" {
		t.Fatalf("owner local object was not preserved: %+v", owner)
	}
	if _, duplicate := byID["duplicate-owner"]; duplicate {
		t.Fatalf("duplicate ACL projection was retained: %+v", root.Members)
	}
	if _, removed := byID["removed-local"]; removed {
		t.Fatalf("removed ACL user remained projected: %+v", root.Members)
	}
	if byID["deleted-local"] == nil || byID["pending-contact"] == nil {
		t.Fatalf("historical/contact-only members were lost: %+v", root.Members)
	}
	synthesized := byID[memberID.String()]
	if synthesized == nil || synthesized["backendUserId"] != memberID.String() ||
		synthesized["name"] != "New member" || synthesized["avatarColor"] != "#BBBBBB" {
		t.Fatalf("missing ACL member was not safely synthesized: %+v", synthesized)
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
