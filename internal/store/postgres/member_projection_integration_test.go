package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresACLAndLegacyMemberProjectionRemainAtomic(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	createUser := func(label string) domain.User {
		t.Helper()
		user, err := persistence.CreateUser(ctx, store.CreateUserParams{
			Email:       "projection-" + label + "-" + uuid.NewString() + "@example.com",
			DisplayName: label, PasswordHash: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	owner := createUser("owner")
	member := createUser("member")
	added := createUser("added")
	if _, err := persistence.UpdateUserProfile(ctx, member.ID, json.RawMessage(`{
		"display_name":"Public Member","username":"@pg_member","avatar_color":"#123456",
		"contact_email":"private@example.com","contact_phone":"+13125550999"
	}`)); err != nil {
		t.Fatal(err)
	}
	ownerLocalID := uuid.NewString()
	memberLocalID := uuid.NewString()
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: owner.ID, MemberIDs: []uuid.UUID{member.ID},
		Metadata: json.RawMessage(`{"members":[
			{"id":"` + ownerLocalID + `","backendUserId":"` + owner.ID.String() + `","name":"Owner","avatarColor":"#111111"},
			{"id":"` + memberLocalID + `","backendUserId":"` + member.ID.String() + `","name":"Member","avatarColor":"#222222"},
			{"id":"stale","backendUserId":"` + added.ID.String() + `","name":"Stale"}
		]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPostgresProjectedMember(t, conversation.Metadata, owner.ID, ownerLocalID, true)
	assertPostgresProjectedMember(t, conversation.Metadata, member.ID, memberLocalID, true)
	assertPostgresProjectedMember(t, conversation.Metadata, added.ID, "", false)

	members, err := persistence.ListConversationMembers(ctx, conversation.ID, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	var publicMember *domain.ConversationMember
	for index := range members {
		if members[index].UserID == member.ID {
			publicMember = &members[index]
			break
		}
	}
	if publicMember == nil || publicMember.DisplayName != "Public Member" ||
		publicMember.Username != "@pg_member" || publicMember.AvatarColor != "#123456" {
		t.Fatalf("public member identity mismatch: %+v", publicMember)
	}
	encodedMembers, _ := json.Marshal(members)
	for _, forbidden := range []string{"private@example.com", "+13125550999", `"email"`, `"phone"`} {
		if strings.Contains(string(encodedMembers), forbidden) {
			t.Fatalf("member listing leaked %q: %s", forbidden, encodedMembers)
		}
	}

	if err := persistence.AddConversationMember(ctx, conversation.ID, member.ID, added.ID, "member"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("ordinary member add returned %v, want forbidden", err)
	}
	if err := persistence.AddConversationMember(ctx, conversation.ID, owner.ID, added.ID, "member"); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.Conversation(ctx, conversation.ID, added.ID); err != nil {
		t.Fatalf("added ACL member was denied: %v", err)
	}
	if err := persistence.RemoveConversationMember(ctx, conversation.ID, owner.ID, added.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.Conversation(ctx, conversation.ID, added.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("removed ACL member read returned %v", err)
	}
	stale := json.RawMessage(`{"members":[{"id":"stale-replay","backendUserId":"` +
		added.ID.String() + `","name":"Stale replay","role":"owner"}]}`)
	updated, err := persistence.UpdateConversation(ctx, conversation.ID, owner.ID, store.UpdateConversationParams{
		Metadata: &stale,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPostgresProjectedMember(t, updated.Metadata, added.ID, "", false)
	if _, err := persistence.Conversation(ctx, conversation.ID, added.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("stale metadata restored ACL access: %v", err)
	}
}

func assertPostgresProjectedMember(
	t *testing.T,
	metadata json.RawMessage,
	backendID uuid.UUID,
	localID string,
	want bool,
) {
	t.Helper()
	var root struct {
		Members []struct {
			ID            string `json:"id"`
			BackendUserID string `json:"backendUserId"`
		} `json:"members"`
	}
	if err := json.Unmarshal(metadata, &root); err != nil {
		t.Fatal(err)
	}
	for _, member := range root.Members {
		if member.BackendUserID != backendID.String() {
			continue
		}
		if !want {
			t.Fatalf("unexpected projected member %s: %s", backendID, metadata)
		}
		if localID != "" && member.ID != localID {
			t.Fatalf("local id=%q want=%q: %s", member.ID, localID, metadata)
		}
		return
	}
	if want {
		t.Fatalf("projected member %s missing: %s", backendID, metadata)
	}
}
