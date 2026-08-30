package httpapi

import (
	"os"
	"strings"
	"testing"
)

func TestOpenAPISplitsConversationAndProfileMediaIntegrityContracts(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	document := string(raw)
	avatar := openAPISection(t, document, "  /me/avatar:", "  /me/phone/start:")
	conversation := openAPISection(
		t, document,
		"  /conversations/{conversation_id}/media:",
		"  /media/{media_id}/complete:",
	)
	completion := openAPISection(
		t, document,
		"  /media/{media_id}/complete:",
		"  /media/{media_id}/download:",
	)
	if !strings.Contains(avatar, `#/components/schemas/ProfileMediaUploadRequest`) {
		t.Fatal("profile avatar route does not use the bounded profile-media schema")
	}
	if !strings.Contains(conversation, `#/components/schemas/ConversationMediaUploadRequest`) {
		t.Fatal("conversation route does not use the production-05b media schema")
	}
	for _, required := range []string{
		"conversation media is verified by size only",
		"declared SHA-256 is stored but not checked by the server",
		"authenticate and decrypt conversation ciphertext client-side",
		"profile-media SHA-256 does not match",
	} {
		if !strings.Contains(completion, required) {
			t.Fatalf("media completion contract is missing %q", required)
		}
	}
	profileSchema := openAPISection(
		t, document,
		"    ProfileMediaUploadRequest:",
		"    MediaObject:",
	)
	for _, required := range []string{
		"maximum: 20971520",
		"enum: [image/jpeg, image/png, image/heic, image/webp]",
		"default: image/jpeg",
	} {
		if !strings.Contains(profileSchema, required) {
			t.Fatalf("profile media schema is missing %q", required)
		}
	}
	conversationSchema := openAPISection(
		t, document,
		"    ConversationMediaUploadRequest:",
		"    ProfileMediaUploadRequest:",
	)
	if !strings.Contains(conversationSchema, "maximum: 1073741824") {
		t.Fatal("conversation media schema lost the production-05b 1 GiB bound")
	}
}

func openAPISection(t *testing.T, document, start, end string) string {
	t.Helper()
	startAt := strings.Index(document, start)
	if startAt < 0 {
		t.Fatalf("OpenAPI section %q is missing", start)
	}
	endAt := strings.Index(document[startAt+len(start):], end)
	if endAt < 0 {
		t.Fatalf("OpenAPI section terminator %q is missing", end)
	}
	return document[startAt : startAt+len(start)+endAt]
}
