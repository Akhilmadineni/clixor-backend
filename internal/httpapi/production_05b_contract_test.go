package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/google/uuid"
)

const production05bMediaDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

type production05bMediaUpload struct {
	Media  domain.MediaObject `json:"media"`
	Upload struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	} `json:"upload"`
}

func TestProduction05bFullProfilePayloadAcceptsOwnedConversationMedia(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServerWithMedia(t, &testMediaService{})
	user := registerTestUser(t, server.URL, "production-05b-profile@example.com")

	var conversation domain.Conversation
	user.client.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "05b profile media host",
	}, http.StatusCreated, &conversation)

	var upload production05bMediaUpload
	user.client.do(t, http.MethodPost,
		"/v1/conversations/"+conversation.ID.String()+"/media",
		map[string]any{
			"byte_size": 3, "ciphertext_sha256": production05bMediaDigest,
		}, http.StatusCreated, &upload)
	user.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete",
		nil, http.StatusOK, nil)

	reference := "clustr-media://" + upload.Media.ID.String()
	payload := map[string]any{
		"display_name":      "Production 05b",
		"contact_email":     "profile-contact@example.com",
		"contact_phone":     "+13125550105",
		"avatar_color":      "#123ABC",
		"username":          "@production_05b",
		"bio":               "05b profile contract",
		"profile_image_url": reference,
		"auto_settle_settings": map[string]any{
			"monthlyAmount": 125.0, "frequency": "Monthly", "dayOfMonth": 15,
			"strategy": "Proportional", "isEnabled": true, "isPaused": false,
			"reminderTiming": "On the day", "autoLogPayments": true,
		},
	}
	var updated domain.User
	user.client.do(t, http.MethodPatch, "/v1/me", payload, http.StatusOK, &updated)

	// The 05b AutoSettle flow reads the full profile, changes one nested value,
	// and sends every field (including profile_image_url) back to PATCH /v1/me.
	settings := payload["auto_settle_settings"].(map[string]any)
	settings["monthlyAmount"] = 250.0
	user.client.do(t, http.MethodPatch, "/v1/me", payload, http.StatusOK, &updated)

	var profile map[string]any
	if err := json.Unmarshal(updated.Profile, &profile); err != nil {
		t.Fatal(err)
	}
	if profile["profile_image_url"] != reference || profile["display_name"] != "Production 05b" {
		t.Fatalf("05b profile fields were not preserved: %s", updated.Profile)
	}
	storedSettings, ok := profile["auto_settle_settings"].(map[string]any)
	if !ok || storedSettings["monthlyAmount"] != 250.0 {
		t.Fatalf("05b AutoSettle update was not stored: %s", updated.Profile)
	}
}

func TestProduction05bExistingExternalProfileURLCanOnlyBeReplayed(t *testing.T) {
	t.Parallel()
	persistence := memory.New()
	t.Cleanup(persistence.Close)
	user, err := persistence.CreateUser(context.Background(), store.CreateUserParams{
		Email: "production-05b-legacy-profile@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	const legacyURL = "https://legacy-media.example/profile.jpg"
	if _, err := persistence.UpdateUserProfile(context.Background(), user.ID,
		json.RawMessage(`{"profile_image_url":"`+legacyURL+`"}`)); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: persistence}
	request := httptest.NewRequest(http.MethodPatch, "/v1/me", nil)
	if !server.validLegacyProfileMediaReference(request, user.ID, legacyURL) {
		t.Fatal("an unchanged profile URL stored by the 05b backend was rejected")
	}
	if server.validLegacyProfileMediaReference(request, user.ID, legacyURL+"?replacement=1") {
		t.Fatal("a new external profile URL bypassed the media ownership check")
	}
}

func TestProduction05bStoredMediaReferenceReplaysAfterConversationAccessIsLost(t *testing.T) {
	t.Parallel()
	persistence := memory.New()
	t.Cleanup(persistence.Close)
	ctx := context.Background()
	user, err := persistence.CreateUser(ctx, store.CreateUserParams{
		Email: "production-05b-lost-media-acl@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := persistence.CreateConversation(ctx, store.CreateConversationParams{
		Kind: "group", CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	mediaObject, err := persistence.CreateMedia(ctx, domain.MediaObject{
		ID: uuid.New(), OwnerID: user.ID, ConversationID: conversation.ID,
		ObjectKey: "compat/lost-acl", ContentType: "application/octet-stream",
		ByteSize: 3, CiphertextSHA256: production05bMediaDigest,
	}, store.DefaultMediaReservationLimits())
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := persistence.ClaimMediaVerification(ctx, mediaObject.ID, user.ID, time.Minute)
	if err != nil || claimed.VerificationLeaseToken == nil {
		t.Fatalf("claim media verification: media=%+v err=%v", claimed, err)
	}
	if _, err := persistence.MarkMediaReady(
		ctx, mediaObject.ID, user.ID, *claimed.VerificationLeaseToken, mediaObject.ObjectKey,
	); err != nil {
		t.Fatal(err)
	}
	reference := "clustr-media://" + mediaObject.ID.String()
	if _, err := persistence.UpdateUserProfile(ctx, user.ID,
		json.RawMessage(`{"profile_image_url":"`+reference+`"}`)); err != nil {
		t.Fatal(err)
	}
	if err := persistence.DeleteConversation(ctx, conversation.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: persistence}
	request := httptest.NewRequest(http.MethodPatch, "/v1/me", nil)
	if !server.validLegacyProfileMediaReference(request, user.ID, reference) {
		t.Fatal("byte-for-byte 05b media replay was rejected after its host conversation disappeared")
	}
	if server.validLegacyProfileMediaReference(request, user.ID, reference+" ") {
		t.Fatal("a non-identical reference was treated as a stored byte-for-byte replay")
	}
}

func TestProduction05bMediaRequestDefaultsContentTypeAndKeepsIntegrityVerification(t *testing.T) {
	t.Parallel()
	mediaService := &testMediaService{}
	server := newTestHTTPServerWithMedia(t, mediaService)
	user := registerTestUser(t, server.URL, "production-05b-media@example.com")
	var conversation domain.Conversation
	user.client.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "05b media",
	}, http.StatusCreated, &conversation)

	var upload production05bMediaUpload
	user.client.do(t, http.MethodPost,
		"/v1/conversations/"+conversation.ID.String()+"/media",
		map[string]any{
			"byte_size": 3, "ciphertext_sha256": production05bMediaDigest,
		}, http.StatusCreated, &upload)
	if upload.Upload.Method != http.MethodPut || upload.Upload.URL == "" ||
		upload.Upload.Headers["Content-Type"] != "application/octet-stream" {
		t.Fatalf("unexpected 05b upload instructions: %+v", upload.Upload)
	}
	user.client.do(t, http.MethodPost, "/v1/media/"+upload.Media.ID.String()+"/complete",
		nil, http.StatusOK, nil)
	if mediaService.verifiedSize != 3 || mediaService.verifiedSHA256 != production05bMediaDigest ||
		mediaService.verifiedType != "application/octet-stream" {
		t.Fatalf("05b conversation completion lost its declared integrity metadata: %+v", mediaService)
	}
}

func TestProduction05bAfterSeqMessageCatchUp(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	user := registerTestUser(t, server.URL, "production-05b-messages@example.com")
	var conversation domain.Conversation
	user.client.do(t, http.MethodPost, "/v1/conversations/", map[string]any{
		"kind": "group", "title": "05b messages",
	}, http.StatusCreated, &conversation)
	path := "/v1/conversations/" + conversation.ID.String() + "/messages"
	for sequence := 1; sequence <= 2; sequence++ {
		user.client.do(t, http.MethodPost, path, map[string]any{
			"client_message_id": uuid.NewString(),
			"content_type":      "text",
			"ciphertext":        base64.StdEncoding.EncodeToString([]byte{byte(sequence)}),
			"envelope":          map[string]any{"protocol": "clustr-transition-v1"},
		}, http.StatusCreated, nil)
	}

	var page domain.Page[domain.Message]
	user.client.do(t, http.MethodGet, path+"?after_seq=1&limit=100", nil, http.StatusOK, &page)
	if len(page.Items) != 1 || page.Items[0].Seq != 2 {
		t.Fatalf("05b after_seq catch-up returned %+v", page.Items)
	}
}

func TestProduction05bDevicePushUpdatePreservesE2EEIdentity(t *testing.T) {
	t.Parallel()
	server, persistence := newTestHTTPServerWithMediaStore(t, &testMediaService{}, DefaultMediaPolicy())
	user := registerTestUser(t, server.URL, "production-05b-device@example.com")
	pushToken := strings.Repeat("a1", 32)
	var updated domain.Device
	user.client.do(t, http.MethodPut, "/v1/devices/"+user.device.ID.String(), map[string]any{
		"name": "Akhil's iPhone", "platform": "ios", "push_token": pushToken,
	}, http.StatusOK, &updated)
	stored, err := persistence.Device(context.Background(), user.user.ID, user.device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PushToken != pushToken || updated.IdentityKey == "" || len(updated.SignedPreKey) == 0 {
		t.Fatalf("05b device update lost push or E2EE state: %+v", updated)
	}
}
