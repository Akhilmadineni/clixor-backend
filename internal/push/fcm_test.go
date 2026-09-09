package push

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestFCMSendsOpaqueTokenAndAndroidPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test-oauth-token" {
			t.Error("missing authenticated POST")
		}
		var body struct {
			Message struct {
				Token        string
				Notification Alert
				Data         map[string]string
				Android      struct {
					Priority, TTL string
					Package       string `json:"restricted_package_name"`
					Notification  map[string]string
				}
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		m := body.Message
		if m.Token != "CaseSensitive:Token_A-b" || m.Android.Package != "com.example.clixor" || m.Android.Priority != "HIGH" || m.Android.TTL != "86400s" || m.Android.Notification["tag"] != "event-id" || m.Data["type"] != "sync" {
			t.Errorf("incorrect Android payload: %+v", m)
		}
		_, _ = io.WriteString(w, `{"name":"projects/test-project/messages/123"}`)
	}))
	defer server.Close()
	f := &FCM{client: server.Client(), tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-oauth-token"}), endpoint: server.URL, packageName: "com.example.clixor"}
	if err := f.Send(context.Background(), "CaseSensitive:Token_A-b", "Clixor", "New activity", map[string]string{"type": "sync"}, "event-id"); err != nil {
		t.Fatal(err)
	}
}

func TestFCMErrorsDoNotConfuseConfigurationWithInvalidTokens(t *testing.T) {
	for _, tc := range []struct {
		status         int
		code           string
		invalid, retry bool
	}{
		{404, "UNREGISTERED", true, false}, {404, "UNKNOWN", false, false}, {403, "SENDER_ID_MISMATCH", false, false},
		{400, "INVALID_ARGUMENT", false, false}, {401, "THIRD_PARTY_AUTH_ERROR", false, false},
		{429, "QUOTA_EXCEEDED", false, true}, {503, "UNAVAILABLE", false, true},
	} {
		t.Run(tc.code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprintf(w, `{"error":{"message":"sensitive-token-never-log","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":%q}]}}`, tc.code)
			}))
			defer server.Close()
			f := &FCM{client: server.Client(), tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"}), endpoint: server.URL, packageName: "com.example.clixor"}
			err := f.Send(context.Background(), "token", "title", "body", nil, "id")
			if err == nil || IsInvalidToken(err) != tc.invalid || IsRetryable(err) != tc.retry {
				t.Fatalf("incorrect rejection class: %v", err)
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("provider text leaked")
			}
			if tc.retry && MinimumRetryDelay(err) != 2*time.Minute {
				t.Fatal("retry-after ignored")
			}
		})
	}
}

func TestFCMRequiresValidAcknowledgement(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{}`) }))
	defer s.Close()
	f := &FCM{client: s.Client(), tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"}), endpoint: s.URL}
	if f.Send(context.Background(), "token", "title", "body", nil, "id") == nil {
		t.Fatal("empty acknowledgement accepted")
	}
}

func TestFCMRejectsUntrustedCredentialConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-account.json")
	for _, raw := range []string{
		`{"type":"external_account","project_id":"test-project","token_uri":"https://oauth2.googleapis.com/token"}`,
		`{"type":"service_account","project_id":"wrong-project","token_uri":"https://oauth2.googleapis.com/token"}`,
		`{"type":"service_account","project_id":"test-project","token_uri":"https://attacker.example/token"}`,
		`{"type":"service_account","project_id":"test-project","token_uri":"https://oauth2.googleapis.com/token","client_email":"test@example.com","private_key":"not-a-private-key"}`,
	} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if f, err := NewFCM(context.Background(), "test-project", path, "com.example.clixor"); err == nil {
			f.Close()
			t.Fatal("untrusted credentials accepted")
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFCM(context.Background(), "test-project", path, "com.example.clixor"); err == nil {
		t.Fatal("public credentials file accepted")
	}
}

func TestPlatformSelectionNeverFallsBackToOtherProvider(t *testing.T) {
	fcm := &FCM{}
	p := &Platforms{IOS: Disabled{}, Android: fcm}
	if IsDisabled(p) || !IsDisabled(ForPlatform(p, "ios")) || ForPlatform(p, "android") != fcm || !IsDisabled(ForPlatform(fcm, "android")) {
		t.Fatal("platform isolation failed")
	}
	if got := EnabledPlatforms(p); len(got) != 1 || got[0] != "android" {
		t.Fatalf("enabled=%v", got)
	}
	if err := (&Platforms{Android: fcm}).Send(context.Background(), "token", "title", "body", nil, "id"); err == nil {
		t.Fatal("missing iOS provider acknowledged a legacy send")
	}
}
