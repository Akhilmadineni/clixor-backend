package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

const expectedUniversalLinkAppID = "H9S3BAQ9U8.com.Clustr.Clustr.Clustr"

type associationDocument struct {
	AppLinks struct {
		Apps    []string `json:"apps"`
		Details []struct {
			AppIDs     []string `json:"appIDs"`
			Components []struct {
				Path    string `json:"/"`
				Comment string `json:"comment"`
			} `json:"components"`
		} `json:"details"`
	} `json:"applinks"`
}

func TestAppleAppSiteAssociationIsPublicAndExact(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)

	for _, path := range []string{
		"/.well-known/apple-app-site-association",
		"/apple-app-site-association",
	} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d", path, response.StatusCode)
		}
		if contentType := response.Header.Get("Content-Type"); contentType != "application/json" {
			t.Fatalf("%s content type = %q", path, contentType)
		}
		if cache := response.Header.Get("Cache-Control"); cache != universalLinksCacheControl {
			t.Fatalf("%s cache control = %q", path, cache)
		}
		if revision := response.Header.Get("X-Clixor-Revision"); revision != "development" {
			t.Fatalf("%s revision = %q", path, revision)
		}
		assertUniversalLinkSecurityHeaders(t, response)

		var document associationDocument
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatalf("%s returned invalid JSON: %v", path, err)
		}
		if document.AppLinks.Apps == nil || len(document.AppLinks.Apps) != 0 {
			t.Fatalf("%s apps = %#v", path, document.AppLinks.Apps)
		}
		if len(document.AppLinks.Details) != 1 {
			t.Fatalf("%s details = %#v", path, document.AppLinks.Details)
		}
		detail := document.AppLinks.Details[0]
		if len(detail.AppIDs) != 1 || detail.AppIDs[0] != expectedUniversalLinkAppID {
			t.Fatalf("%s app IDs = %#v", path, detail.AppIDs)
		}
		if len(detail.Components) != 1 || detail.Components[0].Path != "/join" {
			t.Fatalf("%s components = %#v", path, detail.Components)
		}
	}
}

func TestJoinLandingIsGenericAndPrivacySafe(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	const secret = "cinv_not-a-real-invite-secret"

	response, err := http.Get(server.URL + "/join?invite=" + secret)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "text/html; charset=utf-8" {
		t.Fatalf("content type = %q", contentType)
	}
	if cache := response.Header.Get("Cache-Control"); cache != "public, max-age=300" {
		t.Fatalf("cache control = %q", cache)
	}
	assertUniversalLinkSecurityHeaders(t, response)
	if response.Header.Get("X-Robots-Tag") != "noindex, nofollow, noarchive" {
		t.Fatal("landing page can be indexed")
	}
	if permissions := response.Header.Get("Permissions-Policy"); permissions != "camera=(), geolocation=(), microphone=()" {
		t.Fatalf("permissions policy = %q", permissions)
	}
	if csp := response.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
		t.Fatalf("unexpected content security policy: %q", csp)
	}
	if bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte("cinv_")) {
		t.Fatal("landing page reflected an invite secret")
	}
	if bytes.Contains(bytes.ToLower(body), []byte("<script")) {
		t.Fatal("landing page unexpectedly contains executable script")
	}
	if !bytes.Contains(body, []byte("Open this invite in the app")) {
		t.Fatal("landing page omitted generic invite guidance")
	}
}

func assertUniversalLinkSecurityHeaders(t *testing.T, response *http.Response) {
	t.Helper()
	want := map[string]string{
		"Cross-Origin-Resource-Policy": "same-origin",
		"Referrer-Policy":              "no-referrer",
		"Strict-Transport-Security":    "max-age=31536000",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
	}
	for name, expected := range want {
		if actual := response.Header.Get(name); actual != expected {
			t.Errorf("%s = %q, want %q", name, actual, expected)
		}
	}
}

func TestUniversalLinkRoutesDoNotMatchBroaderPaths(t *testing.T) {
	t.Parallel()
	server := newTestHTTPServer(t)
	for _, path := range []string{
		"/join/",
		"/join/anything",
		"/.well-known/apple-app-site-association/extra",
		"/apple-app-site-association.json",
	} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, response.StatusCode)
		}
	}
}
