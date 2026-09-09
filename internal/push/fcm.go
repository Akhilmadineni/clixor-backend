package push

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const fcmScope = "https://www.googleapis.com/auth/firebase.messaging"

type FCM struct {
	client                *http.Client
	tokens                oauth2.TokenSource
	endpoint, packageName string
}

func NewFCM(ctx context.Context, projectID, credentialsFile, packageName string) (*FCM, error) {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`).MatchString(projectID) || packageName == "" {
		return nil, errors.New("invalid FCM project or Android package configuration")
	}
	file, err := os.Open(credentialsFile)
	if err != nil {
		return nil, errors.New("FCM credentials file is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 || info.Mode().Perm()&0o007 != 0 {
		return nil, errors.New("FCM credentials must be a bounded, non-public regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errors.New("cannot read FCM credentials")
	}
	var identity struct {
		Type      string `json:"type"`
		ProjectID string `json:"project_id"`
		TokenURI  string `json:"token_uri"`
	}
	if json.Unmarshal(raw, &identity) != nil || identity.Type != "service_account" || identity.ProjectID != projectID || identity.TokenURI != "https://oauth2.googleapis.com/token" {
		return nil, errors.New("FCM credentials do not match the configured project or trusted OAuth endpoint")
	}
	config, err := google.JWTConfigFromJSON(raw, fcmScope)
	if err != nil || config.Email == "" || len(config.PrivateKey) == 0 {
		return nil, errors.New("invalid FCM service account credentials")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(config.PrivateKey)
	if err != nil || key.N.BitLen() < 2048 {
		return nil, errors.New("FCM requires a valid RSA service account key of at least 2048 bits")
	}
	// Both token minting and sends have bounded I/O and refuse redirects. Do not
	// use a request-scoped context for the reusable, synchronized token source.
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true, MaxIdleConns: 100, MaxIdleConnsPerHost: 20, IdleConnTimeout: 90 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authContext := context.WithValue(ctx, oauth2.HTTPClient, client)
	return &FCM{client: client, tokens: config.TokenSource(authContext), endpoint: "https://fcm.googleapis.com/v1/projects/" + projectID + "/messages:send", packageName: packageName}, nil
}

func (f *FCM) Send(ctx context.Context, deviceToken, title, body string, data map[string]string, notificationID string) error {
	payload, err := json.Marshal(map[string]any{"message": map[string]any{
		"token": deviceToken, "notification": map[string]string{"title": title, "body": body}, "data": data,
		"android": map[string]any{"priority": "HIGH", "ttl": "86400s", "restricted_package_name": f.packageName,
			"notification": map[string]string{"tag": notificationID}},
	}})
	if err != nil || len(payload) > 4096 {
		return &FCMError{StatusCode: 400, Code: "INVALID_ARGUMENT"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := f.tokens.Token()
	if err != nil {
		return errors.New("FCM OAuth token unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(payload))
	if err != nil {
		return errors.New("invalid FCM request")
	}
	token.SetAuthHeader(request)
	request.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return err
	}
	if response.StatusCode == http.StatusOK {
		var accepted struct {
			Name string `json:"name"`
		}
		if len(raw) > 65536 || json.Unmarshal(raw, &accepted) != nil || accepted.Name == "" {
			return errors.New("invalid FCM acknowledgement")
		}
		return nil
	}
	var rejected struct {
		Error struct {
			Details []struct {
				Type string `json:"@type"`
				Code string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	code := "UNKNOWN"
	if len(raw) <= 65536 && json.Unmarshal(raw, &rejected) == nil {
		for _, detail := range rejected.Error.Details {
			if detail.Type != "type.googleapis.com/google.firebase.fcm.v1.FcmError" {
				continue
			}
			switch detail.Code {
			case "UNREGISTERED", "SENDER_ID_MISMATCH", "INVALID_ARGUMENT", "QUOTA_EXCEEDED", "UNAVAILABLE", "INTERNAL", "THIRD_PARTY_AUTH_ERROR":
				code = detail.Code
			}
		}
	}
	delay := time.Duration(0)
	if seconds, e := strconv.Atoi(response.Header.Get("Retry-After")); e == nil && seconds > 0 && seconds <= 86400 {
		delay = time.Duration(seconds) * time.Second
	} else if until, e := http.ParseTime(response.Header.Get("Retry-After")); e == nil {
		delay = time.Until(until)
	}
	if response.StatusCode == 429 && delay < time.Minute {
		delay = time.Minute
	}
	if delay > 24*time.Hour {
		delay = 24 * time.Hour
	}
	if delay < 0 {
		delay = 0
	}
	return &FCMError{StatusCode: response.StatusCode, Code: code, RetryAfter: delay}
}

func (f *FCM) Close() { f.client.CloseIdleConnections() }

// Only an explicit FCM UNREGISTERED rejection invalidates a token. A 404 may
// refer to a project/configuration problem, and INVALID_ARGUMENT may be payload
// validation: neither is evidence that this installation should lose its token.
type FCMError struct {
	StatusCode int
	Code       string
	RetryAfter time.Duration
}

func (e *FCMError) Error() string { return "FCM delivery rejected: " + strings.ToUpper(e.Code) }
