package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMinIOSignedPUTContract(t *testing.T) {
	service := testMinIOService(t)
	client := &http.Client{Timeout: 10 * time.Second}
	payload := []byte("abc")
	digest := sha256.Sum256(payload)
	digestHex := hex.EncodeToString(digest[:])

	validKey := "contract/" + uuid.NewString()
	putSignedObject(t, client, service, validKey, payload, "image/jpeg", digestHex, nil)
	if err := service.Verify(context.Background(), validKey, int64(len(payload)), digestHex, "image/jpeg"); err != nil {
		t.Fatalf("verify correctly signed upload: %v", err)
	}
	t.Cleanup(func() { _ = service.Delete(context.Background(), validKey) })

	tests := []struct {
		name   string
		status int
		mutate func(*http.Request)
	}{
		{
			name: "content length", status: http.StatusForbidden,
			mutate: func(request *http.Request) {
				request.Body = io.NopCloser(bytes.NewReader([]byte("abcd")))
				request.ContentLength = 4
				request.Header.Set("Content-Length", "4")
			},
		},
		{
			name: "content type", status: http.StatusForbidden,
			mutate: func(request *http.Request) {
				request.Header.Set("Content-Type", "image/png")
			},
		},
		{
			name: "checksum header", status: http.StatusForbidden,
			mutate: func(request *http.Request) {
				request.Header.Set("X-Amz-Checksum-Sha256", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
			},
		},
		{
			name: "payload checksum", status: http.StatusBadRequest,
			mutate: func(request *http.Request) {
				request.Body = io.NopCloser(bytes.NewReader([]byte("abd")))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := "contract/" + uuid.NewString()
			t.Cleanup(func() { _ = service.Delete(context.Background(), key) })
			response := putSignedObject(t, client, service, key, payload, "image/jpeg", digestHex, test.mutate)
			if response.StatusCode != test.status {
				t.Fatalf("invalid upload status=%d, want %d", response.StatusCode, test.status)
			}
			if err := service.Verify(context.Background(), key, int64(len(payload)), digestHex, "image/jpeg"); !IsDefinitiveVerificationFailure(err) {
				t.Fatalf("rejected PUT unexpectedly created a valid object: %v", err)
			}
		})
	}
}

func testMinIOService(t *testing.T) *S3 {
	t.Helper()
	endpoint := os.Getenv("TEST_MINIO_ENDPOINT")
	accessKey := os.Getenv("TEST_MINIO_ACCESS_KEY")
	secretKey := os.Getenv("TEST_MINIO_SECRET_KEY")
	if endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skip("TEST_MINIO_ENDPOINT, TEST_MINIO_ACCESS_KEY, and TEST_MINIO_SECRET_KEY are not configured")
	}
	useTLS, err := strconv.ParseBool(envOr("TEST_MINIO_USE_TLS", "false"))
	if err != nil {
		t.Fatalf("TEST_MINIO_USE_TLS: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	service, err := NewS3(
		ctx, endpoint, endpoint, accessKey, secretKey,
		envOr("TEST_MINIO_BUCKET", "clustr-media-integration"), useTLS, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return service
}

func putSignedObject(
	t *testing.T,
	client *http.Client,
	service *S3,
	key string,
	payload []byte,
	contentType string,
	digestHex string,
	mutate func(*http.Request),
) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	upload, err := service.PrepareUpload(
		ctx, key, contentType, int64(len(payload)), digestHex, 5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, upload.Method, upload.URL.String(), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range upload.Headers {
		request.Header.Set(name, value)
	}
	request.ContentLength = int64(len(payload))
	if mutate != nil {
		mutate(request)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if mutate == nil && (response.StatusCode < 200 || response.StatusCode >= 300) {
		t.Fatalf("signed PUT status=%d", response.StatusCode)
	}
	return response
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
