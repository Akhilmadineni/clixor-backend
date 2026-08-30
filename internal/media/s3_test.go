package media

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const testSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func TestRequiredUploadHeadersBindDeclaration(t *testing.T) {
	headers, err := RequiredUploadHeaders("image/jpeg", 3, testSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if headers.Get("Content-Type") != "image/jpeg" || headers.Get("Content-Length") != "3" {
		t.Fatalf("declaration headers = %+v", headers)
	}
	digest, err := base64.StdEncoding.DecodeString(headers.Get("X-Amz-Checksum-Sha256"))
	if err != nil || len(digest) != 32 {
		t.Fatalf("checksum header is invalid: value=%q err=%v", headers.Get("X-Amz-Checksum-Sha256"), err)
	}
	if _, err := RequiredUploadHeaders("image/jpeg", 0, testSHA256); err == nil {
		t.Fatal("zero-length upload declaration was accepted")
	}
}

func TestVerificationStorageErrorClassification(t *testing.T) {
	missing := verificationStorageError("stat", minio.ErrorResponse{Code: "NoSuchKey"})
	if !errors.Is(missing, ErrUploadMissing) || !IsDefinitiveVerificationFailure(missing) {
		t.Fatalf("missing object classification = %v", missing)
	}
	unavailable := verificationStorageError("stat", minio.ErrorResponse{Code: "InternalError"})
	if !errors.Is(unavailable, ErrUnavailable) || IsDefinitiveVerificationFailure(unavailable) {
		t.Fatalf("storage 5xx classification = %v", unavailable)
	}
}

func TestPrepareUploadSignsLengthTypeAndChecksum(t *testing.T) {
	client, err := minio.New("media.example", &minio.Options{
		Creds: credentials.NewStaticV4("access", "secret", ""), Secure: true,
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &S3{publicClient: client, bucket: "private-media"}
	upload, err := service.PrepareUpload(
		context.Background(), "conversations/id/object", "image/jpeg", 3,
		testSHA256, 5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if upload.Method != "PUT" || upload.URL == nil || upload.Headers["Content-Type"] != "image/jpeg" ||
		upload.Headers["Content-Length"] != "3" || upload.Headers["X-Amz-Checksum-Sha256"] == "" {
		t.Fatalf("incomplete upload instructions: %+v", upload)
	}
	signed := strings.Split(upload.URL.Query().Get("X-Amz-SignedHeaders"), ";")
	for _, required := range []string{"content-length", "content-type", "host", "x-amz-checksum-sha256"} {
		found := false
		for _, value := range signed {
			found = found || value == required
		}
		if !found {
			t.Fatalf("signed headers %v do not contain %q", signed, required)
		}
	}
}

func TestS3TransportBoundsConnectionAndResponseWaits(t *testing.T) {
	transport := boundedS3Transport(&tls.Config{MinVersion: tls.VersionTLS12})
	if transport.DialContext == nil || transport.TLSClientConfig == nil ||
		transport.TLSHandshakeTimeout != 5*time.Second ||
		transport.ResponseHeaderTimeout != 10*time.Second ||
		transport.ExpectContinueTimeout != time.Second ||
		transport.IdleConnTimeout != 90*time.Second {
		t.Fatalf("S3 transport is not fully bounded: %+v", transport)
	}
}
