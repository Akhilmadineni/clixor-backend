package media

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/tlsconfig"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3 struct {
	client       *minio.Client
	publicClient *minio.Client
	bucket       string
}

func NewS3(ctx context.Context, endpoint, publicEndpoint, accessKey, secretKey, bucket string, useTLS bool, caFile string) (*S3, error) {
	return NewS3WithRegion(
		ctx, endpoint, publicEndpoint, "us-east-1", accessKey, secretKey, bucket, useTLS, caFile,
	)
}

func NewS3WithRegion(
	ctx context.Context,
	endpoint string,
	publicEndpoint string,
	region string,
	accessKey string,
	secretKey string,
	bucket string,
	useTLS bool,
	caFile string,
) (*S3, error) {
	tlsConfig, err := tlsconfig.Client(caFile)
	if err != nil {
		return nil, err
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:     credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:    useTLS,
		Region:    region,
		Transport: boundedS3Transport(tlsConfig),
	})
	if err != nil {
		return nil, err
	}
	if publicEndpoint == "" {
		publicEndpoint = endpoint
	}
	publicClient, err := minio.New(publicEndpoint, &minio.Options{
		Creds:     credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:    useTLS,
		Region:    region,
		Transport: boundedS3Transport(tlsConfig),
	})
	if err != nil {
		return nil, err
	}
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return nil, fmt.Errorf("check media bucket: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("create media bucket: %w", err)
		}
	}
	return &S3{client: client, publicClient: publicClient, bucket: bucket}, nil
}

func boundedS3Transport(tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsConfig.Clone(),
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
	}
}

func (s *S3) PrepareUpload(
	ctx context.Context,
	objectKey, contentType string,
	byteSize int64,
	expectedSHA256 string,
	expiry time.Duration,
) (UploadInstructions, error) {
	headers, err := RequiredUploadHeaders(contentType, byteSize, expectedSHA256)
	if err != nil {
		return UploadInstructions{}, err
	}
	uploadURL, err := s.publicClient.PresignHeader(
		ctx, http.MethodPut, s.bucket, objectKey, expiry, nil, headers,
	)
	if err != nil {
		return UploadInstructions{}, err
	}
	required := make(map[string]string, len(headers))
	for name, values := range headers {
		if len(values) != 1 {
			return UploadInstructions{}, fmt.Errorf("invalid S3 upload header %q", name)
		}
		required[name] = values[0]
	}
	return instructions(uploadURL, required), nil
}

func (s *S3) DownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (*url.URL, error) {
	return s.publicClient.PresignedGetObject(ctx, s.bucket, objectKey, expiry, nil)
}

func (s *S3) Verify(
	ctx context.Context,
	objectKey string,
	expectedSize int64,
	expectedSHA256, expectedContentType string,
) error {
	info, err := s.client.StatObject(ctx, s.bucket, objectKey, minio.StatObjectOptions{})
	if err != nil {
		return verificationStorageError("stat media object", err)
	}
	if info.Size != expectedSize {
		return fmt.Errorf("%w: size expected %d, received %d", ErrVerificationMismatch, expectedSize, info.Size)
	}
	actualContentType, _, err := mime.ParseMediaType(info.ContentType)
	if err != nil || !strings.EqualFold(actualContentType, expectedContentType) {
		return fmt.Errorf("%w: content type", ErrVerificationMismatch)
	}
	object, err := s.client.GetObject(ctx, s.bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return verificationStorageError("open media object for verification", err)
	}
	defer object.Close()
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(object, expectedSize+1))
	if err != nil {
		return verificationStorageError("hash media object", err)
	}
	if read != expectedSize {
		return fmt.Errorf("%w: size changed during verification: expected %d, received %d",
			ErrVerificationMismatch, expectedSize, read)
	}
	actualSHA256 := hex.EncodeToString(hash.Sum(nil))
	if actualSHA256 != expectedSHA256 {
		return fmt.Errorf("%w: sha256", ErrVerificationMismatch)
	}
	return nil
}

func verificationStorageError(operation string, err error) error {
	response := minio.ToErrorResponse(err)
	switch response.Code {
	case "NoSuchKey", "NoSuchObject", "NotFound", "XMinioInvalidObjectName":
		return fmt.Errorf("%w: %s", ErrUploadMissing, operation)
	default:
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, operation, err)
	}
}

// RequiredUploadHeaders returns every header covered by the SigV4 presigned
// PUT signature. MinIO rejects a request if any signed value differs. The
// checksum header also makes MinIO validate the uploaded payload while the
// completion endpoint independently streams and hashes it before publication.
func RequiredUploadHeaders(contentType string, byteSize int64, expectedSHA256 string) (http.Header, error) {
	digest, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(digest) != sha256.Size || strings.TrimSpace(contentType) == "" || byteSize < 1 {
		return nil, fmt.Errorf("invalid media upload declaration")
	}
	return http.Header{
		"Content-Type":          []string{contentType},
		"Content-Length":        []string{strconv.FormatInt(byteSize, 10)},
		"X-Amz-Checksum-Sha256": []string{base64.StdEncoding.EncodeToString(digest)},
	}, nil
}

func (s *S3) Delete(ctx context.Context, objectKey string) error {
	return s.client.RemoveObject(ctx, s.bucket, objectKey, minio.RemoveObjectOptions{})
}

func (*S3) Close() {}
