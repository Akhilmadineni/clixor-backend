package media

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useTLS,
		Region: region,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig,
			ForceAttemptHTTP2: true, MaxIdleConns: 100, MaxIdleConnsPerHost: 100,
		},
	})
	if err != nil {
		return nil, err
	}
	if publicEndpoint == "" {
		publicEndpoint = endpoint
	}
	publicClient, err := minio.New(publicEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useTLS,
		Region: region,
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

func (s *S3) UploadURL(ctx context.Context, objectKey, contentType string, byteSize int64, expiry time.Duration) (*url.URL, error) {
	_ = contentType
	_ = byteSize
	return s.publicClient.PresignedPutObject(ctx, s.bucket, objectKey, expiry)
}

func (s *S3) DownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (*url.URL, error) {
	return s.publicClient.PresignedGetObject(ctx, s.bucket, objectKey, expiry, nil)
}

func (s *S3) Verify(ctx context.Context, objectKey string, expectedSize int64) error {
	info, err := s.client.StatObject(ctx, s.bucket, objectKey, minio.StatObjectOptions{})
	if err != nil {
		return err
	}
	if info.Size != expectedSize {
		return fmt.Errorf("media size mismatch: expected %d, received %d", expectedSize, info.Size)
	}
	return nil
}

func (s *S3) Delete(ctx context.Context, objectKey string) error {
	return s.client.RemoveObject(ctx, s.bucket, objectKey, minio.RemoveObjectOptions{})
}

func (*S3) Close() {}
