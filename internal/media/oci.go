package media

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"mime"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Akhilmadineni/clixor-backend/internal/mediakey"
	"github.com/google/uuid"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const (
	ociPARNamePrefix       = "clixor-"
	ociMaxPARExpiry        = 24 * time.Hour
	ociPARCleanupPageLimit = 100
	ociPARCleanupMaxPages  = 10
)

var ociRegionPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)+$`)

type ociObjectStorageClient interface {
	HeadBucket(context.Context, objectstorage.HeadBucketRequest) (objectstorage.HeadBucketResponse, error)
	CreatePreauthenticatedRequest(context.Context, objectstorage.CreatePreauthenticatedRequestRequest) (objectstorage.CreatePreauthenticatedRequestResponse, error)
	ListPreauthenticatedRequests(context.Context, objectstorage.ListPreauthenticatedRequestsRequest) (objectstorage.ListPreauthenticatedRequestsResponse, error)
	DeletePreauthenticatedRequest(context.Context, objectstorage.DeletePreauthenticatedRequestRequest) (objectstorage.DeletePreauthenticatedRequestResponse, error)
	HeadObject(context.Context, objectstorage.HeadObjectRequest) (objectstorage.HeadObjectResponse, error)
	RenameObject(context.Context, objectstorage.RenameObjectRequest) (objectstorage.RenameObjectResponse, error)
	DeleteObject(context.Context, objectstorage.DeleteObjectRequest) (objectstorage.DeleteObjectResponse, error)
}

// OCIObjectStorage stores encrypted media in a private OCI Object Storage
// bucket. It grants clients temporary, object-specific access with
// pre-authenticated requests; the application itself authenticates through the
// compute instance principal and therefore needs no long-lived storage key.
type OCIObjectStorage struct {
	client    ociObjectStorageClient
	endpoint  *url.URL
	namespace string
	bucket    string
	logger    *slog.Logger

	cleanupContext context.Context
	cleanupCancel  context.CancelFunc
	cleanupWG      sync.WaitGroup
	closeOnce      sync.Once
}

func NewOCIObjectStorage(
	ctx context.Context,
	region string,
	namespace string,
	bucket string,
	logger *slog.Logger,
) (*OCIObjectStorage, error) {
	region = strings.TrimSpace(region)
	if !ociRegionPattern.MatchString(region) {
		return nil, errors.New("OCI Object Storage region is invalid")
	}
	provider, err := auth.InstancePrincipalConfigurationProviderForRegion(common.StringToRegion(region))
	if err != nil {
		return nil, fmt.Errorf("create OCI instance-principal provider: %w", err)
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI Object Storage client: %w", err)
	}
	endpoint := "https://" + common.StringToRegion(region).Endpoint("objectstorage")
	store, err := newOCIObjectStorage(&client, endpoint, namespace, bucket, logger)
	if err != nil {
		return nil, err
	}
	checkContext, checkCancel := context.WithTimeout(ctx, 20*time.Second)
	defer checkCancel()
	if _, err := client.HeadBucket(checkContext, objectstorage.HeadBucketRequest{
		NamespaceName: common.String(store.namespace),
		BucketName:    common.String(store.bucket),
	}); err != nil {
		store.Close()
		return nil, fmt.Errorf("access OCI media bucket: %w", err)
	}
	store.startPARCleanup()
	return store, nil
}

func newOCIObjectStorage(
	client ociObjectStorageClient,
	endpoint string,
	namespace string,
	bucket string,
	logger *slog.Logger,
) (*OCIObjectStorage, error) {
	if client == nil {
		return nil, errors.New("OCI Object Storage client is required")
	}
	namespace = strings.TrimSpace(namespace)
	bucket = strings.TrimSpace(bucket)
	if namespace == "" || bucket == "" {
		return nil, errors.New("OCI Object Storage namespace and bucket are required")
	}
	baseURL, err := url.Parse(endpoint)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil ||
		baseURL.RawQuery != "" || baseURL.Fragment != "" || (baseURL.Path != "" && baseURL.Path != "/") {
		return nil, errors.New("OCI Object Storage endpoint must be an HTTPS origin")
	}
	if logger == nil {
		logger = slog.Default()
	}
	cleanupContext, cleanupCancel := context.WithCancel(context.Background())
	return &OCIObjectStorage{
		client: client, endpoint: baseURL, namespace: namespace, bucket: bucket, logger: logger,
		cleanupContext: cleanupContext, cleanupCancel: cleanupCancel,
	}, nil
}

func (s *OCIObjectStorage) PrepareUpload(
	ctx context.Context,
	objectKey string,
	contentType string,
	byteSize int64,
	expectedSHA256 string,
	expiry time.Duration,
) (UploadInstructions, error) {
	digest, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(digest) != sha256.Size || strings.TrimSpace(contentType) == "" || byteSize < 1 {
		return UploadInstructions{}, errors.New("invalid OCI media upload declaration")
	}
	if parsed, _, err := mime.ParseMediaType(contentType); err != nil || !strings.EqualFold(parsed, contentType) {
		return UploadInstructions{}, errors.New("invalid OCI media upload content type")
	}
	uploadURL, revocationToken, err := s.createPAR(
		ctx, objectKey, expiry, objectstorage.CreatePreauthenticatedRequestDetailsAccessTypeObjectwrite,
	)
	if err != nil {
		return UploadInstructions{}, err
	}
	result := instructions(uploadURL, map[string]string{
		"Content-Type":           contentType,
		"Content-Length":         strconv.FormatInt(byteSize, 10),
		"opc-checksum-algorithm": "SHA256",
		"opc-content-sha256":     base64.StdEncoding.EncodeToString(digest),
	})
	result.RevocationToken = revocationToken
	return result, nil
}

func (s *OCIObjectStorage) DownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (*url.URL, error) {
	downloadURL, _, err := s.createPAR(
		ctx, objectKey, expiry, objectstorage.CreatePreauthenticatedRequestDetailsAccessTypeObjectread,
	)
	return downloadURL, err
}

func (s *OCIObjectStorage) createPAR(
	ctx context.Context,
	objectKey string,
	expiry time.Duration,
	accessType objectstorage.CreatePreauthenticatedRequestDetailsAccessTypeEnum,
) (*url.URL, string, error) {
	if err := validateOCIObjectKey(objectKey); err != nil {
		return nil, "", err
	}
	if expiry <= 0 || expiry > ociMaxPARExpiry {
		return nil, "", fmt.Errorf("OCI media URL expiry must be between 1ns and %s", ociMaxPARExpiry)
	}
	expiresAt := common.SDKTime{Time: time.Now().UTC().Add(expiry)}
	response, err := s.client.CreatePreauthenticatedRequest(ctx, objectstorage.CreatePreauthenticatedRequestRequest{
		NamespaceName: common.String(s.namespace),
		BucketName:    common.String(s.bucket),
		CreatePreauthenticatedRequestDetails: objectstorage.CreatePreauthenticatedRequestDetails{
			Name:        common.String(ociPARNamePrefix + uuid.NewString()),
			AccessType:  accessType,
			TimeExpires: &expiresAt,
			ObjectName:  common.String(objectKey),
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("create OCI media pre-authenticated request: %w", err)
	}
	if response.AccessUri == nil {
		return nil, "", errors.New("OCI media pre-authenticated request omitted its access URI")
	}
	if response.Id == nil || strings.TrimSpace(*response.Id) == "" {
		return nil, "", errors.New("OCI media pre-authenticated request omitted its identifier")
	}
	accessURI, err := url.Parse(*response.AccessUri)
	if err != nil || accessURI.IsAbs() || accessURI.Host != "" || accessURI.User != nil ||
		accessURI.RawQuery != "" || accessURI.Fragment != "" || !strings.HasPrefix(accessURI.EscapedPath(), "/p/") {
		return nil, "", errors.New("OCI media pre-authenticated request returned an invalid access URI")
	}
	return s.endpoint.ResolveReference(accessURI), strings.TrimSpace(*response.Id), nil
}

func (s *OCIObjectStorage) Verify(
	ctx context.Context,
	objectKey string,
	expectedSize int64,
	expectedSHA256, expectedContentType string,
) error {
	_, err := s.headVerified(ctx, objectKey, expectedSize, expectedSHA256, expectedContentType)
	return err
}

// FinalizeUpload moves a verified upload out of the PAR-writable staging name
// into a deterministic backend-only name. Revocation closes new writes; the
// source ETag fence and destination create-only condition make already
// authorized in-flight PUTs harmless as well.
func (s *OCIObjectStorage) FinalizeUpload(
	ctx context.Context,
	objectKey string,
	revocationToken string,
	expectedSize int64,
	expectedSHA256, expectedContentType string,
) (string, error) {
	publishedKey, err := mediakey.Published(objectKey)
	if err != nil {
		return "", err
	}
	if publishedKey == objectKey {
		return "", errors.New("OCI media upload is already published")
	}
	if err := s.revokeObjectWritePARs(ctx, objectKey, revocationToken); err != nil {
		return "", err
	}

	// Completion is retry-safe after a rename succeeded but the database write
	// or response failed. Never touch the destination again once it validates.
	if _, err := s.headVerified(ctx, publishedKey, expectedSize, expectedSHA256, expectedContentType); err == nil {
		return publishedKey, nil
	} else if !errors.Is(err, ErrUploadMissing) {
		return "", err
	}

	staged, err := s.headVerified(ctx, objectKey, expectedSize, expectedSHA256, expectedContentType)
	if err != nil {
		return "", err
	}
	if staged.ETag == nil || strings.TrimSpace(*staged.ETag) == "" {
		return "", fmt.Errorf("%w: OCI object omitted ETag", ErrVerificationMismatch)
	}
	_, renameErr := s.client.RenameObject(ctx, objectstorage.RenameObjectRequest{
		NamespaceName: common.String(s.namespace),
		BucketName:    common.String(s.bucket),
		RenameObjectDetails: objectstorage.RenameObjectDetails{
			SourceName:            common.String(objectKey),
			NewName:               common.String(publishedKey),
			SrcObjIfMatchETag:     common.String(strings.TrimSpace(*staged.ETag)),
			NewObjIfNoneMatchETag: common.String("*"),
		},
	})
	// A timeout can hide a successful rename, and a competing idempotent
	// completion can legitimately win the destination. Inspect the immutable
	// destination before classifying any rename response.
	if _, err := s.headVerified(ctx, publishedKey, expectedSize, expectedSHA256, expectedContentType); err == nil {
		return publishedKey, nil
	} else if !errors.Is(err, ErrUploadMissing) {
		return "", err
	}
	if renameErr != nil {
		return "", fmt.Errorf("%w: publish OCI media object: %v", ErrUnavailable, renameErr)
	}
	return "", fmt.Errorf("%w: published OCI media object is not yet visible", ErrUnavailable)
}

func (s *OCIObjectStorage) headVerified(
	ctx context.Context,
	objectKey string,
	expectedSize int64,
	expectedSHA256, expectedContentType string,
) (objectstorage.HeadObjectResponse, error) {
	if err := validateOCIObjectKey(objectKey); err != nil {
		return objectstorage.HeadObjectResponse{}, err
	}
	if expectedSize < 1 {
		return objectstorage.HeadObjectResponse{}, errors.New("expected OCI media size must be positive")
	}
	expectedDigest, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(expectedDigest) != sha256.Size {
		return objectstorage.HeadObjectResponse{}, errors.New("expected OCI media SHA-256 must be 64 hexadecimal characters")
	}
	expectedType, _, err := mime.ParseMediaType(expectedContentType)
	if err != nil || strings.TrimSpace(expectedType) == "" {
		return objectstorage.HeadObjectResponse{}, errors.New("expected OCI media content type is invalid")
	}
	response, err := s.client.HeadObject(ctx, objectstorage.HeadObjectRequest{
		NamespaceName: common.String(s.namespace),
		BucketName:    common.String(s.bucket),
		ObjectName:    common.String(objectKey),
	})
	if err != nil {
		if ociStatus(err, 404) {
			return objectstorage.HeadObjectResponse{}, fmt.Errorf("%w: inspect OCI media object", ErrUploadMissing)
		}
		return objectstorage.HeadObjectResponse{}, fmt.Errorf("%w: inspect OCI media object: %v", ErrUnavailable, err)
	}
	if response.ContentLength == nil {
		return objectstorage.HeadObjectResponse{}, fmt.Errorf("%w: OCI object omitted content length", ErrVerificationMismatch)
	}
	if *response.ContentLength != expectedSize {
		return objectstorage.HeadObjectResponse{}, fmt.Errorf("%w: size expected %d, received %d", ErrVerificationMismatch, expectedSize, *response.ContentLength)
	}
	if response.ContentType == nil {
		return objectstorage.HeadObjectResponse{}, fmt.Errorf("%w: OCI object omitted content type", ErrVerificationMismatch)
	}
	actualType, _, err := mime.ParseMediaType(*response.ContentType)
	if err != nil || !strings.EqualFold(actualType, expectedType) {
		return objectstorage.HeadObjectResponse{}, fmt.Errorf("%w: content type", ErrVerificationMismatch)
	}
	if response.OpcContentSha256 == nil || strings.TrimSpace(*response.OpcContentSha256) == "" {
		return objectstorage.HeadObjectResponse{}, fmt.Errorf("%w: OCI object omitted SHA-256 metadata", ErrVerificationMismatch)
	}
	actualDigest, err := base64.StdEncoding.DecodeString(*response.OpcContentSha256)
	if err != nil || len(actualDigest) != sha256.Size {
		return objectstorage.HeadObjectResponse{}, fmt.Errorf("%w: OCI object returned invalid SHA-256 metadata", ErrVerificationMismatch)
	}
	if subtle.ConstantTimeCompare(actualDigest, expectedDigest) != 1 {
		return objectstorage.HeadObjectResponse{}, fmt.Errorf("%w: SHA-256", ErrVerificationMismatch)
	}
	return response, nil
}

func (s *OCIObjectStorage) revokeObjectWritePARs(ctx context.Context, objectKey, revocationToken string) error {
	revocationToken = strings.TrimSpace(revocationToken)
	if revocationToken != "" {
		if _, err := s.client.DeletePreauthenticatedRequest(ctx, objectstorage.DeletePreauthenticatedRequestRequest{
			NamespaceName: common.String(s.namespace),
			BucketName:    common.String(s.bucket),
			ParId:         common.String(revocationToken),
		}); err != nil && !ociStatus(err, 404) {
			return fmt.Errorf("%w: revoke persisted OCI media write capability: %v", ErrUnavailable, err)
		}
	}
	if err := s.revokeDiscoveredObjectWritePARs(ctx, objectKey); err != nil {
		if revocationToken == "" {
			// Compatibility for an upload created by a pre-migration replica: the
			// exact PAR was not persisted, so discovery is integrity-critical.
			return err
		}
		// The persisted capability is the only URL ever returned by the current
		// API. Prefix enumeration just cleans duplicates and legacy orphans; do
		// not make completion unavailable in buckets with a large PAR history.
		s.logger.Warn("OCI media orphan capability cleanup failed", "error", err)
	}
	return nil
}

func (s *OCIObjectStorage) revokeDiscoveredObjectWritePARs(ctx context.Context, objectKey string) error {
	var page *string
	for pageNumber := 0; pageNumber < ociPARCleanupMaxPages; pageNumber++ {
		response, err := s.client.ListPreauthenticatedRequests(ctx, objectstorage.ListPreauthenticatedRequestsRequest{
			NamespaceName:    common.String(s.namespace),
			BucketName:       common.String(s.bucket),
			ObjectNamePrefix: common.String(objectKey),
			Limit:            common.Int(ociPARCleanupPageLimit),
			Page:             page,
		})
		if err != nil {
			return fmt.Errorf("%w: list OCI media write capabilities: %v", ErrUnavailable, err)
		}
		for _, item := range response.Items {
			if item.ObjectName == nil || *item.ObjectName != objectKey ||
				item.AccessType != objectstorage.PreauthenticatedRequestSummaryAccessTypeObjectwrite {
				continue
			}
			if item.Id == nil || strings.TrimSpace(*item.Id) == "" {
				return fmt.Errorf("%w: OCI media write capability omitted its identifier", ErrUnavailable)
			}
			if _, err := s.client.DeletePreauthenticatedRequest(ctx, objectstorage.DeletePreauthenticatedRequestRequest{
				NamespaceName: common.String(s.namespace),
				BucketName:    common.String(s.bucket),
				ParId:         common.String(*item.Id),
			}); err != nil && !ociStatus(err, 404) {
				return fmt.Errorf("%w: revoke OCI media write capability: %v", ErrUnavailable, err)
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return nil
		}
		page = response.OpcNextPage
	}
	return fmt.Errorf("%w: too many OCI media write capabilities to revoke", ErrUnavailable)
}

func (s *OCIObjectStorage) Delete(ctx context.Context, objectKey string) error {
	if err := validateOCIObjectKey(objectKey); err != nil {
		return err
	}
	_, err := s.client.DeleteObject(ctx, objectstorage.DeleteObjectRequest{
		NamespaceName: common.String(s.namespace),
		BucketName:    common.String(s.bucket),
		ObjectName:    common.String(objectKey),
	})
	if err != nil && !ociStatus(err, 404) {
		return fmt.Errorf("delete OCI media object: %w", err)
	}
	return nil
}

func (s *OCIObjectStorage) startPARCleanup() {
	s.cleanupWG.Add(1)
	go func() {
		defer s.cleanupWG.Done()
		ctx := s.cleanupContext
		for {
			timer := time.NewTimer(parCleanupDelay())
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			cleanupContext, cleanupCancel := context.WithTimeout(ctx, 2*time.Minute)
			if err := s.cleanupExpiredPARs(cleanupContext, time.Now().UTC()); err != nil && ctx.Err() == nil {
				s.logger.Warn("OCI media PAR cleanup failed", "error", err)
			}
			cleanupCancel()
		}
	}()
}

func (s *OCIObjectStorage) cleanupExpiredPARs(ctx context.Context, now time.Time) error {
	var page *string
	parIDs := make([]string, 0)
	for pageNumber := 0; pageNumber < ociPARCleanupMaxPages; pageNumber++ {
		response, err := s.client.ListPreauthenticatedRequests(ctx, objectstorage.ListPreauthenticatedRequestsRequest{
			NamespaceName: common.String(s.namespace),
			BucketName:    common.String(s.bucket),
			Limit:         common.Int(ociPARCleanupPageLimit),
			Page:          page,
		})
		if err != nil {
			return fmt.Errorf("list OCI media pre-authenticated requests: %w", err)
		}
		for _, item := range response.Items {
			if item.Id == nil || item.Name == nil || item.TimeExpires == nil ||
				!strings.HasPrefix(*item.Name, ociPARNamePrefix) || item.TimeExpires.Time.After(now) {
				continue
			}
			parIDs = append(parIDs, *item.Id)
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			break
		}
		page = response.OpcNextPage
	}

	var cleanupErrors []error
	for _, parID := range parIDs {
		_, err := s.client.DeletePreauthenticatedRequest(ctx, objectstorage.DeletePreauthenticatedRequestRequest{
			NamespaceName: common.String(s.namespace),
			BucketName:    common.String(s.bucket),
			ParId:         common.String(parID),
		})
		if err != nil && !ociStatus(err, 404) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("delete expired OCI media pre-authenticated request: %w", err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func (s *OCIObjectStorage) Close() {
	s.closeOnce.Do(func() {
		s.cleanupCancel()
		s.cleanupWG.Wait()
	})
}

func validateOCIObjectKey(objectKey string) error {
	if objectKey == "" || len(objectKey) > 1024 || !utf8.ValidString(objectKey) || strings.HasPrefix(objectKey, "/") {
		return errors.New("OCI media object key is invalid")
	}
	for _, character := range objectKey {
		if character < 0x20 || character == 0x7f {
			return errors.New("OCI media object key is invalid")
		}
	}
	return nil
}

func parCleanupDelay() time.Duration {
	return 50*time.Minute + time.Duration(rand.Int64N(int64(20*time.Minute)))
}

func ociStatus(err error, status int) bool {
	serviceError, ok := common.IsServiceError(err)
	return ok && serviceError.GetHTTPStatusCode() == status
}
