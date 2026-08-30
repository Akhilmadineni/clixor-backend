package media

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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

func (s *OCIObjectStorage) UploadURL(
	ctx context.Context,
	objectKey string,
	contentType string,
	byteSize int64,
	expiry time.Duration,
) (*url.URL, error) {
	if strings.TrimSpace(contentType) == "" || byteSize < 1 {
		return nil, errors.New("OCI media upload content type and positive byte size are required")
	}
	return s.createPAR(ctx, objectKey, expiry, objectstorage.CreatePreauthenticatedRequestDetailsAccessTypeObjectwrite)
}

func (s *OCIObjectStorage) DownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (*url.URL, error) {
	return s.createPAR(ctx, objectKey, expiry, objectstorage.CreatePreauthenticatedRequestDetailsAccessTypeObjectread)
}

func (s *OCIObjectStorage) createPAR(
	ctx context.Context,
	objectKey string,
	expiry time.Duration,
	accessType objectstorage.CreatePreauthenticatedRequestDetailsAccessTypeEnum,
) (*url.URL, error) {
	if err := validateOCIObjectKey(objectKey); err != nil {
		return nil, err
	}
	if expiry <= 0 || expiry > ociMaxPARExpiry {
		return nil, fmt.Errorf("OCI media URL expiry must be between 1ns and %s", ociMaxPARExpiry)
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
		return nil, fmt.Errorf("create OCI media pre-authenticated request: %w", err)
	}
	if response.AccessUri == nil {
		return nil, errors.New("OCI media pre-authenticated request omitted its access URI")
	}
	accessURI, err := url.Parse(*response.AccessUri)
	if err != nil || accessURI.IsAbs() || accessURI.Host != "" || accessURI.User != nil ||
		accessURI.RawQuery != "" || accessURI.Fragment != "" || !strings.HasPrefix(accessURI.EscapedPath(), "/p/") {
		return nil, errors.New("OCI media pre-authenticated request returned an invalid access URI")
	}
	return s.endpoint.ResolveReference(accessURI), nil
}

func (s *OCIObjectStorage) Verify(ctx context.Context, objectKey string, expectedSize int64) error {
	if err := validateOCIObjectKey(objectKey); err != nil {
		return err
	}
	if expectedSize < 1 {
		return errors.New("expected OCI media size must be positive")
	}
	response, err := s.client.HeadObject(ctx, objectstorage.HeadObjectRequest{
		NamespaceName: common.String(s.namespace),
		BucketName:    common.String(s.bucket),
		ObjectName:    common.String(objectKey),
	})
	if err != nil {
		return fmt.Errorf("inspect OCI media object: %w", err)
	}
	if response.ContentLength == nil {
		return errors.New("OCI media object response omitted content length")
	}
	if *response.ContentLength != expectedSize {
		sizeError := fmt.Errorf("media size mismatch: expected %d, received %d", expectedSize, *response.ContentLength)
		deleteContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if deleteErr := s.Delete(deleteContext, objectKey); deleteErr != nil {
			return errors.Join(sizeError, fmt.Errorf("remove mismatched OCI media object: %w", deleteErr))
		}
		return sizeError
	}
	return nil
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
