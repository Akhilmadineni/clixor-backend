package media

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const testOCIEndpoint = "https://objectstorage.us-phoenix-1.oraclecloud.com"

type fakeOCIObjectStorageClient struct {
	createResponse objectstorage.CreatePreauthenticatedRequestResponse
	createError    error
	createRequests []objectstorage.CreatePreauthenticatedRequestRequest

	headObjectResponse objectstorage.HeadObjectResponse
	headObjectError    error
	headObjectRequests []objectstorage.HeadObjectRequest

	deleteObjectError    error
	deleteObjectRequests []objectstorage.DeleteObjectRequest

	listResponses []objectstorage.ListPreauthenticatedRequestsResponse
	listError     error
	listRequests  []objectstorage.ListPreauthenticatedRequestsRequest

	deletePARError    error
	deletePARRequests []objectstorage.DeletePreauthenticatedRequestRequest
}

type fakeOCIServiceError struct{ status int }

func (e fakeOCIServiceError) Error() string           { return "OCI service error" }
func (e fakeOCIServiceError) GetHTTPStatusCode() int  { return e.status }
func (e fakeOCIServiceError) GetMessage() string      { return e.Error() }
func (e fakeOCIServiceError) GetCode() string         { return "test" }
func (e fakeOCIServiceError) GetOpcRequestID() string { return "test-request" }

func (*fakeOCIObjectStorageClient) HeadBucket(
	context.Context,
	objectstorage.HeadBucketRequest,
) (objectstorage.HeadBucketResponse, error) {
	return objectstorage.HeadBucketResponse{}, nil
}

func (f *fakeOCIObjectStorageClient) CreatePreauthenticatedRequest(
	_ context.Context,
	request objectstorage.CreatePreauthenticatedRequestRequest,
) (objectstorage.CreatePreauthenticatedRequestResponse, error) {
	f.createRequests = append(f.createRequests, request)
	return f.createResponse, f.createError
}

func (f *fakeOCIObjectStorageClient) ListPreauthenticatedRequests(
	_ context.Context,
	request objectstorage.ListPreauthenticatedRequestsRequest,
) (objectstorage.ListPreauthenticatedRequestsResponse, error) {
	f.listRequests = append(f.listRequests, request)
	if f.listError != nil {
		return objectstorage.ListPreauthenticatedRequestsResponse{}, f.listError
	}
	if len(f.listResponses) == 0 {
		return objectstorage.ListPreauthenticatedRequestsResponse{}, nil
	}
	response := f.listResponses[0]
	f.listResponses = f.listResponses[1:]
	return response, nil
}

func (f *fakeOCIObjectStorageClient) DeletePreauthenticatedRequest(
	_ context.Context,
	request objectstorage.DeletePreauthenticatedRequestRequest,
) (objectstorage.DeletePreauthenticatedRequestResponse, error) {
	f.deletePARRequests = append(f.deletePARRequests, request)
	return objectstorage.DeletePreauthenticatedRequestResponse{}, f.deletePARError
}

func (f *fakeOCIObjectStorageClient) HeadObject(
	_ context.Context,
	request objectstorage.HeadObjectRequest,
) (objectstorage.HeadObjectResponse, error) {
	f.headObjectRequests = append(f.headObjectRequests, request)
	return f.headObjectResponse, f.headObjectError
}

func (f *fakeOCIObjectStorageClient) DeleteObject(
	_ context.Context,
	request objectstorage.DeleteObjectRequest,
) (objectstorage.DeleteObjectResponse, error) {
	f.deleteObjectRequests = append(f.deleteObjectRequests, request)
	return objectstorage.DeleteObjectResponse{}, f.deleteObjectError
}

func newTestOCIStore(t *testing.T, client *fakeOCIObjectStorageClient) *OCIObjectStorage {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := newOCIObjectStorage(client, testOCIEndpoint, "testnamespace", "clixor-media", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func ociHeadResponse(size int64, contentType, digestHex string) objectstorage.HeadObjectResponse {
	digest, _ := hex.DecodeString(digestHex)
	checksum := base64.StdEncoding.EncodeToString(digest)
	return objectstorage.HeadObjectResponse{
		ContentLength: &size, ContentType: &contentType, OpcContentSha256: &checksum,
	}
}

func TestOCIPrepareUploadCreatesObjectSpecificWritePARAndChecksumHeaders(t *testing.T) {
	client := &fakeOCIObjectStorageClient{
		createResponse: objectstorage.CreatePreauthenticatedRequestResponse{
			PreauthenticatedRequest: objectstorage.PreauthenticatedRequest{
				AccessUri: common.String("/p/opaque-token/n/testnamespace/b/clixor-media/o/conversations/id/media"),
			},
		},
	}
	store := newTestOCIStore(t, client)
	before := time.Now().UTC()
	upload, err := store.PrepareUpload(
		context.Background(), "conversations/id/media", "application/octet-stream", 42,
		testSHA256, 15*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := upload.URL.String(), testOCIEndpoint+"/p/opaque-token/n/testnamespace/b/clixor-media/o/conversations/id/media"; got != want {
		t.Fatalf("upload URL = %q, want %q", got, want)
	}
	if upload.Method != "PUT" || upload.Headers["Content-Type"] != "application/octet-stream" ||
		upload.Headers["Content-Length"] != "42" || upload.Headers["opc-checksum-algorithm"] != "SHA256" ||
		upload.Headers["opc-content-sha256"] != "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=" {
		t.Fatalf("OCI upload instructions = %+v", upload)
	}
	if len(client.createRequests) != 1 {
		t.Fatalf("create request count = %d, want 1", len(client.createRequests))
	}
	request := client.createRequests[0]
	if request.AccessType != objectstorage.CreatePreauthenticatedRequestDetailsAccessTypeObjectwrite {
		t.Fatalf("access type = %q, want ObjectWrite", request.AccessType)
	}
	if request.ObjectName == nil || *request.ObjectName != "conversations/id/media" {
		t.Fatalf("object name = %v", request.ObjectName)
	}
	if request.Name == nil || !strings.HasPrefix(*request.Name, ociPARNamePrefix) {
		t.Fatalf("PAR name = %v, want random clixor name", request.Name)
	}
	if _, err := uuid.Parse(strings.TrimPrefix(*request.Name, ociPARNamePrefix)); err != nil {
		t.Fatalf("PAR name does not contain only the expected prefix and a random UUID: %v", err)
	}
	if strings.Contains(*request.Name, "conversations") || strings.Contains(*request.Name, "media") {
		t.Fatalf("PAR name leaked an object identifier: %q", *request.Name)
	}
	if request.TimeExpires == nil || request.TimeExpires.Time.Before(before.Add(14*time.Minute)) ||
		request.TimeExpires.Time.After(before.Add(16*time.Minute)) {
		t.Fatalf("unexpected PAR expiration: %v", request.TimeExpires)
	}
}

func TestOCIDownloadURLCreatesObjectSpecificReadPAR(t *testing.T) {
	client := &fakeOCIObjectStorageClient{
		createResponse: objectstorage.CreatePreauthenticatedRequestResponse{
			PreauthenticatedRequest: objectstorage.PreauthenticatedRequest{
				AccessUri: common.String("/p/read-token/n/testnamespace/b/clixor-media/o/conversations/id/media"),
			},
		},
	}
	store := newTestOCIStore(t, client)
	if _, err := store.DownloadURL(context.Background(), "conversations/id/media", 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := client.createRequests[0].AccessType; got != objectstorage.CreatePreauthenticatedRequestDetailsAccessTypeObjectread {
		t.Fatalf("access type = %q, want ObjectRead", got)
	}
}

func TestOCIRejectsAbsolutePARAccessURI(t *testing.T) {
	client := &fakeOCIObjectStorageClient{
		createResponse: objectstorage.CreatePreauthenticatedRequestResponse{
			PreauthenticatedRequest: objectstorage.PreauthenticatedRequest{
				AccessUri: common.String("https://attacker.example/p/stolen"),
			},
		},
	}
	store := newTestOCIStore(t, client)
	if _, err := store.DownloadURL(context.Background(), "conversations/id/media", 15*time.Minute); err == nil ||
		!strings.Contains(err.Error(), "invalid access URI") {
		t.Fatalf("expected an absolute access URI to fail, received %v", err)
	}
}

func TestOCIVerifyAcceptsMatchingHeadMetadataWithoutReadingObject(t *testing.T) {
	client := &fakeOCIObjectStorageClient{
		headObjectResponse: ociHeadResponse(3, "application/octet-stream", testSHA256),
	}
	store := newTestOCIStore(t, client)
	if err := store.Verify(
		context.Background(), "conversations/id/media", 3, testSHA256, "application/octet-stream",
	); err != nil {
		t.Fatal(err)
	}
	if len(client.headObjectRequests) != 1 || len(client.deleteObjectRequests) != 0 {
		t.Fatalf("verification calls: head=%d delete=%d", len(client.headObjectRequests), len(client.deleteObjectRequests))
	}
}

func TestOCIVerifyTreatsMissingOrMismatchedMetadataAsDefinitive(t *testing.T) {
	wrongDigest := sha256.Sum256([]byte("wrong"))
	wrongChecksum := base64.StdEncoding.EncodeToString(wrongDigest[:])
	wrongType := "image/jpeg"
	missingChecksum := ociHeadResponse(3, "application/octet-stream", testSHA256)
	missingChecksum.OpcContentSha256 = nil
	wrongChecksumResponse := ociHeadResponse(3, "application/octet-stream", testSHA256)
	wrongChecksumResponse.OpcContentSha256 = &wrongChecksum
	wrongTypeResponse := ociHeadResponse(3, "application/octet-stream", testSHA256)
	wrongTypeResponse.ContentType = &wrongType
	wrongSizeResponse := ociHeadResponse(4, "application/octet-stream", testSHA256)

	for name, response := range map[string]objectstorage.HeadObjectResponse{
		"missing checksum": missingChecksum,
		"wrong checksum":   wrongChecksumResponse,
		"wrong type":       wrongTypeResponse,
		"wrong size":       wrongSizeResponse,
	} {
		t.Run(name, func(t *testing.T) {
			client := &fakeOCIObjectStorageClient{headObjectResponse: response}
			store := newTestOCIStore(t, client)
			err := store.Verify(
				context.Background(), "conversations/id/media", 3, testSHA256, "application/octet-stream",
			)
			if !errors.Is(err, ErrVerificationMismatch) || !IsDefinitiveVerificationFailure(err) {
				t.Fatalf("verification error = %v, want definitive mismatch", err)
			}
			if len(client.deleteObjectRequests) != 0 {
				t.Fatal("verification bypassed the durable deletion outbox")
			}
		})
	}
}

func TestOCIVerifyClassifiesMissingAndTransientStorageErrors(t *testing.T) {
	for name, test := range map[string]struct {
		status     int
		definitive bool
		want       error
	}{
		"missing":   {status: 404, definitive: true, want: ErrUploadMissing},
		"transient": {status: 503, definitive: false, want: ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			client := &fakeOCIObjectStorageClient{headObjectError: fakeOCIServiceError{status: test.status}}
			store := newTestOCIStore(t, client)
			err := store.Verify(
				context.Background(), "conversations/id/media", 3, testSHA256, "application/octet-stream",
			)
			if !errors.Is(err, test.want) || IsDefinitiveVerificationFailure(err) != test.definitive {
				t.Fatalf("verification error = %v", err)
			}
		})
	}
}

func TestOCICleanupDeletesOnlyExpiredOwnedPARsAcrossPages(t *testing.T) {
	now := time.Now().UTC()
	expired := common.SDKTime{Time: now.Add(-time.Minute)}
	future := common.SDKTime{Time: now.Add(time.Minute)}
	nextPage := "next"
	client := &fakeOCIObjectStorageClient{
		listResponses: []objectstorage.ListPreauthenticatedRequestsResponse{
			{
				Items: []objectstorage.PreauthenticatedRequestSummary{
					{Id: common.String("expired-1"), Name: common.String(ociPARNamePrefix + uuid.NewString()), TimeExpires: &expired},
					{Id: common.String("future"), Name: common.String(ociPARNamePrefix + uuid.NewString()), TimeExpires: &future},
					{Id: common.String("foreign"), Name: common.String("another-service"), TimeExpires: &expired},
				},
				OpcNextPage: &nextPage,
			},
			{
				Items: []objectstorage.PreauthenticatedRequestSummary{
					{Id: common.String("expired-2"), Name: common.String(ociPARNamePrefix + uuid.NewString()), TimeExpires: &expired},
				},
			},
		},
	}
	store := newTestOCIStore(t, client)
	if err := store.cleanupExpiredPARs(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(client.listRequests) != 2 || client.listRequests[1].Page == nil || *client.listRequests[1].Page != nextPage {
		t.Fatalf("pagination requests = %#v", client.listRequests)
	}
	if len(client.deletePARRequests) != 2 {
		t.Fatalf("deleted PAR count = %d, want 2", len(client.deletePARRequests))
	}
	deleted := map[string]bool{}
	for _, request := range client.deletePARRequests {
		deleted[*request.ParId] = true
	}
	if !deleted["expired-1"] || !deleted["expired-2"] || deleted["future"] || deleted["foreign"] {
		t.Fatalf("unexpected deleted PARs: %#v", deleted)
	}
}

func TestOCICleanupLoopStopsOnClose(t *testing.T) {
	store := newTestOCIStore(t, &fakeOCIObjectStorageClient{})
	store.startPARCleanup()
	done := make(chan struct{})
	go func() {
		store.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not stop the PAR cleanup loop")
	}
}
