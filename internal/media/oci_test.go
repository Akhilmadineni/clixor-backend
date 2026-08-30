package media

import (
	"context"
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

func TestOCIUploadURLCreatesObjectSpecificWritePAR(t *testing.T) {
	client := &fakeOCIObjectStorageClient{
		createResponse: objectstorage.CreatePreauthenticatedRequestResponse{
			PreauthenticatedRequest: objectstorage.PreauthenticatedRequest{
				AccessUri: common.String("/p/opaque-token/n/testnamespace/b/clixor-media/o/conversations/id/media"),
			},
		},
	}
	store := newTestOCIStore(t, client)
	before := time.Now().UTC()
	uploadURL, err := store.UploadURL(
		context.Background(), "conversations/id/media", "application/octet-stream", 42, 15*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := uploadURL.String(), testOCIEndpoint+"/p/opaque-token/n/testnamespace/b/clixor-media/o/conversations/id/media"; got != want {
		t.Fatalf("upload URL = %q, want %q", got, want)
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

func TestOCIVerifyDeletesMismatchedObject(t *testing.T) {
	actualSize := int64(1 << 30)
	client := &fakeOCIObjectStorageClient{
		headObjectResponse: objectstorage.HeadObjectResponse{ContentLength: &actualSize},
	}
	store := newTestOCIStore(t, client)
	err := store.Verify(context.Background(), "conversations/id/media", 42)
	if err == nil || !strings.Contains(err.Error(), "media size mismatch") {
		t.Fatalf("expected a size mismatch, received %v", err)
	}
	if len(client.deleteObjectRequests) != 1 || client.deleteObjectRequests[0].ObjectName == nil ||
		*client.deleteObjectRequests[0].ObjectName != "conversations/id/media" {
		t.Fatalf("mismatched object was not deleted: %#v", client.deleteObjectRequests)
	}
}

func TestOCIVerifyAcceptsMatchingObjectWithoutDeletingIt(t *testing.T) {
	actualSize := int64(42)
	client := &fakeOCIObjectStorageClient{
		headObjectResponse: objectstorage.HeadObjectResponse{ContentLength: &actualSize},
	}
	store := newTestOCIStore(t, client)
	if err := store.Verify(context.Background(), "conversations/id/media", actualSize); err != nil {
		t.Fatal(err)
	}
	if len(client.deleteObjectRequests) != 0 {
		t.Fatalf("matching object was unexpectedly deleted: %#v", client.deleteObjectRequests)
	}
}

func TestOCIVerifyReportsMismatchedObjectCleanupFailure(t *testing.T) {
	actualSize := int64(100)
	client := &fakeOCIObjectStorageClient{
		headObjectResponse: objectstorage.HeadObjectResponse{ContentLength: &actualSize},
		deleteObjectError:  errors.New("delete failed"),
	}
	store := newTestOCIStore(t, client)
	err := store.Verify(context.Background(), "conversations/id/media", 42)
	if err == nil || !strings.Contains(err.Error(), "media size mismatch") || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("expected both mismatch and cleanup errors, received %v", err)
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
