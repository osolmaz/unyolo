package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStreamUploadAndOneTimeDownloadRoutes(t *testing.T) {
	server := newTestServer(t)
	upload := httptest.NewRequest(http.MethodPost, "/api/agent/v1/streams", bytes.NewBufferString("asset-canary"))
	upload.Header.Set("Authorization", "Bearer "+testSharedSecret)
	upload.Header.Set("Content-Type", "application/octet-stream")
	upload.Header.Set("X-Broker-Operation", "release.repos_upload_release_asset")
	upload.Header.Set("X-Broker-Idempotency-Key", "asset-request")
	uploadResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(uploadResponse, upload)
	if uploadResponse.Code != http.StatusCreated || !bytes.Contains(uploadResponse.Body.Bytes(), []byte(`"owner":"bob"`)) {
		t.Fatalf("upload status = %d body = %s", uploadResponse.Code, uploadResponse.Body.String())
	}

	output, err := server.streamStore.Put("bob", "repo.download_zipball_archive", "download-result", "application/zip",
		bytes.NewBufferString("archive-canary"), 1024, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/agent/v1/streams/"+output.ID, http.NoBody)
	request.Header.Set("Authorization", "Bearer "+testSharedSecret)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	data, _ := io.ReadAll(response.Result().Body)
	if response.Code != http.StatusOK || string(data) != "archive-canary" || response.Header().Get("X-Broker-Content-SHA256") != output.Digest {
		t.Fatalf("download status = %d body = %q headers = %v", response.Code, data, response.Header())
	}
	replay := httptest.NewRecorder()
	server.Handler().ServeHTTP(replay, request.Clone(request.Context()))
	if replay.Code != http.StatusNotFound {
		t.Fatalf("replay status = %d", replay.Code)
	}
}

func TestStreamRoutesRejectWrongPurposeAndOwner(t *testing.T) {
	server := newTestServer(t)
	upload := httptest.NewRequest(http.MethodPost, "/api/agent/v1/streams", bytes.NewBufferString("canary"))
	upload.Header.Set("Authorization", "Bearer "+testSharedSecret)
	upload.Header.Set("Content-Type", "application/octet-stream")
	upload.Header.Set("X-Broker-Operation", "repo.metadata.read")
	upload.Header.Set("X-Broker-Idempotency-Key", "bad-stream")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, upload)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("upload status = %d", response.Code)
	}
	output, _ := server.streamStore.Put("alice", "repo.download_zipball_archive", "download-result", "application/zip",
		bytes.NewBufferString("archive"), 1024, time.Now().Add(time.Hour))
	download := httptest.NewRequest(http.MethodGet, "/api/agent/v1/streams/"+output.ID, http.NoBody)
	download.Header.Set("Authorization", "Bearer "+testSharedSecret)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, download)
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-owner status = %d", response.Code)
	}
}
