package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agent/v1"
)

func TestBucketObjectStreamsAreBoundedOwnedAndOneShot(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	server, handler, stop := newAgentOperationTestServer(t, upstream.URL, emptyPolicyJSON())
	defer server.Close()
	defer func() {
		stop()
		_ = handler.Close()
	}()

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/agent/v1/streams", bytes.NewReader([]byte("artifact")))
	request.Header.Set("Authorization", "Bearer "+testSecret)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Broker-Operation", "bucket.object.write")
	request.Header.Set("X-Broker-Idempotency-Key", "bucket-write-1")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var reference agentv1.StreamReference
	if err := json.NewDecoder(response.Body).Decode(&reference); err != nil || response.StatusCode != http.StatusCreated || reference.Owner != "agent" || reference.TransferID != "bucket-write-1" || reference.Size != 8 {
		t.Fatalf("upload = %d %+v, %v", response.StatusCode, reference, err)
	}

	download, _ := http.NewRequest(http.MethodGet, server.URL+"/api/agent/v1/streams/"+reference.ID, nil)
	download.Header.Set("Authorization", "Bearer "+testSecret)
	response, err = http.DefaultClient.Do(download)
	if err != nil {
		t.Fatal(err)
	}
	content, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(content) != "artifact" || response.Header.Get("X-Broker-Content-SHA256") != reference.Digest {
		t.Fatalf("download = %d %q headers=%v", response.StatusCode, content, response.Header)
	}
	response, err = http.DefaultClient.Do(download.Clone(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("replayed download status = %d", response.StatusCode)
	}
}

func TestBucketObjectStreamRejectsUnboundOperation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/agent/v1/streams", bytes.NewReader([]byte("data")))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Broker-Operation", "repo.create")
	request.Header.Set("X-Broker-Idempotency-Key", "bad-stream")
	if _, err := hfStreamUploadFromRequest("agent", request, time.Now()); err == nil {
		t.Fatal("non-stream operation accepted")
	}
}
