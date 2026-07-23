package agentclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/internal/storage/sealed"
)

func TestBoundedTransferMethods(t *testing.T) {
	content := []byte("stream content")
	digest := sha256.Sum256(content)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testCredential {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch request.URL.Path {
		case "/api/agent/v1/sealed-payloads":
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(sealedstore.Reference{ID: "sealed_012345678901234567890123", Owner: "agent", Purpose: "secret.set",
				RequestKey: "request", Digest: strings.Repeat("a", 64), Size: 6, ExpiresAt: time.Now().Add(time.Hour).Unix()})
		case "/api/agent/v1/streams":
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(agentv1.StreamReference{ID: "stream_012345678901234567890123", Owner: "agent", Purpose: "asset.upload",
				TransferID: request.Header.Get("X-Broker-Idempotency-Key"), Digest: hex.EncodeToString(digest[:]), Size: int64(len(content)),
				MediaType: request.Header.Get("Content-Type"), ExpiresAt: time.Now().Add(time.Hour).Unix()})
		case "/api/agent/v1/streams/stream_012345678901234567890123":
			writer.Header().Set("Content-Length", stringLength(content))
			writer.Header().Set("X-Broker-Content-SHA256", hex.EncodeToString(digest[:]))
			_, _ = writer.Write(content)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, nil)
	if reference, err := client.UploadSealedPayload(t.Context(), "secret.set", "request", []byte("secret")); err != nil || reference.Purpose != "secret.set" {
		t.Fatalf("UploadSealedPayload() = %+v, %v", reference, err)
	}
	if reference, err := client.UploadStream(t.Context(), "asset.upload", "request", "application/octet-stream", bytes.NewReader(content), int64(len(content)), 1024); err != nil || reference.Size != int64(len(content)) {
		t.Fatalf("UploadStream() = %+v, %v", reference, err)
	}
	if reference, err := client.UploadStream(t.Context(), "asset.upload", "parameterized", "text/plain; charset=utf-8", bytes.NewReader(content), int64(len(content)), 1024); err != nil || reference.MediaType != "text/plain" {
		t.Fatalf("UploadStream(parameterized) = %+v, %v", reference, err)
	}
	var output bytes.Buffer
	if size, err := client.DownloadStream(t.Context(), "stream_012345678901234567890123", &output, 1024); err != nil || size != int64(len(content)) || !bytes.Equal(output.Bytes(), content) {
		t.Fatalf("DownloadStream() = %d, %v, %q", size, err, output.Bytes())
	}
}

func stringLength(value []byte) string { return strconv.Itoa(len(value)) }

func TestTransferMethodsRejectInvalidBounds(t *testing.T) {
	client := newTestClient(t, "http://127.0.0.1:1", nil)
	if _, err := client.UploadSealedPayload(t.Context(), "secret.set", "request", nil); err == nil {
		t.Fatal("empty sealed payload accepted")
	}
	if _, err := client.UploadStream(t.Context(), "asset.upload", "request", "", bytes.NewReader([]byte("x")), 1, 1); err == nil {
		t.Fatal("empty media type accepted")
	}
	if _, err := client.DownloadStream(t.Context(), "bad", &bytes.Buffer{}, 1); err == nil {
		t.Fatal("invalid stream ID accepted")
	}
	if _, err := client.UploadSealedPayload(t.Context(), "invalid", "request", []byte("x")); err == nil {
		t.Fatal("invalid operation accepted")
	}
	if _, err := client.UploadStream(t.Context(), "asset.upload", "bad key", "application/octet-stream", bytes.NewReader([]byte("x")), 1, 1); err == nil {
		t.Fatal("invalid request key accepted")
	}
}

func TestStreamTransfersUseLongLivedSecureClient(t *testing.T) {
	client := newTestClient(t, "http://127.0.0.1:1", &http.Client{Timeout: time.Second})
	if client.httpClient.Timeout != time.Second {
		t.Fatalf("operation timeout = %s", client.httpClient.Timeout)
	}
	if client.transfer.Timeout != 10*time.Minute || client.transfer.CheckRedirect == nil {
		t.Fatalf("transfer client = timeout %s, redirect policy %v", client.transfer.Timeout, client.transfer.CheckRedirect != nil)
	}
}

func TestTransferMethodsRejectBrokerFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/agent/v1/sealed-payloads":
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"id":"sealed_012345678901234567890123","owner":"agent","purpose":"secret.set","request_key":"request","digest":"bad","size":1,"expires_at":1}`))
		case "/api/agent/v1/streams":
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte(`{"error":"bad"}`))
		case "/api/agent/v1/streams/stream_012345678901234567890123":
			writer.Header().Set("Content-Length", "4")
			writer.Header().Set("X-Broker-Content-SHA256", strings.Repeat("0", 64))
			_, _ = writer.Write([]byte("data"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, nil)
	if _, err := client.UploadSealedPayload(t.Context(), "secret.set", "request", []byte("x")); err == nil {
		t.Fatal("invalid sealed reference accepted")
	}
	if _, err := client.UploadStream(t.Context(), "asset.upload", "request", "application/octet-stream", bytes.NewReader([]byte("x")), 1, 1); err == nil {
		t.Fatal("rejected stream upload accepted")
	}
	if _, err := client.DownloadStream(t.Context(), "stream_012345678901234567890123", &bytes.Buffer{}, 4); err == nil {
		t.Fatal("invalid stream integrity accepted")
	}
}
