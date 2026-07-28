package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/internal/storage/sealed"
)

func TestSealedPayloadUploadBindsAuthenticatedRequest(t *testing.T) {
	server := newTestServer(t)
	payload := []byte(`{"input":{"encrypted_value":"Y2FuYXJ5","key_id":"key-1"}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/agent/v1/sealed-payloads", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+testSharedSecret)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Broker-Operation", "workflow.actions_create_or_update_repo_secret")
	request.Header.Set("X-Broker-Idempotency-Key", "sealed-request")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var reference sealedstore.Reference
	if err := json.Unmarshal(response.Body.Bytes(), &reference); err != nil {
		t.Fatal(err)
	}
	if reference.Owner != "bob" || reference.Purpose != "workflow.actions_create_or_update_repo_secret" || reference.RequestKey != "sealed-request" {
		t.Fatalf("reference = %+v", reference)
	}
	stored, err := server.sealedStore.Get(reference)
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatalf("stored = %s err = %v", stored, err)
	}
}

func TestSealedPayloadUploadFailsClosed(t *testing.T) {
	server := newTestServer(t)
	for name, configure := range map[string]func(*http.Request){
		"missing auth": func(request *http.Request) {
			request.Header.Set("Content-Type", "application/octet-stream")
			request.Header.Set("X-Broker-Operation", "workflow.actions_create_or_update_repo_secret")
			request.Header.Set("X-Broker-Idempotency-Key", "sealed-request")
		},
		"public operation": func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer "+testSharedSecret)
			request.Header.Set("Content-Type", "application/octet-stream")
			request.Header.Set("X-Broker-Operation", "repo.metadata.read")
			request.Header.Set("X-Broker-Idempotency-Key", "sealed-request")
		},
		"wrong content type": func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer "+testSharedSecret)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Broker-Operation", "workflow.actions_create_or_update_repo_secret")
			request.Header.Set("X-Broker-Idempotency-Key", "sealed-request")
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/agent/v1/sealed-payloads", strings.NewReader(`{"input":{}}`))
			configure(request)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code < http.StatusBadRequest {
				t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
			}
		})
	}
}
