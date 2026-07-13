package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/sealedstore"
)

func TestSealedPayloadUploadBindsAuthenticatedClientAndPurpose(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, emptyPolicyJSON())
	defer cancel()
	defer server.Close()
	secret := []byte("canary-secret-value")
	response, body := doRequestWithHeaders(t, http.MethodPost, server.URL+"/api/agent/v1/sealed-payloads", "Bearer "+testSecret,
		map[string]string{"Content-Type": "application/octet-stream", "X-Broker-Operation": "space.secret.set"}, bytes.NewReader(secret))
	if response.StatusCode != http.StatusCreated || strings.Contains(body, string(secret)) {
		t.Fatalf("upload = %d %s", response.StatusCode, body)
	}
	var reference sealedstore.Reference
	if err := json.Unmarshal([]byte(body), &reference); err != nil || reference.Owner != "agent" || reference.Purpose != "space.secret.set" {
		t.Fatalf("reference = %+v, %v", reference, err)
	}
	plaintext, err := handler.sealedStore.Get(reference)
	if err != nil || !bytes.Equal(plaintext, secret) {
		t.Fatalf("sealed Get() = %q, %v", plaintext, err)
	}
}

func TestSealedPayloadUploadFailsClosed(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	server, _, cancel := newAgentOperationTestServer(t, upstream.URL, emptyPolicyJSON())
	defer cancel()
	defer server.Close()
	tests := []struct {
		auth, contentType, operation string
		want                         int
	}{
		{"", "application/octet-stream", "space.secret.set", http.StatusUnauthorized},
		{"Bearer " + testSecret, "application/json", "space.secret.set", http.StatusBadRequest},
		{"Bearer " + testSecret, "application/octet-stream", "repo.delete", http.StatusBadRequest},
	}
	for _, test := range tests {
		response, _ := doRequestWithHeaders(t, http.MethodPost, server.URL+"/api/agent/v1/sealed-payloads", test.auth,
			map[string]string{"Content-Type": test.contentType, "X-Broker-Operation": test.operation}, strings.NewReader("secret"))
		if response.StatusCode != test.want {
			t.Fatalf("upload status = %d, want %d", response.StatusCode, test.want)
		}
	}
}
