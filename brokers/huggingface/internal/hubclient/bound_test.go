package hubclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecuteBoundUsesOnlyRegisteredMethodPathAndFixedFields(t *testing.T) {
	requests := make(chan *http.Request, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- request.Clone(request.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "hf_test_token")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ExecuteBound(context.Background(), "bucket.delete",
		json.RawMessage(`{"namespace":"alice","repo":"old"}`), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	request := <-requests
	if request.Method != http.MethodDelete || request.URL.Path != "/api/buckets/alice/old" {
		t.Fatalf("request = %s %s", request.Method, request.URL.Path)
	}
	if err := client.ExecuteBound(context.Background(), "webhook.enable",
		json.RawMessage(`{"webhookId":"0123456789abcdef01234567"}`), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	request = <-requests
	if request.Method != http.MethodPost || request.URL.Path != "/api/settings/webhooks/0123456789abcdef01234567/enable" {
		t.Fatalf("request = %s %s", request.Method, request.URL.Path)
	}
}

func TestExecuteBoundRejectsUnknownOperationAndPathFields(t *testing.T) {
	client, _ := New("https://huggingface.co", "hf_test_token")
	for _, test := range []struct {
		operation string
		target    string
	}{
		{operation: "http.request", target: `{}`},
		{operation: "bucket.delete", target: `{"namespace":"alice"}`},
		{operation: "bucket.delete", target: `{"namespace":"alice","repo":"../admin"}`},
	} {
		if err := client.ExecuteBound(context.Background(), test.operation, json.RawMessage(test.target), json.RawMessage(`{}`)); err == nil {
			t.Fatalf("unsafe operation accepted: %+v", test)
		}
	}
}
