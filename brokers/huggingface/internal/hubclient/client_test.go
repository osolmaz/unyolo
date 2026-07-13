package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientBoundsAndAuthenticatesRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/repos/delete" || r.URL.Query().Get("check") != "yes" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("request = %s %s, auth %q", r.Method, r.URL.String(), r.Header.Get("Authorization"))
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(` { "ok": true } `))
	}))
	defer server.Close()
	client, err := New(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), Call{Method: http.MethodPost, Path: "/api/repos/delete", Query: map[string][]string{"check": {"yes"}}, Body: json.RawMessage(`{"name":"demo"}`)})
	if err != nil || string(response.Body) != `{"ok":true}` || response.ETag != `"v1"` {
		t.Fatalf("response = %+v, %v", response, err)
	}
}

func TestClientClassifiesAndRedactsErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"token":"must-not-escape"}`))
	}))
	defer server.Close()
	client, _ := New(server.URL, "secret", server.Client())
	_, err := client.Do(context.Background(), Call{Method: http.MethodDelete, Path: "/api/resource"})
	var upstream *Error
	if !errors.As(err, &upstream) || upstream.Code != CodeRateLimited || upstream.RetryAfter != 17*time.Second || strings.Contains(err.Error(), "token") {
		t.Fatalf("error = %#v (%v)", upstream, err)
	}
}

func TestClientTreatsMutationTransportFailureAsAmbiguous(t *testing.T) {
	client, _ := New("http://127.0.0.1:1", "secret", &http.Client{Timeout: 10 * time.Millisecond})
	_, err := client.Do(context.Background(), Call{Method: http.MethodPost, Path: "/api/repos/delete", Body: json.RawMessage(`{}`)})
	var upstream *Error
	if !errors.As(err, &upstream) || upstream.Code != CodeUnknownResult || !upstream.Ambiguous {
		t.Fatalf("error = %#v (%v)", upstream, err)
	}
	_, err = client.Do(context.Background(), Call{Method: http.MethodGet, Path: "/api/repos/demo"})
	if !errors.As(err, &upstream) || upstream.Code != CodeUnavailable {
		t.Fatalf("GET error = %#v (%v)", upstream, err)
	}
}

func TestClientRejectsUnsafeCalls(t *testing.T) {
	client, _ := New("https://huggingface.co", "", nil)
	for _, call := range []Call{
		{Method: "TRACE", Path: "/api/x"},
		{Method: http.MethodGet, Path: "https://attacker.example/x"},
		{Method: http.MethodGet, Path: "/api/../settings"},
		{Method: http.MethodPost, Path: "/api/x", Body: json.RawMessage(`no`)},
	} {
		if _, err := client.Do(context.Background(), call); err == nil {
			t.Fatalf("unsafe call accepted: %+v", call)
		}
	}
}
