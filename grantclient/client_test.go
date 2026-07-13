package grantclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type testGrant struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func TestClientLifecycleAndWait(t *testing.T) {
	t.Parallel()
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testCredential {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		status := "pending"
		if request.URL.Path == "/api/grants/grant/cancel" {
			status = "canceled"
		} else if request.URL.Path == "/api/grants/grant/revoke" {
			status = "revoked"
		} else if request.Method == http.MethodGet && gets.Add(1) > 1 {
			status = "active"
		}
		_ = json.NewEncoder(writer).Encode(testGrant{ID: "grant", Status: status})
	}))
	defer server.Close()
	client := newTestClient(t, server.URL)
	if grant, err := client.Request(t.Context(), map[string]string{"operation": "write"}); err != nil || grant.ID != "grant" {
		t.Fatalf("Request() = %+v, %v", grant, err)
	}
	if grant, err := client.Wait(t.Context(), "grant"); err != nil || grant.Status != "active" {
		t.Fatalf("Wait() = %+v, %v", grant, err)
	}
	if grant, err := client.Cancel(t.Context(), "grant"); err != nil || grant.Status != "canceled" {
		t.Fatalf("Cancel() = %+v, %v", grant, err)
	}
	if grant, err := client.Revoke(t.Context(), "grant"); err != nil || grant.Status != "revoked" {
		t.Fatalf("Revoke() = %+v, %v", grant, err)
	}
}

func TestClientRejectsInvalidConfigurationAndResponses(t *testing.T) {
	t.Parallel()
	if _, err := New(Options[testGrant]{}); err == nil {
		t.Fatal("New() accepted empty options")
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/grants/error":
			writer.WriteHeader(http.StatusForbidden)
		case "/api/grants/text":
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = writer.Write([]byte("no"))
		case "/api/grants/large":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(make([]byte, maxResponseBytes+1))
		default:
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte("bad"))
		}
	}))
	defer server.Close()
	client := newTestClient(t, server.URL)
	for _, test := range []struct {
		id     string
		status int
	}{
		{id: "error", status: http.StatusForbidden},
		{id: "text"},
		{id: "large"},
		{id: "bad"},
	} {
		_, err := client.Get(t.Context(), test.id)
		var httpErr *Error
		if err == nil || (test.status != 0 && (!errors.As(err, &httpErr) || httpErr.Status != test.status)) {
			t.Fatalf("Get(%s) error = %v", test.id, err)
		}
	}
}

func TestClientWaitCancellation(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(testGrant{ID: "grant", Status: "pending"})
	}))
	defer server.Close()
	client := newTestClient(t, server.URL)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	grant, err := client.Wait(ctx, "grant")
	if !errors.Is(err, context.Canceled) || grant.ID != "" {
		t.Fatalf("Wait() = %+v, %v", grant, err)
	}
}

func TestClientRejectsRedirectsWithoutMutatingProvidedClient(t *testing.T) {
	t.Parallel()
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed.Store(true)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", target.URL)
		writer.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()
	provided := &http.Client{}
	client, err := New(Options[testGrant]{
		BaseURL: redirect.URL, Credential: testCredential, HTTPClient: provided,
		Decode:   func([]byte) (testGrant, error) { return testGrant{}, nil },
		Terminal: func(testGrant) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Get(t.Context(), "grant")
	var httpErr *Error
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusFound || followed.Load() {
		t.Fatalf("Get() error = %v, followed=%v", err, followed.Load())
	}
	if provided.CheckRedirect != nil {
		t.Fatal("New() mutated the provided HTTP client")
	}
}

const testCredential = "client-credential-with-enough-entropy"

func newTestClient(t *testing.T, baseURL string) *Client[testGrant] {
	t.Helper()
	client, err := New(Options[testGrant]{
		BaseURL: baseURL, Credential: testCredential, PollInterval: time.Millisecond,
		Decode: func(data []byte) (testGrant, error) {
			var grant testGrant
			err := json.Unmarshal(data, &grant)
			return grant, err
		},
		Terminal: func(grant testGrant) bool { return grant.Status != "pending" },
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
