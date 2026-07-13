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

func TestTypedRepositoryCallsAreBoundedAndAuthenticated(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch requests {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/api/datasets/acme/demo" {
				t.Fatalf("repo info request = %s %s", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"id":"acme/demo","sha":"abc","private":true,"gated":"manual","sdk":"docker"}`))
		case 2:
			if r.Method != http.MethodDelete || r.URL.Path != "/api/repos/delete" {
				t.Fatalf("delete request = %s %s", r.Method, r.URL.Path)
			}
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["organization"] != "acme" || body["name"] != "demo" || body["type"] != "dataset" {
				t.Fatalf("delete body = %#v", body)
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "secret", WithHTTPTransport(server.Client().Transport))
	if err != nil {
		t.Fatal(err)
	}
	ref := RepoRef{Type: RepoTypeDataset, Owner: "acme", Name: "demo"}
	info, err := client.RepoInfo(context.Background(), ref)
	if err != nil || info.SHA != "abc" || info.Gated != GatedManual || info.SDK != "docker" {
		t.Fatalf("RepoInfo() = %+v, %v", info, err)
	}
	if err := client.DeleteRepo(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
}

func TestTypedKernelRepositoryCallsUseKernelPathsAndType(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch requests {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/api/kernels/acme/demo" {
				t.Fatalf("kernel info request = %s %s", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"id":"acme/demo","sha":"abc","private":true}`))
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != "/api/repos/create" {
				t.Fatalf("kernel create request = %s %s", r.Method, r.URL.Path)
			}
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["type"] != "kernel" {
				t.Fatalf("kernel create body = %#v", body)
			}
			_, _ = w.Write([]byte(`{"url":"https://huggingface.co/kernels/acme/demo"}`))
		case 3:
			if r.Method != http.MethodDelete || r.URL.Path != "/api/repos/delete" {
				t.Fatalf("kernel delete request = %s %s", r.Method, r.URL.Path)
			}
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["type"] != "kernel" {
				t.Fatalf("kernel delete body = %#v", body)
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "secret", WithHTTPTransport(server.Client().Transport))
	if err != nil {
		t.Fatal(err)
	}
	ref := RepoRef{Type: RepoTypeKernel, Owner: "acme", Name: "demo"}
	if info, err := client.RepoInfo(t.Context(), ref); err != nil || info.ID != "acme/demo" {
		t.Fatalf("RepoInfo() = %+v, %v", info, err)
	}
	if created, err := client.CreateRepo(t.Context(), CreateRepoInput{Ref: ref, Visibility: VisibilityPrivate}); err != nil || created.URL == "" {
		t.Fatalf("CreateRepo() = %+v, %v", created, err)
	}
	if err := client.DeleteRepo(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedSpaceHardwareFlavorsAreAccepted(t *testing.T) {
	for _, flavor := range []string{"cpu-performance", "cpu-xl", "sprx8", "h200", "h200x8", "rtx-pro-6000", "rtx-pro-6000x8", "inf2x6"} {
		if !ValidHardwareFlavor(flavor) {
			t.Errorf("pinned Space hardware flavor %q was rejected", flavor)
		}
	}
	if ValidHardwareFlavor("future-unpinned-hardware") {
		t.Fatal("unpinned Space hardware flavor was accepted")
	}
}

func TestTypedClientClassifiesAndRedactsErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"token":"must-not-escape"}`))
	}))
	defer server.Close()
	client, _ := New(server.URL, "secret", WithHTTPTransport(server.Client().Transport))
	_, err := client.RepoInfo(context.Background(), RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"})
	var upstream *Error
	if !errors.As(err, &upstream) || upstream.Code != CodeRateLimited || upstream.RetryAfterSeconds != 17 || strings.Contains(err.Error(), "token") {
		t.Fatalf("error = %#v (%v)", upstream, err)
	}
}

func TestTypedClientDistinguishesReadFailureFromAmbiguousMutation(t *testing.T) {
	client, _ := New("http://127.0.0.1:1", "secret", WithTimeout(10*time.Millisecond))
	ref := RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}
	_, err := client.RepoInfo(context.Background(), ref)
	var upstream *Error
	if !errors.As(err, &upstream) || upstream.Code != CodeUnavailable || upstream.Ambiguous {
		t.Fatalf("read error = %#v (%v)", upstream, err)
	}
	err = client.DeleteRepo(context.Background(), ref)
	if !errors.As(err, &upstream) || upstream.Code != CodeResultUnknown || !upstream.Ambiguous {
		t.Fatalf("mutation error = %#v (%v)", upstream, err)
	}
}

func TestTypedClientTreatsInvalidMutationResponseAsAmbiguous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()
	client, _ := New(server.URL, "secret", WithHTTPTransport(server.Client().Transport))
	var output map[string]any
	err := client.call(t.Context(), callSpec{method: http.MethodPost, path: "/mutation", out: &output})
	var upstream *Error
	if !errors.As(err, &upstream) || upstream.Code != CodeResultUnknown || !upstream.Ambiguous || upstream.Definitive() {
		t.Fatalf("mutation response error = %#v (%v)", upstream, err)
	}
}

func TestTypedClientTreatsInvalidReadResponseAsDefinitive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()
	client, _ := New(server.URL, "secret", WithHTTPTransport(server.Client().Transport))
	var output map[string]any
	err := client.call(t.Context(), callSpec{method: http.MethodGet, path: "/read", out: &output})
	var upstream *Error
	if !errors.As(err, &upstream) || upstream.Code != CodeResponseInvalid || upstream.Ambiguous || !upstream.Definitive() {
		t.Fatalf("read response error = %#v (%v)", upstream, err)
	}
}

func TestTypedClientRejectsUnsafeInputs(t *testing.T) {
	if _, err := New("https://user@example.com", "secret"); err == nil {
		t.Fatal("credentialed endpoint accepted")
	}
	client, _ := New("https://huggingface.co", "secret")
	for _, ref := range []RepoRef{
		{Type: "other", Owner: "acme", Name: "demo"},
		{Type: RepoTypeModel, Owner: "../acme", Name: "demo"},
		{Type: RepoTypeModel, Owner: "acme", Name: "bad/name"},
	} {
		if _, err := client.RepoInfo(context.Background(), ref); err == nil {
			t.Fatalf("unsafe ref accepted: %+v", ref)
		}
	}
}
