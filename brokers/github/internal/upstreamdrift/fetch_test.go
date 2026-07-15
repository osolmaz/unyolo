package upstreamdrift

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestFetchCurrentUsesVerifiedBoundedSources(t *testing.T) {
	const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Date(2026, 7, 15, 2, 3, 4, 0, time.UTC)
	requests := 0
	client := NewClient("secret-token")
	client.now = func() time.Time { return now }
	client.http = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Host == "api.github.com" && request.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("API request omitted bearer authentication")
		}
		if request.URL.Host == "raw.githubusercontent.com" && request.Header.Get("Authorization") != "" {
			t.Errorf("raw request received bearer authentication")
		}
		return fixtureResponse(request, commit), nil
	})}

	set, err := client.FetchCurrent(t.Context(), []byte("query { __schema { types { name } } }"))
	if err != nil {
		t.Fatal(err)
	}
	if requests != 9 || len(set.Sources) != 4 || len(set.REST) == 0 || len(set.GraphQL) == 0 || len(set.Permissions) == 0 || strings.Join(set.APIVersions, ",") != "2022-11-28,2026-03-10" {
		t.Fatalf("requests=%d set=%+v", requests, set)
	}
	for _, source := range set.Sources {
		if source.SHA256 == "" || !source.RetrievedAt.Equal(now) {
			t.Fatalf("unverified source: %+v", source)
		}
	}
}

func fixtureResponse(request *http.Request, commit string) *http.Response {
	path := request.URL.Path
	var body string
	switch {
	case strings.Contains(path, "/contents/descriptions/api.github.com"):
		body = `[{"name":"api.github.com.2026-03-10.json","type":"file"}]`
	case strings.Contains(path, "/contents/src/github-apps/data"):
		body = `[{"name":"fpt-2026-03-10","type":"dir"}]`
	case strings.HasSuffix(path, "/commits"):
		body = `[{"sha":"` + commit + `"}]`
	case strings.HasSuffix(path, "api.github.com.2026-03-10.json"):
		body = `{"paths":{"/repos":{"get":{"operationId":"repos/list","responses":{"200":{}}}}}}`
	case strings.HasSuffix(path, "server-to-server-permissions.json"):
		body = permissionFixture("GET", "/repos", "contents", "read")
	case strings.HasSuffix(path, "rest-api-versions.yml"):
		body = "versions:\n  '2022-11-28': {}\n  '2026-03-10': {}\n"
	case path == "/graphql":
		body = graphqlFixture("viewer", false, "String")
	default:
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("not found"))}
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestLoadPinnedVerifiesReviewedSnapshots(t *testing.T) {
	set, err := LoadPinned(filepath.Join("..", "upstream", "snapshots"))
	if err != nil || !completeSnapshot(set) || len(set.Sources) != 4 {
		t.Fatalf("LoadPinned() = %+v, %v", set, err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, provenanceFileName), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinned(directory); err == nil {
		t.Fatal("invalid provenance accepted")
	}
}

func TestClientRejectsInvalidSourcesAndResponses(t *testing.T) {
	if _, err := (*Client)(nil).FetchCurrent(t.Context(), nil); err == nil {
		t.Fatal("nil client accepted")
	}
	client := NewClient("")
	if _, _, err := client.fetchGraphQL(t.Context(), []byte("query {}"), time.Now()); err == nil {
		t.Fatal("missing token accepted")
	}
	if _, err := allowedSource("http://api.github.com/meta"); err == nil {
		t.Fatal("plaintext source accepted")
	}
	if _, err := readResponse(nil); err == nil {
		t.Fatal("nil response accepted")
	}
	response := &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader("secret upstream error"))}
	if _, err := readResponse(response); err == nil || strings.Contains(err.Error(), "secret upstream") {
		t.Fatalf("unsafe HTTP error = %v", err)
	}
	client.http = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network unavailable")
	})}
	if _, err := client.request(context.Background(), http.MethodGet, githubAPI+"/meta", nil, ""); err == nil {
		t.Fatal("transport error ignored")
	}
}

func TestFetchCurrentPropagatesSourceFailures(t *testing.T) {
	for name, failAt := range map[string]int{"rest": 1, "permissions": 4} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			client := NewClient("token")
			client.http = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if calls == failAt {
					return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
				}
				return fixtureResponse(request, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), nil
			})}
			if _, err := client.FetchCurrent(t.Context(), []byte("query {}")); err == nil {
				t.Fatal("source failure ignored")
			}
		})
	}
}

func TestVersionSelectionAndExtraction(t *testing.T) {
	entries := []remoteEntry{{Name: "api.github.com.2022-11-28.json", Type: "file"}, {Name: "api.github.com.2026-03-10.json", Type: "file"}, {Name: "api.github.com.json", Type: "file"}}
	name, version, err := latestVersionedEntry(entries, restVersionName, "file")
	if err != nil || name != "api.github.com.2026-03-10.json" || version != "2026-03-10" {
		t.Fatalf("latestVersionedEntry() = %q, %q, %v", name, version, err)
	}
	versions := extractVersions([]byte("versions:\n  '2022-11-28': {}\n  2026-03-10: {}\n  '2026-03-10': {}"))
	if strings.Join(versions, ",") != "2022-11-28,2026-03-10" {
		t.Fatalf("versions = %v", versions)
	}
	if _, _, err := latestVersionedEntry(nil, restVersionName, "file"); err == nil {
		t.Fatal("missing version accepted")
	}
}

func TestBoundedReaderAndIdentityValidation(t *testing.T) {
	if _, err := readBounded(bytes.NewReader(make([]byte, maxMetadataBytes+1))); err == nil {
		t.Fatal("oversized metadata accepted")
	}
	if !validRelativePath("nested/file.json") || validRelativePath("../file.json") || validRelativePath("/file.json") {
		t.Fatal("relative path validation drifted")
	}
	if !validDigest(strings.Repeat("a", 64)) || validDigest("short") {
		t.Fatal("digest validation drifted")
	}
}
