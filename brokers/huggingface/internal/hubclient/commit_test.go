package hubclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCommitClientUsesPinnedTypedRoutes(t *testing.T) {
	hash := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/models/acme/demo/revision/main":
			_, _ = io.WriteString(w, `{"id":"acme/demo","sha":"abc1234","private":false,"gated":false}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/models/acme/demo/paths-info/main":
			_, _ = io.WriteString(w, `[{"type":"file","oid":"blob","size":4,"path":"src.bin","xetHash":"`+hash+`","lfs":{"sha256":"`+hash+`"}}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/acme/demo/resolve/main/src.txt":
			_, _ = io.WriteString(w, "data")
		case r.Method == http.MethodPost && r.URL.Path == "/api/models/acme/demo/lfs-files/duplicate":
			_, _ = io.WriteString(w, `{"success":true,"processed":1,"succeeded":1,"failed":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/models/acme/demo/commit/main":
			if r.Header.Get("Content-Type") != "application/x-ndjson" || r.URL.Query().Get("create_pr") != "1" {
				t.Fatalf("commit headers/query = %q %q", r.Header.Get("Content-Type"), r.URL.RawQuery)
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"key":"header"`) || !strings.Contains(string(body), `"key":"file"`) || strings.Contains(string(body), "token") {
				t.Fatalf("commit body = %s", body)
			}
			_, _ = io.WriteString(w, `{"commitUrl":"https://huggingface.co/acme/demo/commit/abcdef1","commitOid":"abcdef1","pullRequestUrl":"https://huggingface.co/acme/demo/discussions/1"}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	ref := RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}
	if info, err := client.RepoInfoRevision(context.Background(), ref, "main"); err != nil || info.SHA != "abc1234" {
		t.Fatalf("RepoInfoRevision() = %#v, %v", info, err)
	}
	paths, err := client.RepoPathsInfo(context.Background(), ref, "main", []string{"src.bin"})
	if err != nil || len(paths) != 1 || paths[0].LFSSHA != hash {
		t.Fatalf("RepoPathsInfo() = %#v, %v", paths, err)
	}
	if content, err := client.ReadRepoFile(context.Background(), ref, "main", "src.txt"); err != nil || string(content) != "data" {
		t.Fatalf("ReadRepoFile() = %q, %v", content, err)
	}
	if err := client.DuplicateLFSFile(context.Background(), ref, ref, paths[0]); err != nil {
		t.Fatal(err)
	}
	result, err := client.CreateCommit(context.Background(), CommitRequest{Ref: ref, Revision: "main", Summary: "update", CreatePR: true,
		Operations: []CommitOperation{{Kind: CommitFile, Path: "file.txt", Content: []byte("data")}}})
	if err != nil || result.CommitOID != "abcdef1" {
		t.Fatalf("CreateCommit() = %#v, %v", result, err)
	}
}

func TestCommitClientRejectsInvalidPlansAndUntrustedRedirects(t *testing.T) {
	ref := RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}
	if err := ValidateCommitOperations([]CommitOperation{{Kind: CommitFile, Path: "../secret", Content: []byte("x")}}); err == nil {
		t.Fatal("unsafe path accepted")
	}
	if err := ValidateCommitOperations([]CommitOperation{{Kind: CommitDeletedFile, Path: "same"}, {Kind: CommitDeletedFile, Path: "same"}}); err == nil {
		t.Fatal("duplicate path accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://attacker.example/secret")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	if _, err := client.ReadRepoFile(context.Background(), ref, "main", "file"); err == nil {
		t.Fatal("untrusted content redirect accepted")
	}
}

func TestReadRepoFileAppliesClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport), WithTimeout(20*time.Millisecond))
	started := time.Now()
	_, err := client.ReadRepoFile(context.Background(), RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}, "main", "file")
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("ReadRepoFile timeout error = %v after %s", err, time.Since(started))
	}
}

func TestCommitClientEncodesEveryOperationKind(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/spaces/acme/demo/commit/main" || r.URL.Query().Get("hot_reload") != "1" {
			t.Fatalf("request = %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		body, _ := io.ReadAll(r.Body)
		for _, key := range []string{`"parentCommit"`, `"key":"file"`, `"key":"lfsFile"`, `"key":"deletedFile"`, `"key":"deletedFolder"`} {
			if !strings.Contains(string(body), key) {
				t.Fatalf("commit body does not contain %s: %s", key, body)
			}
		}
		_, _ = io.WriteString(w, `{"commitUrl":"https://huggingface.co/spaces/acme/demo/commit/abcdef1","commitOid":"abcdef1"}`)
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	request := CommitRequest{Ref: RepoRef{Type: RepoTypeSpace, Owner: "acme", Name: "demo"}, Revision: "main", Summary: "all operations",
		Description: "exercise each typed NDJSON entry", ParentCommit: "abcdef1", HotReload: true,
		Operations: []CommitOperation{
			{Kind: CommitFile, Path: "file.txt", Content: []byte("data")},
			{Kind: CommitLFSFile, Path: "large.bin", OID: hash, Size: 10},
			{Kind: CommitDeletedFile, Path: "old.txt"},
			{Kind: CommitDeletedFolder, Path: "old/"},
		}}
	if _, err := client.CreateCommit(t.Context(), request); err != nil {
		t.Fatal(err)
	}
}

func TestCommitValidationRejectsEveryMalformedShape(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("a", 64)
	valid := CommitOperation{Kind: CommitFile, Path: "file.txt", Content: []byte("data")}
	invalidOperations := [][]CommitOperation{
		nil,
		make([]CommitOperation, maxCommitOperations+1),
		{{Kind: CommitFile, Path: "file.txt"}},
		{{Kind: CommitFile, Path: "file.txt", Content: []byte("data"), OID: hash}},
		{{Kind: CommitLFSFile, Path: "large.bin", Content: []byte("data"), OID: hash}},
		{{Kind: CommitLFSFile, Path: "large.bin", OID: "bad", Size: 1}},
		{{Kind: CommitLFSFile, Path: "large.bin", OID: hash, Size: -1}},
		{{Kind: CommitDeletedFile, Path: "old.txt", Content: []byte("data")}},
		{{Kind: CommitDeletedFolder, Path: "old", Size: 1}},
		{{Kind: "unknown", Path: "file.txt"}},
	}
	for _, operations := range invalidOperations {
		if err := ValidateCommitOperations(operations); err == nil {
			t.Fatalf("ValidateCommitOperations(%#v) succeeded", operations)
		}
	}
	if err := ValidateCommitOperations([]CommitOperation{valid}); err != nil {
		t.Fatalf("ValidateCommitOperations(valid) = %v", err)
	}

	client, _ := New("https://huggingface.co", "token")
	base := CommitRequest{Ref: RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}, Revision: "main", Summary: "update", Operations: []CommitOperation{valid}}
	mutations := []func(*CommitRequest){
		func(request *CommitRequest) { request.Ref.Owner = "bad/name" },
		func(request *CommitRequest) { request.Revision = "bad ref" },
		func(request *CommitRequest) { request.Summary = " " },
		func(request *CommitRequest) { request.Summary = strings.Repeat("x", 501) },
		func(request *CommitRequest) { request.Description = strings.Repeat("x", 10_001) },
		func(request *CommitRequest) { request.ParentCommit = "bad" },
		func(request *CommitRequest) { request.HotReload = true },
	}
	for _, mutate := range mutations {
		request := base
		mutate(&request)
		if _, err := client.CreateCommit(t.Context(), request); err == nil {
			t.Fatalf("CreateCommit(%#v) succeeded", request)
		}
	}
}

func TestCommitReadAndMetadataResponseValidation(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/models/acme/demo/revision/main":
			_, _ = io.WriteString(w, `{"id":"other/repo","sha":""}`)
		case "/api/models/acme/demo/paths-info/main":
			_, _ = io.WriteString(w, `[{"type":"file","oid":"","size":-1,"path":"../bad"}]`)
		case "/api/models/acme/demo/lfs-files/duplicate":
			_, _ = io.WriteString(w, `{"success":false,"processed":1,"succeeded":0,"failed":["large.bin"]}`)
		case "/acme/demo/resolve/main/missing.txt":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	ref := RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}
	if _, err := client.RepoInfoRevision(t.Context(), ref, "main"); err == nil {
		t.Fatal("RepoInfoRevision accepted invalid identity")
	}
	if _, err := client.RepoPathsInfo(t.Context(), ref, "main", []string{"file.txt"}); err == nil {
		t.Fatal("RepoPathsInfo accepted invalid item")
	}
	if _, err := client.ReadRepoFile(t.Context(), ref, "main", "missing.txt"); err == nil {
		t.Fatal("ReadRepoFile accepted missing file")
	}
	info := RepoPathInfo{Path: "large.bin", XetHash: hash, LFSSHA: hash}
	if err := client.DuplicateLFSFile(t.Context(), ref, ref, info); err == nil {
		t.Fatal("DuplicateLFSFile accepted failed batch")
	}
	for _, invalid := range []RepoPathInfo{
		{Path: "../bad", XetHash: hash, LFSSHA: hash},
		{Path: "large.bin", XetHash: "bad", LFSSHA: hash},
		{Path: "large.bin", XetHash: hash, LFSSHA: "bad"},
	} {
		if err := client.DuplicateLFSFile(t.Context(), ref, ref, invalid); err == nil {
			t.Fatalf("DuplicateLFSFile(%#v) succeeded", invalid)
		}
	}
	for _, paths := range [][]string{nil, {"../bad"}, make([]string, 501)} {
		if _, err := client.RepoPathsInfo(t.Context(), ref, "main", paths); err == nil {
			t.Fatalf("RepoPathsInfo(%#v) succeeded", paths)
		}
	}
	if _, err := client.RepoInfoRevision(t.Context(), ref, "bad ref"); err == nil {
		t.Fatal("RepoInfoRevision accepted invalid revision")
	}
	if _, err := client.ReadRepoFile(t.Context(), ref, "bad ref", "file.txt"); err == nil {
		t.Fatal("ReadRepoFile accepted invalid revision")
	}
}
