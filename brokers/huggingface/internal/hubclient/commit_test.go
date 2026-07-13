package hubclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
