package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBucketClientUsesPinnedNDJSONAndMoveRoutes(t *testing.T) {
	hash := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatal("missing broker credential")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/buckets/acme/source":
			_, _ = io.WriteString(w, `{"id":"acme/source","private":true,"updatedAt":"now","size":4,"totalFiles":1}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/buckets/acme/source/batch":
			if r.Header.Get("Content-Type") != "application/x-ndjson" {
				t.Fatalf("content type = %q", r.Header.Get("Content-Type"))
			}
			body, _ := io.ReadAll(r.Body)
			want := `{"type":"copyFile","path":"new/file","xetHash":"` + hash + `","sourceRepoType":"model","sourceRepoId":"acme/model"}` + "\n" +
				`{"type":"deleteFile","path":"old/file"}` + "\n"
			if string(body) != want {
				t.Fatalf("batch body = %q, want %q", body, want)
			}
			_, _ = io.WriteString(w, `{"success":true,"processed":2,"succeeded":2,"failed":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/repos/move":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["fromRepo"] != "acme/source" || body["toRepo"] != "acme/destination" || body["type"] != "bucket" {
				t.Fatalf("move body = %#v, err=%v", body, err)
			}
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	ref := BucketRef{Namespace: "acme", Name: "source"}
	if info, err := client.BucketInfo(context.Background(), ref); err != nil || info.ID != "acme/source" {
		t.Fatalf("BucketInfo() = %#v, %v", info, err)
	}
	operations := []BucketBatchOperation{
		{Type: "copyFile", Path: "new/file", XetHash: hash, SourceRepoType: "model", SourceRepoID: "acme/model"},
		{Type: "deleteFile", Path: "old/file"},
	}
	if err := client.ApplyBucketBatch(context.Background(), ref, operations); err != nil {
		t.Fatal(err)
	}
	if err := client.MoveBucket(context.Background(), ref, BucketRef{Namespace: "acme", Name: "destination"}); err != nil {
		t.Fatal(err)
	}
}

func TestBucketClientReadsBoundedBucketData(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("c", 64)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/content" {
			if r.Header.Get("Authorization") != "" {
				t.Fatal("broker credential reached content redirect")
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "artifact")
			return
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatal("missing broker credential")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/buckets/acme":
			if r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("search") != "art" {
				t.Fatalf("bucket query = %s", r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, `[{"id":"acme/artifacts","private":true,"createdAt":"2026-01-01T00:00:00Z","size":8,"totalFiles":1}]`)
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/api/buckets/acme/artifacts/tree/runs%2F":
			_, _ = io.WriteString(w, `[{"type":"file","path":"runs/result.txt","size":8,"xetHash":"`+hash+`"}]`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/buckets/acme/artifacts/paths-info":
			_, _ = io.WriteString(w, `[{"type":"file","path":"runs/result.txt","size":8,"xetHash":"`+hash+`"}]`)
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/buckets/acme/artifacts/resolve/runs%2Fresult.txt":
			http.Redirect(w, r, server.URL+"/content", http.StatusTemporaryRedirect)
		default:
			t.Fatalf("unexpected request: %s %s (%s)", r.Method, r.URL.Path, r.URL.EscapedPath())
		}
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	client.maxResponseBytes = 128
	ref := BucketRef{Namespace: "acme", Name: "artifacts"}
	if values, err := client.ListBuckets(t.Context(), "acme", "art", 2); err != nil || len(values) != 1 {
		t.Fatalf("ListBuckets() = %#v, %v", values, err)
	}
	if values, err := client.ListBucketTree(t.Context(), ref, "runs/", true, 10); err != nil || len(values) != 1 || values[0].XetHash != hash {
		t.Fatalf("ListBucketTree() = %#v, %v", values, err)
	}
	if value, err := client.BucketObjectInfo(t.Context(), ref, "runs/result.txt"); err != nil || value.Size != 8 {
		t.Fatalf("BucketObjectInfo() = %#v, %v", value, err)
	}
	if value, err := client.ReadBucketObject(t.Context(), ref, "runs/result.txt"); err != nil || string(value.Content) != "artifact" || value.ContentType != "text/plain" {
		t.Fatalf("ReadBucketObject() = %#v, %v", value, err)
	}
}

func TestBucketClientRejectsUnsafeOrAmbiguousBatches(t *testing.T) {
	hash := strings.Repeat("b", 64)
	tests := [][]BucketBatchOperation{
		nil,
		{{Type: "deleteFile", Path: "../secret"}},
		{{Type: "deleteFile", Path: "old"}, {Type: "copyFile", Path: "new", XetHash: hash, SourceRepoType: "bucket", SourceRepoID: "acme/source"}},
		{{Type: "addFile", Path: "new", XetHash: "not-a-hash", MTime: 1}},
		{{Type: "copyFile", Path: "new", XetHash: hash, SourceRepoType: "shell", SourceRepoID: "acme/source"}},
	}
	for _, operations := range tests {
		if err := ValidateBucketBatchOperations(operations); err == nil {
			t.Fatalf("invalid operations accepted: %#v", operations)
		}
	}
	if err := (BucketRef{Namespace: "acme", Name: "../source"}).Validate(); err == nil {
		t.Fatal("unsafe bucket name accepted")
	}
}

func TestValidBucketTreeEntryType(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("a", 64)
	for name, entry := range map[string]BucketTreeEntry{
		"file":              {Type: "file", XetHash: hash},
		"directory":         {Type: "directory"},
		"invalid file":      {Type: "file", XetHash: "invalid"},
		"invalid directory": {Type: "directory", XetHash: hash},
		"unknown":           {Type: "symlink"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := name == "file" || name == "directory"
			if got := validBucketTreeEntryType(entry); got != want {
				t.Fatalf("validBucketTreeEntryType(%+v) = %v, want %v", entry, got, want)
			}
		})
	}
}

func TestBucketClientTreatsPartialBatchResultAsAmbiguous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"success":false,"processed":1,"succeeded":1,"failed":[{"path":"second"}]}`)
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	err := client.ApplyBucketBatch(context.Background(), BucketRef{Namespace: "acme", Name: "source"}, []BucketBatchOperation{{Type: "deleteFile", Path: "first"}, {Type: "deleteFile", Path: "second"}})
	var upstream *Error
	if !errors.As(err, &upstream) || upstream.Code != CodeResultUnknown || !upstream.Ambiguous || upstream.Definitive() {
		t.Fatalf("ApplyBucketBatch() error = %#v", err)
	}
}
