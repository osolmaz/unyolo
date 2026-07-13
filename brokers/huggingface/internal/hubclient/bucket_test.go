package hubclient

import (
	"context"
	"encoding/json"
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
