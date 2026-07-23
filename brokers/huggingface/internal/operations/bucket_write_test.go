package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/xetuploader"
	"github.com/osolmaz/brokerkit/internal/storage/stream"
)

type bucketWriteFake struct {
	identity  string
	bucket    hubclient.BucketInfo
	object    *hubclient.BucketTreeEntry
	batchErr  error
	batchHits int
}

func (f *bucketWriteFake) WhoAmI(context.Context) (hubclient.Identity, error) {
	return hubclient.Identity{Name: f.identity}, nil
}

func (f *bucketWriteFake) BucketInfo(context.Context, hubclient.BucketRef) (hubclient.BucketInfo, error) {
	return f.bucket, nil
}

func (f *bucketWriteFake) BucketObjectInfo(_ context.Context, _ hubclient.BucketRef, path string) (hubclient.BucketTreeEntry, error) {
	if f.object == nil || f.object.Path != path {
		return hubclient.BucketTreeEntry{}, &hubclient.Error{Code: hubclient.CodeNotFound, StatusCode: 404}
	}
	return *f.object, nil
}

func (f *bucketWriteFake) ApplyBucketBatch(_ context.Context, _ hubclient.BucketRef, operations []hubclient.BucketBatchOperation) error {
	f.batchHits++
	operation := operations[0]
	f.object = &hubclient.BucketTreeEntry{Type: "file", Path: operation.Path, Size: 4, XetHash: operation.XetHash}
	return f.batchErr
}

type xetUploadFake struct {
	content string
	hits    int
}

func (f *xetUploadFake) Upload(_ context.Context, _ hubclient.BucketRef, file *os.File, size int64) (xetuploader.Result, error) {
	f.hits++
	content, err := io.ReadAll(file)
	if err != nil || int64(len(content)) != size {
		return xetuploader.Result{}, errors.New("invalid stream")
	}
	f.content = string(content)
	return xetuploader.Result{Hash: strings.Repeat("e", 64), Size: size}, nil
}

func TestBucketObjectWriteBindsStreamAndVerifiesReadback(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	streams, err := streamstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reference, err := streams.Put("agent", "bucket.object.write", "write-1", "application/octet-stream",
		bytes.NewReader([]byte("data")), 16, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	client := &bucketWriteFake{identity: "operator", bucket: hubclient.BucketInfo{ID: "acme/artifacts", UpdatedAt: "now"}}
	uploader := &xetUploadFake{}
	adapter, err := NewBucketObjectWriteAdapter(client, uploader, streams, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	arguments, _ := json.Marshal(map[string]any{
		"public": map[string]any{"path": "runs/result.bin"},
		"stream_input": map[string]any{
			"id": reference.ID, "owner": reference.Owner, "purpose": reference.Purpose,
			"transfer_id": reference.RequestKey, "digest": reference.Digest, "size": reference.Size,
			"media_type": reference.MediaType, "expires_at": reference.ExpiresAt,
		},
	})
	input, err := adapter.Decode(json.RawMessage(`{"kind":"bucket","namespace":"acme","name":"artifacts"}`), arguments)
	if err != nil {
		t.Fatal(err)
	}
	bound := adapter.(ClientBoundAdapter)
	if err := bound.ValidateClient(input, "agent", "write-1"); err != nil {
		t.Fatal(err)
	}
	if err := bound.ValidateClient(input, "other", "write-1"); err == nil {
		t.Fatal("cross-client stream accepted")
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	assertPlanReconstruction(t, adapter, plan)
	outcome, err := adapter.Execute(t.Context(), plan)
	if err != nil || !outcome.Proven || uploader.content != "data" || client.batchHits != 1 || !strings.Contains(string(outcome.Result), `"path":"runs/result.bin"`) {
		t.Fatalf("Execute() = %s, %v; upload=%q batches=%d", outcome.Result, err, uploader.content, client.batchHits)
	}
	if err := streams.Validate(reference); err == nil {
		t.Fatal("successful stream was not retired")
	}
}

func TestBucketObjectWriteRequiresExplicitOverwriteAndStablePreconditions(t *testing.T) {
	t.Parallel()
	now := time.Now()
	streams, _ := streamstore.Open(t.TempDir())
	reference, _ := streams.Put("agent", "bucket.object.write", "write-2", "text/plain", bytes.NewReader([]byte("data")), 16, now.Add(time.Hour))
	existing := hubclient.BucketTreeEntry{Type: "file", Path: "result.txt", Size: 3, XetHash: strings.Repeat("a", 64)}
	client := &bucketWriteFake{identity: "operator", bucket: hubclient.BucketInfo{ID: "acme/artifacts", UpdatedAt: "now"}, object: &existing}
	adapter, _ := NewBucketObjectWriteAdapter(client, &xetUploadFake{}, streams, func() time.Time { return now })
	arguments := writeArgumentsForTest(reference, "result.txt", false)
	input, _ := adapter.Decode(json.RawMessage(`{"kind":"bucket","namespace":"acme","name":"artifacts"}`), arguments)
	if _, err := adapter.Resolve(t.Context(), input); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("Resolve() error = %v", err)
	}
	input, _ = adapter.Decode(json.RawMessage(`{"kind":"bucket","namespace":"acme","name":"artifacts"}`), writeArgumentsForTest(reference, "result.txt", true))
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	client.object = &hubclient.BucketTreeEntry{Type: "file", Path: "result.txt", Size: 5, XetHash: strings.Repeat("b", 64)}
	if _, err := adapter.Execute(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "precondition") {
		t.Fatalf("Execute() error = %v", err)
	}
}

func writeArgumentsForTest(reference streamstore.Reference, path string, overwrite bool) json.RawMessage {
	value, _ := json.Marshal(map[string]any{
		"public": map[string]any{"path": path, "overwrite": overwrite},
		"stream_input": map[string]any{"id": reference.ID, "owner": reference.Owner, "purpose": reference.Purpose,
			"transfer_id": reference.RequestKey, "digest": reference.Digest, "size": reference.Size,
			"media_type": reference.MediaType, "expires_at": reference.ExpiresAt},
	})
	return value
}
