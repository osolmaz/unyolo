package operations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/authorization/grants"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/internal/storage/stream"
)

type bucketFake struct {
	identity string
	infos    map[string]hubclient.BucketInfo
	tree     []hubclient.BucketTreeEntry
	object   hubclient.BucketObject
	batches  [][]hubclient.BucketBatchOperation
	moves    [][2]hubclient.BucketRef
}

func (f *bucketFake) WhoAmI(context.Context) (hubclient.Identity, error) {
	return hubclient.Identity{Name: f.identity}, nil
}

func (f *bucketFake) BucketInfo(_ context.Context, ref hubclient.BucketRef) (hubclient.BucketInfo, error) {
	info, found := f.infos[ref.ID()]
	if !found {
		return hubclient.BucketInfo{}, &hubclient.Error{Code: hubclient.CodeNotFound, StatusCode: http.StatusNotFound}
	}
	return info, nil
}

func (f *bucketFake) ListBuckets(_ context.Context, namespace, search string, limit int) ([]hubclient.BucketInfo, error) {
	result := make([]hubclient.BucketInfo, 0, len(f.infos))
	for _, info := range f.infos {
		if strings.HasPrefix(info.ID, namespace+"/") && strings.Contains(info.ID, search) && len(result) < limit {
			result = append(result, info)
		}
	}
	return result, nil
}

func (f *bucketFake) ListBucketTree(context.Context, hubclient.BucketRef, string, bool, int) ([]hubclient.BucketTreeEntry, error) {
	return f.tree, nil
}

func (f *bucketFake) BucketObjectInfo(_ context.Context, _ hubclient.BucketRef, path string) (hubclient.BucketTreeEntry, error) {
	for _, entry := range f.tree {
		if entry.Path == path {
			return entry, nil
		}
	}
	return hubclient.BucketTreeEntry{}, &hubclient.Error{Code: hubclient.CodeNotFound, StatusCode: http.StatusNotFound}
}

func (f *bucketFake) ReadBucketObject(_ context.Context, _ hubclient.BucketRef, path string) (hubclient.BucketObject, error) {
	if f.object.Path != path {
		return hubclient.BucketObject{}, &hubclient.Error{Code: hubclient.CodeNotFound, StatusCode: http.StatusNotFound}
	}
	return f.object, nil
}

func (f *bucketFake) OpenBucketObject(_ context.Context, _ hubclient.BucketRef, path string) (hubclient.BucketObjectReader, error) {
	if f.object.Path != path {
		return hubclient.BucketObjectReader{}, &hubclient.Error{Code: hubclient.CodeNotFound, StatusCode: http.StatusNotFound}
	}
	return hubclient.BucketObjectReader{Body: io.NopCloser(strings.NewReader(string(f.object.Content))), Size: int64(len(f.object.Content)), ContentType: f.object.ContentType}, nil
}

func (f *bucketFake) ApplyBucketBatch(_ context.Context, _ hubclient.BucketRef, operations []hubclient.BucketBatchOperation) error {
	f.batches = append(f.batches, operations)
	return nil
}

func (f *bucketFake) MoveBucket(_ context.Context, from, to hubclient.BucketRef) error {
	f.moves = append(f.moves, [2]hubclient.BucketRef{from, to})
	delete(f.infos, from.ID())
	f.infos[to.ID()] = hubclient.BucketInfo{ID: to.ID(), UpdatedAt: "later"}
	return nil
}

func TestBucketAdaptersExecuteTypedOperations(t *testing.T) {
	hash := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		arguments json.RawMessage
	}{
		{"bucket.batch.apply", json.RawMessage(`{"operations":[{"type":"copyFile","path":"copy.bin","xetHash":"` + hash + `","sourceRepoType":"model","sourceRepoId":"acme/model"}]}`)},
		{"bucket.sync.apply", json.RawMessage(`{"operations":[{"type":"deleteFile","path":"stale.bin"}]}`)},
		{"bucket.object.delete", json.RawMessage(`{"path":"obsolete.bin"}`)},
		{"bucket.move", json.RawMessage(`{"to_namespace":"acme","to_name":"renamed"}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &bucketFake{identity: "operator", infos: map[string]hubclient.BucketInfo{
				"acme/data": {ID: "acme/data", UpdatedAt: "now", Size: 1, TotalFiles: 1},
			}}
			adapters, err := NewBucketAdapters(client)
			if err != nil {
				t.Fatal(err)
			}
			registry, _ := NewRegistry(adapters...)
			adapter, _ := registry.Lookup(test.name)
			input, err := adapter.Decode(json.RawMessage(`{"kind":"bucket","namespace":"acme","name":"data"}`), test.arguments)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := adapter.Resolve(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			assertPlanReconstruction(t, adapter, plan)
			if test.name == "bucket.move" {
				if plan.Policy.Attrs["destination"] != "acme/renamed" {
					t.Fatalf("move policy attrs = %#v", plan.Policy.Attrs)
				}
			} else if len(plan.Policy.Target.Keys) != 1 {
				t.Fatalf("bucket policy target = %#v", plan.Policy.Target)
			}
			outcome, err := adapter.Execute(context.Background(), plan)
			if err != nil || !outcome.Proven {
				t.Fatalf("Execute() = %#v, %v", outcome, err)
			}
			if test.name == "bucket.move" {
				reconciled, reconcileErr := adapter.Reconcile(context.Background(), plan)
				if reconcileErr != nil || !reconciled.Proven || len(client.moves) != 1 {
					t.Fatalf("move reconcile = %#v, %v; calls=%d", reconciled, reconcileErr, len(client.moves))
				}
			} else if len(client.batches) != 1 {
				t.Fatalf("batch calls = %d", len(client.batches))
			}
		})
	}
}

func TestBucketReadAdaptersFilterDiscoveryAndReadExactObjects(t *testing.T) {
	t.Parallel()
	private := true
	hash := strings.Repeat("d", 64)
	client := &bucketFake{infos: map[string]hubclient.BucketInfo{
		"acme/artifacts": {ID: "acme/artifacts", Private: &private, Size: 7, TotalFiles: 2},
		"acme/private":   {ID: "acme/private", Private: &private},
	}, tree: []hubclient.BucketTreeEntry{
		{Type: "file", Path: "runs/result.txt", Size: 7, XetHash: hash},
		{Type: "file", Path: "secret/token.txt", Size: 6, XetHash: hash},
	}, object: hubclient.BucketObject{Path: "runs/result.txt", Content: []byte("result\n"), ContentType: "text/plain"}}
	authorize := func(_ string, operation hfpolicy.Operation, target hfpolicy.Target, _ *grants.Grant) bool {
		return target.Name != "private" && (operation != hfpolicy.OpBucketObjectList || target.Keys[0] != "secret/token.txt")
	}
	streams, err := streamstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adapters, err := NewBucketReadAdapters(client, authorize, streams, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	tests := []struct {
		name, target, arguments, contains, excludes string
	}{
		{"bucket.list", `{"kind":"bucket","namespace":"acme","name":"*"}`, `{"limit":10}`, "acme/artifacts", "acme/private"},
		{"bucket.metadata.read", `{"kind":"bucket","namespace":"acme","name":"artifacts"}`, `{}`, `"total_files":2`, "content"},
		{"bucket.object.list", `{"kind":"bucket","namespace":"acme","name":"artifacts"}`, `{"recursive":true,"limit":10}`, "runs/result.txt", "secret/token.txt"},
		{"bucket.object.read", `{"kind":"bucket","namespace":"acme","name":"artifacts"}`, `{"path":"runs/result.txt"}`, `"content":"result\n"`, "secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, _ := registry.Lookup(test.name)
			input, err := adapter.Decode(json.RawMessage(test.target), json.RawMessage(test.arguments))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := adapter.Resolve(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			plan.Policy.Client = "agent"
			outcome, err := adapter.Execute(t.Context(), plan)
			if err != nil || !outcome.Proven || !strings.Contains(string(outcome.Result), test.contains) || strings.Contains(string(outcome.Result), test.excludes) {
				t.Fatalf("Execute() = %s, %v", outcome.Result, err)
			}
		})
	}
}

func TestBucketObjectReadUsesOwnedStreamForLargeContent(t *testing.T) {
	t.Parallel()
	content := strings.Repeat("x", int(maxInlineBucketObjectBytes)+1)
	hash := strings.Repeat("f", 64)
	client := &bucketFake{infos: map[string]hubclient.BucketInfo{"acme/artifacts": {ID: "acme/artifacts"}},
		tree:   []hubclient.BucketTreeEntry{{Type: "file", Path: "large.bin", Size: int64(len(content)), XetHash: hash}},
		object: hubclient.BucketObject{Path: "large.bin", Content: []byte(content), ContentType: "application/octet-stream"}}
	streams, _ := streamstore.Open(t.TempDir())
	adapters, err := NewBucketReadAdapters(client, func(string, hfpolicy.Operation, hfpolicy.Target, *grants.Grant) bool { return true }, streams, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("bucket.object.read")
	input, _ := adapter.Decode(json.RawMessage(`{"kind":"bucket","namespace":"acme","name":"artifacts"}`), json.RawMessage(`{"path":"large.bin"}`))
	plan, _ := adapter.Resolve(t.Context(), input)
	plan.Policy.Client = "agent"
	outcome, err := adapter.Execute(t.Context(), plan)
	if err != nil || !outcome.Proven || strings.Contains(string(outcome.Result), `"content"`) {
		t.Fatalf("Execute() = %s, %v", outcome.Result, err)
	}
	var result struct {
		Stream bucketStreamReference `json:"stream"`
	}
	if json.Unmarshal(outcome.Result, &result) != nil || result.Stream.Owner != "agent" || result.Stream.Size != int64(len(content)) || streams.Validate(result.Stream.canonical()) != nil {
		t.Fatalf("stream result = %+v", result)
	}
}

func TestBucketAdaptersRejectUnknownFieldsAndStaleState(t *testing.T) {
	client := &bucketFake{identity: "operator", infos: map[string]hubclient.BucketInfo{
		"acme/data": {ID: "acme/data", UpdatedAt: "now", Size: 1},
	}}
	adapters, _ := NewBucketAdapters(client)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("bucket.object.delete")
	if _, err := adapter.Decode(json.RawMessage(`{"kind":"bucket","namespace":"acme","name":"data","url":"https://attacker"}`), json.RawMessage(`{"path":"file"}`)); err == nil {
		t.Fatal("unknown target field accepted")
	}
	input, _ := adapter.Decode(json.RawMessage(`{"kind":"bucket","namespace":"acme","name":"data"}`), json.RawMessage(`{"path":"file"}`))
	plan, _ := adapter.Resolve(context.Background(), input)
	client.infos["acme/data"] = hubclient.BucketInfo{ID: "acme/data", UpdatedAt: "changed", Size: 2}
	if _, err := adapter.Execute(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "precondition") {
		t.Fatalf("stale Execute() error = %v", err)
	}
	client.identity = "different"
	if _, err := adapter.Execute(context.Background(), plan); err == nil {
		t.Fatal("credential drift accepted")
	}
}
