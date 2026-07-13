package operations

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
)

type bucketFake struct {
	identity string
	infos    map[string]hubclient.BucketInfo
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
