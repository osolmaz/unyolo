package hfgrant

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/state"
)

func TestCanonicalRequestRoundTrip(t *testing.T) {
	store, plans := mustStores(t)
	result, created, err := Request(store, plans, Input{
		Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force", Mode: ModeWindow,
		Target: "model/owner/repo", Ref: "refs/heads/main", Attrs: map[string]any{"max_bytes": int64(42)},
		Reason: "test", RequestedDuration: 5 * time.Minute, MaxUses: 1,
	})
	if err != nil || !created {
		t.Fatalf("Request() = %+v, %v, %v", result, created, err)
	}
	attrs, err := Attrs(result.Grant)
	if err != nil || attrs["max_bytes"] != int64(42) || Target(result.Grant) != "model/owner/repo" || Ref(result.Grant) != "refs/heads/main" {
		t.Fatalf("round trip = %+v, %v", attrs, err)
	}
}

func TestCanonicalRequestPreservesExactProviderTarget(t *testing.T) {
	target := hfpolicy.Target{Kind: hfpolicy.KindBucket, Owner: "acme", Name: "artifacts", Keys: []string{"runs/one.json"}}
	request, err := CanonicalRequest(Input{Client: "bob", ClientRequestID: "bucket-1", Operation: "bucket.object.read",
		PolicyTarget: &target, Reason: "inspect result", RequestedDuration: time.Minute, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	stored := grants.Grant{Operation: "bucket.object.read", Target: request.Target}
	decoded, err := PolicyTarget(stored)
	if err != nil || decoded.Kind != hfpolicy.KindBucket || decoded.Owner != "acme" || decoded.Name != "artifacts" ||
		len(decoded.Keys) != 1 || decoded.Keys[0] != "runs/one.json" || Target(stored) != "bucket/acme/artifacts" {
		t.Fatalf("provider target round trip = %#v, %v", decoded, err)
	}
}

func TestCanonicalRequestRejectsInvalidBounds(t *testing.T) {
	input := Input{Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force", Target: "model/owner/repo", Reason: "test", RequestedDuration: MaxDuration + time.Minute}
	if _, err := CanonicalRequest(input); err == nil {
		t.Fatal("CanonicalRequest() accepted excessive duration")
	}
}

func TestCanonicalRequestValidation(t *testing.T) {
	valid := Input{Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force", Target: "model/owner/repo", Reason: "test"}
	invalid := []Input{
		{Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason},
		{Client: valid.Client, Target: valid.Target, Reason: valid.Reason},
		{Client: valid.Client, Operation: valid.Operation, Reason: valid.Reason},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: strings.Repeat("r", 513)},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason, ClientRequestID: "bad id"},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason, ClientRequestID: strings.Repeat("i", 129)},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason, Mode: "invalid"},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason, RequestedDuration: time.Second},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason, MaxUses: -1},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason, MaxUses: MaxUses + 1},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason, Mode: ModeExecution, MaxUsesSpecified: true},
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason, Attrs: map[string]any{"bad": func() {}}},
	}
	for index, input := range invalid {
		if _, err := CanonicalRequest(input); err == nil {
			t.Fatalf("CanonicalRequest(invalid[%d]) unexpectedly succeeded", index)
		}
	}
	request, err := CanonicalRequest(Input{
		Client: valid.Client, ClientRequestID: valid.ClientRequestID, Operation: valid.Operation, Target: valid.Target, Reason: "  test  ",
		Mode: ModeExecution, RequestedDuration: 2 * time.Minute, MaxUses: 1,
	})
	if err != nil || request.Reason != "test" || request.Metadata[metadataMode] != ModeExecution || request.Duration != 2*time.Minute || request.MaxUses != 1 {
		t.Fatalf("CanonicalRequest(valid) = %+v, %v", request, err)
	}
}

func TestStoredGrantAccessorsAndMatching(t *testing.T) {
	store, plans := mustStores(t)
	result, _, err := Request(store, plans, Input{
		Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force", Target: "model/owner/repo", Ref: "refs/heads/main",
		Reason: "test", RequestedDuration: 3 * time.Minute, MaxUses: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if Mode(result.Grant) != ModeWindow || RequestedMinutes(result.Grant) != 3 {
		t.Fatalf("grant accessors = mode %q minutes %d", Mode(result.Grant), RequestedMinutes(result.Grant))
	}
	if _, err := GetForClient(store, "alice", result.Grant.ID); err == nil {
		t.Fatal("GetForClient() returned another client's grant")
	}
	if _, err := GetForClient(store, "bob", "missing"); err == nil {
		t.Fatal("GetForClient() returned a missing grant")
	}
	approved, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, err := MatchActiveFunc(store, "bob", approved.Operation, Target(approved), Ref(approved), nil); err != nil || !ok || got.ID != approved.ID {
		t.Fatalf("MatchActiveFunc() = %+v, %v, %v", got, ok, err)
	}
	if _, ok, err := MatchActiveFunc(store, "bob", approved.Operation, Target(approved), Ref(approved), func(grants.Grant) bool { return false }); err != nil || ok {
		t.Fatalf("MatchActiveFunc(rejected) = %v, %v", ok, err)
	}
}

func TestRequestRetryReusesImmutablePlanAcrossRestart(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state")
	input := Input{Client: "bob", ClientRequestID: "retry-1", Operation: "git.push.force", Mode: ModeWindow,
		Target: "dataset/acme/demo", Ref: "refs/heads/main", Reason: "repair", RequestedDuration: time.Minute, MaxUses: 1}
	firstDatabase, err := state.Open(t.Context(), statePath, state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	firstPlans, err := hfplan.NewStore(firstDatabase)
	if err != nil {
		t.Fatal(err)
	}
	first, created, err := Request(grants.NewDatabase(firstDatabase, grants.Options{}), firstPlans, input)
	if err != nil || !created {
		t.Fatalf("first Request() = %+v, %v, %v", first, created, err)
	}
	if err := firstDatabase.Close(); err != nil {
		t.Fatal(err)
	}
	secondDatabase, err := state.Open(t.Context(), statePath, state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondDatabase.Close() })
	secondPlans, err := hfplan.NewStore(secondDatabase)
	if err != nil {
		t.Fatal(err)
	}
	secondStore := grants.NewDatabase(secondDatabase, grants.Options{})
	second, created, err := Request(secondStore, secondPlans, input)
	if err != nil || created || second.Grant.ID != first.Grant.ID || second.Grant.Metadata[hfplan.MetadataDigest] != first.Grant.Metadata[hfplan.MetadataDigest] {
		t.Fatalf("retry Request() = %+v, %v, %v", second, created, err)
	}
	input.Target = "dataset/acme/other"
	if _, _, err := Request(secondStore, secondPlans, input); !errors.Is(err, grants.ErrIdempotencyConflict) {
		t.Fatalf("changed retry error = %v", err)
	}
}

func mustStores(t *testing.T) (*grants.Store, *hfplan.Store) {
	t.Helper()
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	plans, err := hfplan.NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	return grants.NewDatabase(database, grants.Options{}), plans
}

func TestAttrsRejectMalformedStoredValues(t *testing.T) {
	for _, attrs := range []map[string][]string{
		{"bad": {"one", "two"}},
		{"bad": {"{"}},
		{"bad": {`1 {}`}},
		{"bad": {`{"key":1,"key":2}`}},
	} {
		if _, err := Attrs(grants.Grant{Attrs: attrs}); err == nil {
			t.Fatalf("Attrs(%v) unexpectedly succeeded", attrs)
		}
	}
	if attrs, err := Attrs(grants.Grant{}); err != nil || attrs != nil {
		t.Fatalf("Attrs(empty) = %v, %v", attrs, err)
	}
}
