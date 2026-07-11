package hfgrant

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/grants"
)

func TestCanonicalRequestRoundTrip(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	plans, _ := hfplan.NewStore(filepath.Join(t.TempDir(), "plans"))
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
		{Client: valid.Client, Operation: valid.Operation, Target: valid.Target, Reason: valid.Reason, Attrs: map[string]any{"bad": func() {}}},
	}
	for index, input := range invalid {
		if _, err := CanonicalRequest(input); err == nil {
			t.Fatalf("CanonicalRequest(invalid[%d]) unexpectedly succeeded", index)
		}
	}
	request, err := CanonicalRequest(Input{
		Client: valid.Client, ClientRequestID: valid.ClientRequestID, Operation: valid.Operation, Target: valid.Target, Reason: "  test  ",
		Mode: ModeExecution, RequestedDuration: 2 * time.Minute, MaxUses: 2,
	})
	if err != nil || request.Reason != "test" || request.Metadata[metadataMode] != ModeExecution || request.Duration != 2*time.Minute || request.MaxUses != 2 {
		t.Fatalf("CanonicalRequest(valid) = %+v, %v", request, err)
	}
}

func TestStoredGrantAccessorsAndMatching(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	plans, _ := hfplan.NewStore(filepath.Join(t.TempDir(), "plans"))
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
	grantPath := filepath.Join(directory, "grants.json")
	planPath := filepath.Join(directory, "plans")
	input := Input{Client: "bob", ClientRequestID: "retry-1", Operation: "git.push.force", Mode: ModeWindow,
		Target: "dataset/acme/demo", Ref: "refs/heads/main", Reason: "repair", RequestedDuration: time.Minute, MaxUses: 1}
	first, created, err := Request(grants.New(grantPath, grants.Options{}), mustPlanStore(t, planPath), input)
	if err != nil || !created {
		t.Fatalf("first Request() = %+v, %v, %v", first, created, err)
	}
	second, created, err := Request(grants.New(grantPath, grants.Options{}), mustPlanStore(t, planPath), input)
	if err != nil || created || second.Grant.ID != first.Grant.ID || second.Grant.Metadata[hfplan.MetadataDigest] != first.Grant.Metadata[hfplan.MetadataDigest] {
		t.Fatalf("retry Request() = %+v, %v, %v", second, created, err)
	}
	input.Target = "dataset/acme/other"
	if _, _, err := Request(grants.New(grantPath, grants.Options{}), mustPlanStore(t, planPath), input); !errors.Is(err, grants.ErrIdempotencyConflict) {
		t.Fatalf("changed retry error = %v", err)
	}
}

func mustPlanStore(t *testing.T, path string) *hfplan.Store {
	t.Helper()
	plans, err := hfplan.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return plans
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
