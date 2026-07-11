package plan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
)

func TestPlanBindsGrantAndValidatesActivationAndExecution(t *testing.T) {
	t.Parallel()
	snapshot, resolved := testResolved(t)
	request := testGrantRequest(resolved)
	identity := Identity{Name: "root", UID: 0, GID: 0, SupplementaryGIDs: []uint32{20, 10}}
	value, err := Build(request, resolved, identity, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(value.SupplementaryGIDs) != 2 || value.SupplementaryGIDs[0] != 10 {
		t.Fatalf("groups = %v", value.SupplementaryGIDs)
	}
	plans, _ := NewStore(filepath.Join(t.TempDir(), "plans"))
	if err := plans.Bind(&request, value); err != nil {
		t.Fatal(err)
	}
	grantStore := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	created, _, err := grantStore.Request(request)
	if err != nil {
		t.Fatal(err)
	}
	helper := &fakeReadiness{}
	validator := Validator{Store: plans, Catalog: snapshot, Identities: fakeIdentities{identity: Identity{Name: "root", UID: 0, GID: 0, SupplementaryGIDs: []uint32{10, 20}}}, Helper: helper}
	if err := validator.ValidateActivation(t.Context(), created.Grant, grants.ApprovalConstraints{Duration: time.Minute, MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := validator.ValidateExecution(t.Context(), created.Grant)
	if err != nil || got.CommandID != "scale" || helper.calls != 2 {
		t.Fatalf("ValidateExecution() = %+v, %v calls=%d", got, err, helper.calls)
	}
	if err := validator.ValidateActivation(context.Background(), created.Grant, grants.ApprovalConstraints{Duration: 10 * time.Minute}); !errors.Is(err, grants.ErrConstraintExceeded) {
		t.Fatalf("widening error = %v", err)
	}
}

func TestPlanCanonicalHelpersAndIndependentHelperValidation(t *testing.T) {
	t.Parallel()
	snapshot, resolved := testResolved(t)
	request := testGrantRequest(resolved)
	identity := Identity{Name: "root", UID: 0, GID: 0}
	value, err := Build(request, resolved, identity, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := EncodeCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCanonical(canonical)
	if err != nil || decoded.CommandID != value.CommandID {
		t.Fatalf("DecodeCanonical() = %+v, %v", decoded, err)
	}
	if err := ValidateForHelper(decoded, snapshot, fakeIdentities{identity: identity}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateForHelper(decoded, nil, fakeIdentities{}); err == nil {
		t.Fatal("nil helper catalog was accepted")
	}
	plans, _ := NewStore(filepath.Join(t.TempDir(), "plans"))
	if err := plans.Bind(&request, value); err != nil {
		t.Fatal(err)
	}
	stored, err := plans.Canonical(request.Metadata[MetadataDigest])
	if err != nil || string(stored) != string(canonical) {
		t.Fatalf("Canonical() = %q, %v", stored, err)
	}
	current, err := user.Current()
	if err == nil {
		if got, lookupErr := (SystemIdentityResolver{}).Lookup(current.Username); lookupErr != nil || got.Name == "" {
			t.Fatalf("system identity = %+v, %v", got, lookupErr)
		}
	}
}

func TestPlanRejectsGrantPlanCatalogIdentityAndHelperDrift(t *testing.T) {
	t.Parallel()
	snapshot, resolved := testResolved(t)
	request := testGrantRequest(resolved)
	identity := Identity{Name: "root", UID: 0, GID: 0}
	value, _ := Build(request, resolved, identity, time.Unix(1_700_000_000, 0))
	plans, _ := NewStore(filepath.Join(t.TempDir(), "plans"))
	if err := plans.Bind(&request, value); err != nil {
		t.Fatal(err)
	}
	grantStore := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	created, _, _ := grantStore.Request(request)
	base := Validator{Store: plans, Catalog: snapshot, Identities: fakeIdentities{identity: identity}, Helper: &fakeReadiness{}}

	mutated := created.Grant
	mutated.Operation = "exec.other"
	if _, err := base.ValidateExecution(t.Context(), mutated); err == nil {
		t.Fatal("mutated grant was accepted")
	}
	drifted := base
	drifted.Identities = fakeIdentities{identity: Identity{Name: "root", UID: 1, GID: 0}}
	if _, err := drifted.ValidateExecution(t.Context(), created.Grant); err == nil {
		t.Fatal("identity drift was accepted")
	}
	unready := base
	unready.Helper = &fakeReadiness{err: errors.New("offline")}
	if _, err := unready.ValidateExecution(t.Context(), created.Grant); err == nil {
		t.Fatal("unready helper was accepted")
	}
	corruptDigest := request.Metadata[MetadataDigest]
	if err := os.WriteFile(plans.content.Path(corruptDigest), []byte(`{"schema":"sudo-broker.io/plan/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := base.ValidateExecution(t.Context(), created.Grant); err == nil {
		t.Fatal("corrupt plan was accepted")
	}
}

func TestPlanEncodingIsDeterministicAndClosed(t *testing.T) {
	t.Parallel()
	_, resolved := testResolved(t)
	request := testGrantRequest(resolved)
	value, _ := Build(request, resolved, Identity{Name: "root", UID: 0, GID: 0}, time.Unix(1_700_000_000, 0))
	first, err := encode(value)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := encode(value)
	if string(first) != string(second) {
		t.Fatal("plan encoding is not deterministic")
	}
	var object map[string]any
	if err := json.Unmarshal(first, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	if _, err := decode(unknown); err == nil {
		t.Fatal("unknown plan field was accepted")
	}
	if _, err := decode(append(first, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing plan data was accepted")
	}
	for name, mutate := range map[string]func(*Plan){
		"relative executable":  func(value *Plan) { value.Executable = "bin/tool" },
		"duplicate group":      func(value *Plan) { value.SupplementaryGIDs = []uint32{10, 10} },
		"unsorted environment": func(value *Plan) { value.Environment = []string{"Z=1", "A=1"} },
		"loader environment":   func(value *Plan) { value.Environment = []string{"LD_PRELOAD=x"} },
		"control argument":     func(value *Plan) { value.Arguments = []string{"bad\nvalue"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := value
			mutate(&changed)
			if _, err := encode(changed); err == nil {
				t.Fatal("unsafe plan was accepted")
			}
		})
	}
}

func TestPlanStoreCollectsOnlyOldOrphans(t *testing.T) {
	t.Parallel()
	_, resolved := testResolved(t)
	request := testGrantRequest(resolved)
	value, _ := Build(request, resolved, Identity{Name: "root"}, time.Unix(1_700_000_000, 0))
	plans, _ := NewStore(filepath.Join(t.TempDir(), "plans"))
	if err := plans.Bind(&request, value); err != nil {
		t.Fatal(err)
	}
	referenced := request.Metadata[MetadataDigest]
	orphan := value
	orphan.RequestID = "orphan"
	orphanDigest, err := plans.content.Put(mustEncode(t, orphan))
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(plans.content.Path(orphanDigest), old, old); err != nil {
		t.Fatal(err)
	}
	removed, err := plans.CollectOrphans(map[string]bool{referenced: true}, time.Now().Add(-24*time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("CollectOrphans() = %d, %v", removed, err)
	}
	if _, err := plans.Get(referenced); err != nil {
		t.Fatalf("referenced plan removed: %v", err)
	}
}

func TestPlanFailsClosedForInvalidInputsAndUnavailableStores(t *testing.T) {
	t.Parallel()
	_, resolved := testResolved(t)
	request := testGrantRequest(resolved)
	identity := Identity{Name: "root"}
	for _, mutate := range []func(*grants.Request, *catalog.Resolved, *Identity){
		func(value *grants.Request, _ *catalog.Resolved, _ *Identity) { value.Operation = "other" },
		func(_ *grants.Request, value *catalog.Resolved, _ *Identity) { value.TargetUser = "other" },
		func(_ *grants.Request, _ *catalog.Resolved, value *Identity) { value.Name = "other" },
		func(value *grants.Request, _ *catalog.Resolved, _ *Identity) { value.Attrs = map[string][]string{} },
	} {
		changedRequest, changedResolved, changedIdentity := request, resolved, identity
		mutate(&changedRequest, &changedResolved, &changedIdentity)
		if _, err := Build(changedRequest, changedResolved, changedIdentity, time.Now()); err == nil {
			t.Fatal("invalid plan input was accepted")
		}
	}
	var plans *Store
	if err := plans.Bind(&request, Plan{}); err == nil {
		t.Fatal("nil plan store accepted a bind")
	}
	if _, err := plans.Get(strings.Repeat("a", 64)); err == nil {
		t.Fatal("nil plan store returned a plan")
	}
	if _, err := plans.Canonical(strings.Repeat("a", 64)); err == nil {
		t.Fatal("nil plan store returned canonical bytes")
	}
	if _, err := plans.CollectOrphans(nil, time.Now()); err == nil {
		t.Fatal("nil plan store collected plans")
	}
	if _, err := (SystemIdentityResolver{}).Lookup("definitely-missing-sudo-broker-user"); err == nil {
		t.Fatal("missing system identity was resolved")
	}
	if _, err := parseID("not-a-number"); err == nil {
		t.Fatal("invalid numeric id was parsed")
	}
}

func mustEncode(t *testing.T, value Plan) []byte {
	t.Helper()
	data, err := encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testResolved(t *testing.T) (*catalog.Snapshot, catalog.Resolved) {
	t.Helper()
	directory := t.TempDir()
	snapshot, err := catalog.Parse([]byte(fmt.Sprintf(`{"version":1,"commands":[{
		"id":"scale","executable":"/usr/bin/printf","arguments":[{"literal":"%%s"},{"slot":"replicas","type":"integer","minimum":1,"maximum":4}],
		"target_users":["root"],"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100,"environment":{"SAFE":"yes"}}]}`, directory)))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := snapshot.Resolve("scale", "root", map[string]json.RawMessage{"replicas": json.RawMessage(`2`)})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, resolved
}

func testGrantRequest(resolved catalog.Resolved) grants.Request {
	policyRequest := sudopolicy.Request("bob", resolved)
	return grants.Request{
		Client: "bob", ClientRequestID: "request-1", Operation: policyRequest.Operation, Target: policyRequest.Target, Attrs: policyRequest.Attrs,
		Reason: "scale release", Duration: 5 * time.Minute, PendingTimeout: time.Minute, MaxUses: 1,
	}
}

type fakeIdentities struct {
	identity Identity
	err      error
}

func (f fakeIdentities) Lookup(string) (Identity, error) { return f.identity, f.err }

type fakeReadiness struct {
	calls int
	err   error
}

func (f *fakeReadiness) Ready(context.Context) error { f.calls++; return f.err }
