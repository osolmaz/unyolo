package grants

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/policy"
)

func TestLifecycleIdempotencyAndUseBudget(t *testing.T) {
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	ids := []string{"grant-1", "token-1", "token-2"}
	store := newDeterministicStore(t, func() time.Time { return now }, &ids)
	req := Request{
		Client:          "bob",
		ClientRequestID: "push-main",
		Operation:       "git.push.fast_forward",
		Target:          repoTarget("demo"),
		Attrs:           map[string][]string{"ref": {"refs/heads/main"}},
		Reason:          "fix production",
		MaxUses:         1,
	}
	result, created, err := store.Request(req)
	if err != nil || !created {
		t.Fatalf("Request() = %+v created=%v err=%v, want created grant", result, created, err)
	}
	grant := result.Grant
	decisionToken := assertIdempotency(t, store, req, grant.ID)

	approved, err := store.Approve(grant.ID, decisionToken, "telegram:1")
	if err != nil || approved.Status != StatusActive {
		t.Fatalf("Approve() = %+v err=%v, want active", approved, err)
	}
	if _, err := store.Deny(grant.ID, decisionToken, "telegram:1"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("replayed Deny() error = %v, want ErrNotPending", err)
	}

	overlays, err := store.ActivePolicyGrants()
	if err != nil || len(overlays) != 1 || overlays[0].ID != grant.ID {
		t.Fatalf("ActivePolicyGrants() = %+v err=%v, want grant overlay", overlays, err)
	}
	assertUseBudget(t, store, grant.ID)
}

func TestListForClientExpiresAndFiltersGrants(t *testing.T) {
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	ids := []string{"grant-1", "token-1", "grant-2", "token-2"}
	store := newDeterministicStore(t, func() time.Time { return now }, &ids)
	firstReq := Request{
		Client:          "bob",
		ClientRequestID: "push-main",
		Operation:       "git.push.force",
		Target:          repoTarget("demo"),
		Attrs:           map[string][]string{"ref": {"refs/heads/main"}},
		Reason:          "fix production",
	}
	first, _, err := store.Request(firstReq)
	if err != nil {
		t.Fatalf("Request(first) error = %v", err)
	}
	secondReq := firstReq
	secondReq.Client = "other"
	secondReq.ClientRequestID = "push-main-other"
	if _, _, err := store.Request(secondReq); err != nil {
		t.Fatalf("Request(second) error = %v", err)
	}
	now = first.Grant.PendingExpiresAt.Add(time.Second)

	grants, err := store.ListForClient(first.Grant.Client)
	if err != nil {
		t.Fatalf("ListForClient() error = %v", err)
	}
	if len(grants) != 1 || grants[0].ID != first.Grant.ID || grants[0].Status != StatusExpired {
		t.Fatalf("ListForClient() = %+v, want expired first grant only", grants)
	}

	all, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("List() len = %d, want both grants", len(all))
	}
}

func TestApprovedIdempotentRetryKeepsOriginalDuration(t *testing.T) {
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	ids := []string{"grant-1", "token-1"}
	store := newDeterministicStore(t, func() time.Time { return now }, &ids)
	req := Request{
		Client:          "bob",
		ClientRequestID: "push-main",
		Operation:       "git.push.fast_forward",
		Target:          repoTarget("demo"),
		Attrs:           map[string][]string{"ref": {"refs/heads/main"}},
		Reason:          "fix production",
	}
	result, _, err := store.Request(req)
	if err != nil {
		t.Fatal(err)
	}
	grant := result.Grant
	now = now.Add(time.Minute)
	if _, err := store.Approve(grant.ID, result.DecisionToken, "telegram:1"); err != nil {
		t.Fatal(err)
	}
	retry, created, err := store.Request(req)
	if err != nil || created || retry.Grant.ID != grant.ID {
		t.Fatalf("approved retry Request() = %+v created=%v err=%v, want same grant", retry, created, err)
	}
}

func TestIdempotentRetryIgnoresValueOrder(t *testing.T) {
	ids := []string{"grant-1", "token-1", "token-2"}
	store := newDeterministicStore(t, time.Now, &ids)
	request := Request{
		Client:          "bob",
		ClientRequestID: "multi-ref",
		Operation:       "git.push",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{
			"refs": {"refs/heads/main", "refs/heads/dev"},
		}},
		Attrs:  map[string][]string{"paths": {"README.md", "go.mod"}},
		Reason: "push two refs",
	}
	first, created, err := store.Request(request)
	if err != nil || !created {
		t.Fatalf("first Request() = %+v created=%v err=%v", first, created, err)
	}
	request.Target.Fields["refs"] = []string{"refs/heads/dev", "refs/heads/main"}
	request.Attrs["paths"] = []string{"go.mod", "README.md"}
	retry, created, err := store.Request(request)
	if err != nil || created || retry.Grant.ID != first.Grant.ID {
		t.Fatalf("reordered Request() = %+v created=%v err=%v", retry, created, err)
	}
}

func TestGrantMetadataIsDurableAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	store := New(path, Options{})
	request := Request{
		Client:          "bob",
		ClientRequestID: "provider-metadata",
		Operation:       "git.push",
		Target:          repoTarget("demo"),
		Reason:          "provider metadata",
		Metadata:        map[string]string{"grant_mode": "execution"},
	}
	result, created, err := store.Request(request)
	if err != nil || !created || result.Grant.Metadata["grant_mode"] != "execution" {
		t.Fatalf("Request() = %+v created=%v err=%v", result, created, err)
	}
	request.Metadata["grant_mode"] = "window"
	if result.Grant.Metadata["grant_mode"] != "execution" {
		t.Fatalf("request mutation changed grant metadata: %+v", result.Grant.Metadata)
	}
	request.Metadata["grant_mode"] = "execution"
	restarted := New(path, Options{})
	stored, err := restarted.Get(result.Grant.ID)
	if err != nil || stored.Metadata["grant_mode"] != "execution" {
		t.Fatalf("Get() = %+v err=%v", stored, err)
	}
	request.Metadata["grant_mode"] = "window"
	if _, _, err := restarted.Request(request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Request(metadata conflict) error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestGrantMetadataValidation(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	base := Request{Client: "bob", Operation: "git.push", Target: repoTarget("demo"), Reason: "metadata"}
	cases := []map[string]string{
		{"": "value"},
		{" key": "value"},
		{"key": " "},
		{strings.Repeat("k", maxMetadataKeyBytes+1): "value"},
		{"key": strings.Repeat("v", maxMetadataValueBytes+1)},
	}
	tooMany := make(map[string]string, maxMetadataEntries+1)
	for index := range maxMetadataEntries + 1 {
		tooMany[fmt.Sprintf("key-%d", index)] = "value"
	}
	cases = append(cases, tooMany)
	for _, metadata := range cases {
		request := base
		request.Metadata = metadata
		if _, _, err := store.Request(request); err == nil {
			t.Fatalf("Request(metadata=%q) error = nil, want validation error", metadata)
		}
	}
}

func TestLoadRejectsLegacyScalarGrantValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	data := `{"version":1,"next_event":1,"grants":[{
		"id":"grant-1",
		"decision_token_verifier":"verifier",
		"client":"bob",
		"operation":"git.push",
		"target":{"Kind":"repo","Fields":{"owner":"osolmaz","name":"demo"}},
		"attrs":{"ref":"refs/heads/main"},
		"reason":"legacy",
		"status":"active",
		"created_at":"2026-07-08T00:00:00Z",
		"pending_expires_at":"2026-07-08T00:05:00Z",
		"expires_at":"2026-07-08T01:00:00Z",
		"duration":300000000000,
		"pending_timeout":300000000000,
		"max_uses":1
	}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(path, Options{})
	if _, err := store.List(); err == nil {
		t.Fatal("List() accepted legacy scalar attrs and target fields")
	}
}

func TestPendingIdempotentRetryRefreshesDecisionToken(t *testing.T) {
	ids := []string{"grant-1", "token-1", "token-2"}
	store := newDeterministicStore(t, time.Now, &ids)
	req := Request{
		Client:          "bob",
		ClientRequestID: "shell-debug",
		Operation:       "session.shell",
		Target:          policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:          "debug deploy",
	}
	first, created, err := store.Request(req)
	if err != nil || !created {
		t.Fatalf("first Request() = %+v created=%v err=%v, want created", first, created, err)
	}
	retry, created, err := store.Request(req)
	if err != nil || created || retry.Grant.ID != first.Grant.ID || retry.DecisionToken == "" {
		t.Fatalf("retry Request() = %+v created=%v err=%v, want same grant with token", retry, created, err)
	}
	if _, err := store.Approve(first.Grant.ID, first.DecisionToken, "telegram:1"); !errors.Is(err, ErrInvalidDecisionToken) {
		t.Fatalf("Approve(old token) error = %v, want ErrInvalidDecisionToken", err)
	}
	if _, err := store.Approve(first.Grant.ID, retry.DecisionToken, "telegram:1"); err != nil {
		t.Fatalf("Approve(refreshed token) error = %v", err)
	}
}

func TestDecisionTokenExpiryAndRevoke(t *testing.T) {
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	result, _, err := store.Request(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:    "debug deploy",
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := result.Grant
	if _, err := store.Approve(grant.ID, "wrong", "telegram:1"); !errors.Is(err, ErrInvalidDecisionToken) {
		t.Fatalf("Approve(wrong token) error = %v, want ErrInvalidDecisionToken", err)
	}
	approved, err := store.Approve(grant.ID, result.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	revoked, err := store.Revoke(approved.ID, "operator")
	if err != nil || revoked.Status != StatusRevoked {
		t.Fatalf("Revoke() = %+v err=%v, want revoked", revoked, err)
	}
}

func TestDecisionTokenRequiresExactMatch(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	result, _, err := store.Request(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:    "debug deploy",
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := result.Grant
	if _, err := store.Approve(grant.ID, result.DecisionToken+"suffix", "telegram:1"); !errors.Is(err, ErrInvalidDecisionToken) {
		t.Fatalf("Approve(suffixed token) error = %v, want ErrInvalidDecisionToken", err)
	}
	if _, err := store.Approve(grant.ID, result.DecisionToken, "telegram:1"); err != nil {
		t.Fatalf("Approve(exact token) error = %v", err)
	}
}

func TestApproveSetsExpiryFromApprovalTime(t *testing.T) {
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	result, _, err := store.Request(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:    "debug deploy",
		Duration:  10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Grant.ExpiresAt.IsZero() {
		t.Fatalf("pending ExpiresAt = %s, want zero", result.Grant.ExpiresAt)
	}
	now = now.Add(4 * time.Minute)
	approved, err := store.Approve(result.Grant.ID, result.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatal(err)
	}
	want := now.Add(10 * time.Minute)
	if !approved.ExpiresAt.Equal(want) {
		t.Fatalf("approved ExpiresAt = %s, want %s", approved.ExpiresAt, want)
	}
}

func TestRequestDefaultsPendingTimeoutToPolicyTTL(t *testing.T) {
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	result, _, err := store.Request(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:    "debug deploy",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := now.Add(5 * time.Minute)
	if !result.Grant.PendingExpiresAt.Equal(want) {
		t.Fatalf("PendingExpiresAt = %s, want %s", result.Grant.PendingExpiresAt, want)
	}
}

func TestDecisionTokenIsNotSerialized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	ids := []string{"grant-1", "token-1"}
	store := New(path, Options{
		Now: nowFunc(now),
		NewID: func(int) (string, error) {
			next := ids[0]
			ids = ids[1:]
			return next, nil
		},
	})
	result, _, err := store.Request(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:    "debug deploy",
	})
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := json.Marshal(result.Grant)
	if err != nil {
		t.Fatal(err)
	}
	assertNoRawDecisionToken(t, string(serialized), result.DecisionToken)
	assertNoPendingAccessTimes(t, string(serialized))
	state, err := os.ReadFile(path) // #nosec G304 -- test reads its own temp state file.
	if err != nil {
		t.Fatal(err)
	}
	assertNoRawDecisionToken(t, string(state), result.DecisionToken)
	assertNoPendingAccessTimes(t, string(state))
	if !strings.Contains(string(state), "decision_token_verifier") {
		t.Fatalf("state file does not contain decision token verifier: %s", string(state))
	}
}

func TestLateDecisionPersistsExpiredStatus(t *testing.T) {
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	expiring, _, err := store.Request(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:    "expire",
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if _, err := store.Approve(expiring.Grant.ID, expiring.DecisionToken, "telegram:1"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("Approve(expired) error = %v, want ErrNotPending", err)
	}
	data, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	_, persisted, err := findGrant(data.Grants, expiring.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Status != StatusExpired {
		t.Fatalf("persisted expired grant status = %s, want expired", persisted.Status)
	}
}

func TestLifecyclePreparationReportsPersistenceFailure(t *testing.T) {
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	dir := t.TempDir()
	store := New(filepath.Join(dir, "grants.json"), Options{Now: func() time.Time { return now }})
	result, _, err := store.Request(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:    "expire",
		Duration:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "telegram:1"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if err := os.Chmod(dir, 0o500); err != nil { // #nosec G302 -- test intentionally blocks directory writes.
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- private test directory restore.

	_, err = store.ReserveUse(result.Grant.ID)
	if !errors.Is(err, ErrNotActive) || !strings.Contains(err.Error(), "create temp file") {
		t.Fatalf("ReserveUse() error = %v, want joined lifecycle and persistence errors", err)
	}
}

func TestGetExpiresPendingGrant(t *testing.T) {
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	result, _, err := store.Request(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:    "debug deploy",
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	got, err := store.Get(result.Grant.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("Get() status = %s, want expired", got.Status)
	}
}

func TestRequestValidation(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	_, _, err := store.Request(Request{Client: "bob", Operation: "op", Reason: "missing target"})
	if err == nil {
		t.Fatal("Request(missing target) error = nil, want error")
	}
	_, _, err = store.Request(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    policy.Target{Kind: "user", Fields: map[string][]string{"name": {"deploy"}}},
		Reason:    "too many uses",
		MaxUses:   26,
	})
	if err == nil {
		t.Fatal("Request(too many uses) error = nil, want error")
	}
	invalidValues := []Request{
		{Client: "bob", Operation: "op", Target: policy.Target{Kind: "repo", Fields: map[string][]string{"refs": nil}}, Reason: "empty target list"},
		{Client: "bob", Operation: "op", Target: policy.Target{Kind: "repo", Fields: map[string][]string{"": {"main"}}}, Reason: "empty target name"},
		{Client: "bob", Operation: "op", Target: repoTarget("demo"), Attrs: map[string][]string{"refs": {" "}}, Reason: "blank attr value"},
		{Client: "bob", Operation: "op", Target: repoTarget("demo"), Attrs: map[string][]string{"": {"main"}}, Reason: "empty attr name"},
	}
	for _, request := range invalidValues {
		if _, _, err := store.Request(request); err == nil {
			t.Fatalf("Request(%s) error = nil, want error", request.Reason)
		}
	}
}

func TestReleaseUseRestoresOverlay(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	result, _, err := store.Request(Request{
		Client:    "bob",
		Operation: "git.push.fast_forward",
		Target:    repoTarget("demo"),
		Attrs:     map[string][]string{"ref": {"refs/heads/main"}},
		Reason:    "test release",
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := result.Grant
	if _, err := store.Approve(grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(grant.ID); err != nil {
		t.Fatal(err)
	}
	if overlays, err := store.ActivePolicyGrants(); err != nil || len(overlays) != 0 {
		t.Fatalf("reserved ActivePolicyGrants() = %+v err=%v, want none", overlays, err)
	}
	if _, err := store.ReleaseUse(grant.ID); err != nil {
		t.Fatal(err)
	}
	overlays, err := store.ActivePolicyGrants()
	if err != nil || len(overlays) != 1 {
		t.Fatalf("ActivePolicyGrants() = %+v err=%v, want restored overlay", overlays, err)
	}
}

func repoTarget(name string) policy.Target {
	return policy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {name}}}
}

func newDeterministicStore(t *testing.T, now func() time.Time, ids *[]string) *Store {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now: now,
		NewID: func(int) (string, error) {
			next := (*ids)[0]
			*ids = (*ids)[1:]
			return next, nil
		},
	})
}

func nowFunc(now time.Time) func() time.Time {
	return func() time.Time { return now }
}

func assertNoRawDecisionToken(t *testing.T, data string, token string) {
	t.Helper()
	if strings.Contains(data, `"decision_token":`) || strings.Contains(data, token) {
		t.Fatalf("serialized grant leaked raw decision token: %s", data)
	}
}

func assertNoPendingAccessTimes(t *testing.T, data string) {
	t.Helper()
	for _, forbidden := range []string{`"expires_at"`, `"decided_at"`, `"used_at"`, "0001-01-01T00:00:00Z"} {
		if strings.Contains(data, forbidden) {
			t.Fatalf("pending grant serialized %s: %s", forbidden, data)
		}
	}
}

func assertIdempotency(t *testing.T, store *Store, req Request, grantID string) string {
	t.Helper()
	retry, created, err := store.Request(req)
	if err != nil || created || retry.Grant.ID != grantID {
		t.Fatalf("retry Request() = %+v created=%v err=%v, want same grant", retry, created, err)
	}
	if retry.DecisionToken == "" {
		t.Fatalf("retry Request() DecisionToken is empty")
	}
	req.Duration = 10 * time.Minute
	if _, _, err := store.Request(req); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("duration conflict Request() error = %v, want ErrIdempotencyConflict", err)
	}
	req.Duration = 0
	req.PendingTimeout = 20 * time.Minute
	if _, _, err := store.Request(req); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("pending timeout conflict Request() error = %v, want ErrIdempotencyConflict", err)
	}
	req.PendingTimeout = 0
	req.Reason = "different"
	if _, _, err := store.Request(req); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting Request() error = %v, want ErrIdempotencyConflict", err)
	}
	return retry.DecisionToken
}

func assertUseBudget(t *testing.T, store *Store, grantID string) {
	t.Helper()
	reserved, err := store.ReserveUse(grantID)
	if err != nil || reserved.ReservedCount != 1 {
		t.Fatalf("ReserveUse() = %+v err=%v, want one reservation", reserved, err)
	}
	if overlays, err := store.ActivePolicyGrants(); err != nil || len(overlays) != 0 {
		t.Fatalf("reserved ActivePolicyGrants() = %+v err=%v, want none", overlays, err)
	}
	used, err := store.CommitUse(grantID)
	if err != nil || used.Status != StatusConsumed || used.UsedCount != 1 {
		t.Fatalf("CommitUse() = %+v err=%v, want consumed", used, err)
	}
}
