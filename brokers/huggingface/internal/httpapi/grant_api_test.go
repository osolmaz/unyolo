package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	rootpolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/usebudget"
)

func TestGrantRequestAcceptsConfiguredGitCapabilities(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce, policy.OpGitRefDelete, policy.OpGitTagUpdate))))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Audit: testAuditRecorder(),
		Config: config.Config{
			HFToken:      testToken,
			Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:     filepath.Join(dir, "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	tests := []struct {
		operation string
		ref       string
	}{
		{operation: "git.push.force", ref: "refs/heads/main"},
		{operation: "git.ref.delete", ref: "refs/heads/feature"},
		{operation: "git.tag.update", ref: "refs/tags/v1"},
	}
	for i, tc := range tests {
		body := apiGrantRequestJSON(policy.Operation(tc.operation), tc.ref, "recover", tc.operation, 0, 0)
		resp, text := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("%s grant request = %d %q, want 202", tc.operation, resp.StatusCode, text)
		}
		if len(notifier.messages) != i+1 || notifier.messages[i].Operation != tc.operation {
			t.Fatalf("notifier messages = %+v, want operation %s at index %d", notifier.messages, tc.operation, i)
		}
	}

	invalid := []struct {
		operation string
		ref       string
	}{
		{operation: "git.push.force", ref: "refs/tags/v1"},
		{operation: "git.push.force", ref: "refs/replace/abc"},
		{operation: "git.ref.delete", ref: "refs/tags/v1"},
		{operation: "git.ref.delete", ref: "refs/replace/abc"},
		{operation: "git.tag.update", ref: "refs/heads/main"},
	}
	for _, tc := range invalid {
		body := apiGrantRequestJSON(policy.Operation(tc.operation), tc.ref, "recover", "", 0, 0)
		resp, _ := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s grant request for %s = %d, want 400", tc.operation, tc.ref, resp.StatusCode)
		}
	}
}

func TestGrantRequestAcceptsAppendPushWhenRequestable(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(testDatasetPolicy{
		name:       "repo",
		requestOps: []policy.Operation{policy.OpGitPushAppend},
	})))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Audit: testAuditRecorder(),
		Config: config.Config{
			HFToken:      testToken,
			Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:     filepath.Join(dir, "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	body := apiGrantRequestJSON(policy.OpGitPushAppend, "refs/heads/main", "append once", "append-once", 0, 0)
	resp, text := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("append grant request = %d %s messages=%d, want 202 and one message", resp.StatusCode, text, len(notifier.messages))
	}

	body = apiGrantRequestJSON(policy.OpGitPushAppend, "refs/replace/abc", "append replace", "", 0, 0)
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("append grant for replace ref = %d, want 400", resp.StatusCode)
	}
}

func TestGrantRequestAcceptsExplicitUnlimitedUseBudget(t *testing.T) {
	t.Parallel()
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"unlimited","effect":"request","clients":["agent"],
		"operations":["git.push.force"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]}],
		"grant_policy":{"default_max_uses":3,"max_uses":null}
	}]}`))
	if err != nil {
		t.Fatal(err)
	}
	notifier := &captureGrantNotifier{}
	handler, err := New(Options{
		Audit: testAuditRecorder(),
		Config: config.Config{
			HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir: filepath.Join(t.TempDir(), "state"), MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 10 * time.Second,
		},
		Scope: scp, UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	var payload map[string]any
	if err := json.Unmarshal([]byte(apiGrantRequestJSON(
		policy.OpGitPushForce, "refs/heads/main", "continuous maintenance", "unlimited", 5, 0,
	)), &payload); err != nil {
		t.Fatal(err)
	}
	payload["max_uses"] = nil
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	resp, responseBody := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, bytes.NewReader(body))
	if resp.StatusCode != http.StatusAccepted || !strings.Contains(responseBody, `"max_uses":null`) {
		t.Fatalf("grant request = %d %s", resp.StatusCode, responseBody)
	}
	created := decodeAPIGrantResponse(t, responseBody)
	grant, err := handler.grants.Get(created.ID)
	if err != nil || !grant.MaxUses.IsUnlimited() {
		t.Fatalf("stored grant = %+v, %v", grant, err)
	}
	for _, next := range []any{nil, 3} {
		if next == nil {
			delete(payload, "max_uses")
		} else {
			payload["max_uses"] = next
		}
		conflictBody, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, bytes.NewReader(conflictBody))
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("tri-state idempotency conflict = %d, want 409", resp.StatusCode)
		}
	}
	decision := handler.handleTelegramDecision(t.Context(), telegramGrantDecision(notify.ActionApprove, notifier.messages[0]))
	if decision.Answer != notify.AnswerApproved || decision.Retry {
		t.Fatalf("approval = %+v", decision)
	}
	for range 3 {
		if _, err := handler.grants.ReserveUse(created.ID); err != nil {
			t.Fatal(err)
		}
		used, err := handler.grants.CommitUse(created.ID)
		if err != nil || used.Status != grants.StatusActive {
			t.Fatalf("CommitUse() = %+v, %v", used, err)
		}
	}
	resp, responseBody = doRequest(t, http.MethodPost, broker.URL+"/api/grants/"+created.ID+"/revoke", "Bearer "+testSecret, strings.NewReader("{}"))
	if resp.StatusCode != http.StatusOK || decodeAPIGrantResponse(t, responseBody).Status != string(grants.StatusRevoked) {
		t.Fatalf("revoke = %d %s", resp.StatusCode, responseBody)
	}
	resp, responseBody = doRequest(t, http.MethodPost, broker.URL+"/api/grants/"+created.ID+"/revoke", "Bearer "+testSecret, strings.NewReader("{}"))
	if resp.StatusCode != http.StatusConflict || !strings.Contains(responseBody, "invalid_grant_state") {
		t.Fatalf("repeat revoke = %d %s", resp.StatusCode, responseBody)
	}
	pending, _, err := handler.grants.Request(grants.Request{
		Client: "agent", ClientRequestID: "cancel-me", Operation: string(policy.OpGitPushForce),
		Target: rootpolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/repo"}}},
		Reason: "cancel", Duration: time.Minute, MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, responseBody = doRequest(t, http.MethodPost, broker.URL+"/api/grants/"+pending.Grant.ID+"/cancel", "Bearer "+testSecret, strings.NewReader("{}"))
	if resp.StatusCode != http.StatusOK || decodeAPIGrantResponse(t, responseBody).Status != string(grants.StatusCanceled) {
		t.Fatalf("cancel = %d %s", resp.StatusCode, responseBody)
	}
	resp, responseBody = doRequest(t, http.MethodPost, broker.URL+"/api/grants/"+pending.Grant.ID+"/cancel", "Bearer "+testSecret, strings.NewReader(`{"unexpected":true}`))
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(responseBody, "validation_failed") {
		t.Fatalf("invalid cancel = %d %s", resp.StatusCode, responseBody)
	}
}

func TestResolveAPIGrantUses(t *testing.T) {
	t.Parallel()
	window := &rootpolicy.GrantPolicy{Mode: string(rootpolicy.GrantModeWindow), DefaultMaxUses: 3}
	for _, test := range []struct {
		name      string
		requested usebudget.Optional
		bounds    *rootpolicy.GrantPolicy
		want      usebudget.Limit
		wantError bool
	}{
		{name: "default", bounds: window, want: 3},
		{name: "unlimited", requested: usebudget.NoLimit(), bounds: window, want: usebudget.Unlimited},
		{name: "finite", requested: usebudget.Finite(4), bounds: window, want: 4},
		{name: "negative", requested: usebudget.Optional{Limit: -1, Specified: true}, bounds: window, wantError: true},
		{name: "finite ceiling", requested: usebudget.NoLimit(), bounds: &rootpolicy.GrantPolicy{Mode: string(rootpolicy.GrantModeWindow), MaxUses: 2}, wantError: true},
		{name: "execution", requested: usebudget.NoLimit(), bounds: &rootpolicy.GrantPolicy{Mode: string(rootpolicy.GrantModeExecution), MaxUses: 1}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveAPIGrantUses(test.requested, test.bounds)
			if (err != nil) != test.wantError || (!test.wantError && got != test.want) {
				t.Fatalf("resolveAPIGrantUses() = %v, %v", got, err)
			}
		})
	}
}

func TestGrantRequestErrors(t *testing.T) {
	dir := t.TempDir()
	var auditLog bytes.Buffer
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDatasetWithBounds("repo", map[string]int{"max_uses": 2}, policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	baseCfg := config.Config{
		HFToken:      testToken,
		Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
		StateDir:     filepath.Join(dir, "state"),
		MaxPackBytes: 25 * 1024 * 1024,
		HFTimeout:    10 * time.Second,
	}
	handler, err := New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	validBody := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "without-notifier", 5, 0)
	resp, _ := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(validBody))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("grant without approval channel = %d, want 503", resp.StatusCode)
	}
	baseCfg.Operators = []config.Client{{Name: "operator", Secret: "operator-secret-abcdefghijklmnopqrstuvwxyz"}}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	handler, err = New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	broker.Config.Handler = handler
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(validBody))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("grant with operator inbox = %d, want 202", resp.StatusCode)
	}

	notifier := &captureGrantNotifier{}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	handler, err = New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: notifier})
	if err != nil {
		t.Fatal(err)
	}
	broker.Config.Handler = handler
	beforeBadTargetAudit := auditLog.Len()
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{"operation":"git.push.force","target":%q,"reason":"recover","client_request_id":"bad-target"}`, testSecret)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad target status = %d, want 400", resp.StatusCode)
	}
	if got := auditLog.String()[beforeBadTargetAudit:]; strings.Contains(got, testSecret) || !strings.Contains(got, `"target":""`) {
		t.Fatalf("bad grant target audit leaked request body or missed empty target:\n%s", got)
	}
	attrMarker := "secret_attr_marker"
	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(
		`{"operation":"git.push.force","target":{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]},"attrs":{%q:"value"},"reason":"recover","client_request_id":"unknown-attr-marker"}`,
		attrMarker,
	)))
	if resp.StatusCode != http.StatusBadRequest || decodeJSendFailReason(t, body) != "invalid_attrs" {
		t.Fatalf("unknown attrs = %d %s, want 400 invalid_attrs", resp.StatusCode, body)
	}
	if strings.Contains(body, attrMarker) || strings.Contains(body, "value") {
		t.Fatalf("invalid attrs response leaked request attrs: %s", body)
	}
	tests := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "wrong method", method: http.MethodPut, want: http.StatusMethodNotAllowed},
		{name: "bad json", method: http.MethodPost, body: `{`, want: http.StatusBadRequest},
		{name: "trailing json", method: http.MethodPost, body: validBody + `{}`, want: http.StatusBadRequest},
		{name: "missing client request id", method: http.MethodPost, body: `{"operation":"git.push.force","target":{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]},"reason":"recover"}`, want: http.StatusBadRequest},
		{name: "bad operation", method: http.MethodPost, body: apiGrantRequestJSON(policy.Operation("git.upload_pack"), "refs/heads/main", "recover", "", 0, 0), want: http.StatusBadRequest},
		{name: "transport operation", method: http.MethodPost, body: apiGrantRequestJSON(policy.Operation("git.receive-pack"), "refs/heads/main", "recover", "", 0, 0), want: http.StatusBadRequest},
		{name: "unknown attrs", method: http.MethodPost, body: `{"operation":"git.push.force","target":{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]},"attrs":{"unknown":"value"},"reason":"recover","client_request_id":"unknown-attrs"}`, want: http.StatusBadRequest},
		{name: "target paths", method: http.MethodPost, body: `{"operation":"repo.contents.read","target":{"kind":"repo","type":"dataset","owner":"acme","name":"repo","paths":["README.md"]},"reason":"read one file","client_request_id":"target-paths"}`, want: http.StatusForbidden},
		{name: "wildcard target", method: http.MethodPost, body: `{"operation":"git.push.force","target":{"kind":"repo","type":"dataset","owner":"acme","name":"*","refs":["refs/heads/main"]},"reason":"recover","client_request_id":"wildcard-target"}`, want: http.StatusBadRequest},
		{name: "bucket target", method: http.MethodPost, body: `{"operation":"bucket.object.read","target":{"kind":"bucket","owner":"acme","name":"artifacts","keys":["runs/one"]},"reason":"read one object","client_request_id":"bucket-target"}`, want: http.StatusForbidden},
		{name: "unconfigured capability", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitRefDelete, "refs/heads/main", "recover", "", 0, 0), want: http.StatusForbidden},
		{name: "bad ref", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "main", "recover", "", 0, 0), want: http.StatusBadRequest},
		{name: "out of scope", method: http.MethodPost, body: apiGrantRequestForRepoJSON(policy.OpGitPushForce, "other", "refs/heads/main", "recover", "", 0, 0), want: http.StatusForbidden},
		{name: "negative minutes", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", -1, 0), want: http.StatusBadRequest},
		{name: "too many minutes", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 61, 0), want: http.StatusBadRequest},
		{name: "negative max uses", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 0, -1), want: http.StatusBadRequest},
		{name: "too many uses", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 0, 3), want: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := doRequest(t, tc.method, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(tc.body))
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}

	baseCfg.Operators = nil
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	handler, err = New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: failingGrantNotifier{}})
	if err != nil {
		t.Fatal(err)
	}
	broker.Config.Handler = handler
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(validBody))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("notifier failure status = %d, want 502", resp.StatusCode)
	}
}

func TestOperatorInboxSurvivesTelegramNotificationFailure(t *testing.T) {
	dir := t.TempDir()
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Audit: testAuditRecorder(),
		Config: config.Config{
			HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
			Operators: []config.Client{{Name: "operator", Secret: "operator-secret-abcdefghijklmnopqrstuvwxyz"}},
			StateDir:  filepath.Join(dir, "state"), MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 10 * time.Second,
		},
		Scope: scp, UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: failingGrantNotifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	body := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "telegram-failed-inbox-pending", 5, 0)
	resp, responseBody := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("grant request = %d %s, want 202", resp.StatusCode, responseBody)
	}
	stored := decodeAPIGrantResponse(t, responseBody)
	grant, err := handler.grants.Get(stored.ID)
	if err != nil || grant.Status != grants.StatusPending || !grant.NotificationDeliveryUnresolved {
		t.Fatalf("stored grant = %+v, err=%v", grant, err)
	}
}

func TestValidateGrantTargetForOperation(t *testing.T) {
	repo := policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo"}
	tests := []struct {
		name      string
		operation policy.Operation
		target    policy.Target
		wantErr   bool
	}{
		{name: "force with ref", operation: policy.OpGitPushForce, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"}}},
		{name: "fetch without ref", operation: policy.OpGitFetch, target: repo},
		{name: "force missing ref", operation: policy.OpGitPushForce, target: repo, wantErr: true},
		{name: "fetch with ignored ref", operation: policy.OpGitFetch, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"}}, wantErr: true},
		{name: "read with ignored ref", operation: policy.OpRepoContentsRead, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"}}, wantErr: true},
		{name: "path constraint", operation: policy.OpRepoContentsRead, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo", Paths: []string{"README.md"}}},
		{name: "bucket target", operation: policy.OpBucketObjectRead, target: policy.Target{Kind: policy.KindBucket, Owner: "acme", Name: "artifacts", Keys: []string{"runs/one"}}},
		{name: "bad repo identity", operation: policy.OpGitFetch, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeAny, Owner: "acme", Name: "repo"}, wantErr: true},
		{name: "wildcard owner", operation: policy.OpGitFetch, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "*", Name: "repo"}, wantErr: true},
		{name: "wildcard name", operation: policy.OpGitFetch, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "*"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGrantTargetForOperation(tc.operation, tc.target)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateGrantTargetForOperation() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestBucketWindowGrantPersistsExactKeyScope(t *testing.T) {
	policyJSON, _ := json.Marshal(map[string]any{"rules": []any{map[string]any{
		"id": "read-result", "effect": "request", "clients": []string{"agent"}, "operations": []string{"bucket.object.read"},
		"targets":      []any{map[string]any{"kind": "bucket", "owner": "acme", "name": "artifacts", "keys": []string{"runs/**"}}},
		"grant_policy": map[string]any{"mode": "window", "default_minutes": 5, "max_minutes": 5, "request_ttl_minutes": 5, "default_max_uses": 1, "max_uses": 2},
	}}})
	scp, err := policy.Parse(policyJSON)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{Config: config.Config{HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
		StateDir: filepath.Join(t.TempDir(), "state"), MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 10 * time.Second},
		Scope: scp, Audit: testAuditRecorder(), UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: &captureGrantNotifier{}})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	response, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(
		`{"operation":"bucket.object.read","target":{"kind":"bucket","owner":"acme","name":"artifacts","keys":["runs/one.json"]},"reason":"inspect result","client_request_id":"bucket-read"}`))
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("grant request = %d %s", response.StatusCode, body)
	}
	stored := decodeAPIGrantResponse(t, body)
	grant, err := handler.grants.Get(stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	target := targetFromGrant(grant)
	if target.Kind != policy.KindBucket || target.Owner != "acme" || target.Name != "artifacts" || len(target.Keys) != 1 || target.Keys[0] != "runs/one.json" {
		t.Fatalf("stored target = %#v", target)
	}
}

func TestAPIGrantsUseJSendAndClientScopedReads(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	var auditLog bytes.Buffer
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Config: config.Config{
			HFToken: testToken,
			Clients: []config.Client{
				{Name: "agent", Secret: testSecret},
				{Name: "other", Secret: testOtherSecret},
			},
			StateDir:     filepath.Join(dir, "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		Audit:           audit.New(&auditLog),
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/api/grants", "", nil)
	if resp.StatusCode != http.StatusUnauthorized || decodeJSendFailReason(t, body) != "missing_auth" {
		t.Fatalf("missing auth = %d %s, want 401 missing_auth", resp.StatusCode, body)
	}

	body = apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "api-idempotent", 5, 0)
	resp, body = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted || decodeJSendStatus(t, body) != "success" {
		t.Fatalf("grant create = %d %s, want 202 success", resp.StatusCode, body)
	}
	if len(notifier.messages) != 1 || strings.Contains(body, notifier.messages[0].DecisionToken) {
		t.Fatalf("grant create messages=%+v body=%s, want one message and no decision token leak", notifier.messages, body)
	}
	created := decodeAPIGrantResponse(t, body)
	if created.Operation != string(policy.OpGitPushForce) || len(created.Target.Refs) != 1 || created.Target.Refs[0] != "refs/heads/main" {
		t.Fatalf("created grant = %+v, want force grant for main", created)
	}
	if created.PendingUntil == nil || created.ExpiresAt != nil {
		t.Fatalf("created grant times = pending_until %v expires_at %v, want pending only", created.PendingUntil, created.ExpiresAt)
	}

	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants/"+created.ID, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK || decodeAPIGrantResponse(t, body).ID != created.ID {
		t.Fatalf("grant get = %d %s, want created grant", resp.StatusCode, body)
	}
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK || len(decodeAPIGrantList(t, body)) != 1 {
		t.Fatalf("grant list = %d %s, want one grant", resp.StatusCode, body)
	}
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants?status=bogus", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusBadRequest || decodeJSendFailReason(t, body) != "validation_failed" {
		t.Fatalf("bad grant list status filter = %d %s, want 400 validation_failed", resp.StatusCode, body)
	}
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants/"+created.ID, "Bearer "+testOtherSecret, nil)
	if resp.StatusCode != http.StatusNotFound || decodeJSendFailReason(t, body) != "grant_not_found" {
		t.Fatalf("cross-client grant get = %d %s, want 404 grant_not_found", resp.StatusCode, body)
	}

	conflictBody := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "different reason", "api-idempotent", 5, 0)
	resp, body = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(conflictBody))
	if resp.StatusCode != http.StatusConflict || decodeJSendFailReason(t, body) != "idempotency_conflict" {
		t.Fatalf("idempotency conflict = %d %s, want 409 idempotency_conflict", resp.StatusCode, body)
	}
	assertAuditContains(t, auditLog.String(),
		`"operation":"grant_read"`,
		`"target":"`+created.ID+`"`,
		`"operation":"grant_list"`,
		`"target":"grants"`,
		`"client":"other"`,
		`"reason":"grant_not_found"`,
		`"reason":"validation_failed"`,
	)
}

func assertAuditContains(t *testing.T, auditText string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(auditText, value) {
			t.Fatalf("audit missing %s:\n%s", value, auditText)
		}
	}
}

func TestAPIGrantResponsesPersistGrantMode(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"request-force-execution",
		"effect":"request",
		"clients":["agent"],
		"operations":["git.push.force"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
		"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5}
	}]}`))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Audit: testAuditRecorder(),
		Config: config.Config{
			HFToken:      testToken,
			Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:     filepath.Join(dir, "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 0, 0)))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("grant create = %d %s, want 202", resp.StatusCode, body)
	}
	created := decodeAPIGrantResponse(t, body)
	if created.Mode != policy.GrantModeExecution {
		t.Fatalf("created grant mode = %q, want execution", created.Mode)
	}

	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants/"+created.ID, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grant get = %d %s, want 200", resp.StatusCode, body)
	}
	if got := decodeAPIGrantResponse(t, body).Mode; got != policy.GrantModeExecution {
		t.Fatalf("get grant mode = %q, want execution", got)
	}

	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grant list = %d %s, want 200", resp.StatusCode, body)
	}
	listed := decodeAPIGrantList(t, body)
	if len(listed) != 1 || listed[0].Mode != policy.GrantModeExecution {
		t.Fatalf("listed grants = %+v, want one execution grant", listed)
	}
}

func TestGrantExpiresAtStringPtrOmitsNeverActiveExpiredGrant(t *testing.T) {
	expiresAt := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	if got := grantExpiresAtStringPtr(grants.Grant{Status: grants.StatusExpired, ExpiredFrom: grants.StatusPending, ExpiresAt: expiresAt}); got != nil {
		t.Fatalf("pending-expired grant expires_at = %q, want nil", *got)
	}
	if got := grantExpiresAtStringPtr(grants.Grant{Status: grants.StatusExpired, ExpiredFrom: grants.StatusActive, ExpiresAt: expiresAt}); got == nil {
		t.Fatalf("active-expired grant expires_at = nil, want timestamp")
	}
}

func TestAPIGrantNotifierFailureIsJSend(t *testing.T) {
	dir := t.TempDir()
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Audit: testAuditRecorder(),
		Config: config.Config{
			HFToken:      testToken,
			Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:     filepath.Join(dir, "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   failingGrantNotifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 0, 0)))
	if resp.StatusCode != http.StatusBadGateway || decodeJSendStatus(t, body) != "error" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("notifier failure = %d %q %s, want 502 JSend error", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	stored, err := handler.grants.ListForClient("agent")
	if err != nil || len(stored) != 1 || !stored[0].NotificationDeliveryUnresolved || stored[0].NotificationClaimedAt.IsZero() {
		t.Fatalf("stored notifier failure = %+v err=%v, want one unresolved claim", stored, err)
	}
}

func TestGrantNotificationWaitState(t *testing.T) {
	tests := []struct {
		name  string
		grant grants.Grant
		want  error
	}{
		{name: "canceled", grant: grants.Grant{Status: grants.StatusCanceled}, want: errGrantNotificationCanceled},
		{name: "unresolved", grant: grants.Grant{Status: grants.StatusPending, NotificationDeliveryUnresolved: true}, want: errGrantNotificationUnresolved},
		{name: "queued", grant: grants.Grant{Status: grants.StatusPending}, want: errGrantNotificationStillQueued},
		{name: "notified", grant: grants.Grant{Status: grants.StatusPending, Notification: &grants.MessageRef{MessageID: 1}}},
		{name: "terminal", grant: grants.Grant{Status: grants.StatusDenied}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := grantNotificationWaitState(test.grant); !errors.Is(got, test.want) || (got == nil) != (test.want == nil) {
				t.Fatalf("grantNotificationWaitState() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUnresolvedNotifierFailureSurvivesRestartAndRetriesAfterLease(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 7, 10, 7, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	nowFunc := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	advanceNow := func(duration time.Duration) {
		nowMu.Lock()
		defer nowMu.Unlock()
		now = now.Add(duration)
	}
	notifier := newBlockingGrantNotifier()
	notifier.firstErr = errors.New("notify failed")
	notifier.releaseSend()
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	newHandler := func() *Server {
		handler, err := New(Options{
			Audit: testAuditRecorder(),
			Config: config.Config{
				HFToken:      testToken,
				Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
				StateDir:     stateDir,
				MaxPackBytes: 25 * 1024 * 1024,
				HFTimeout:    10 * time.Second,
			},
			Scope:           scp,
			UpstreamBaseURL: "http://127.0.0.1:1",
			GrantNotifier:   notifier,
			Now:             nowFunc,
		})
		if err != nil {
			t.Fatal(err)
		}
		return handler
	}
	body := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "restart-unresolved", 0, 0)

	firstHandler := newHandler()
	firstBroker := httptest.NewServer(firstHandler)
	resp, responseBody := doRequest(t, http.MethodPost, firstBroker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	firstBroker.Close()
	if err := firstHandler.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("first request status=%d body=%q, want 502", resp.StatusCode, responseBody)
	}
	if notifier.calls() != 1 {
		t.Fatalf("first notifier calls = %d, want one", notifier.calls())
	}

	restartedHandler := newHandler()
	restartedBroker := httptest.NewServer(restartedHandler)
	started := time.Now()
	resp, responseBody = doRequest(t, http.MethodPost, restartedBroker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusBadGateway || time.Since(started) >= time.Second {
		t.Fatalf("restart request status=%d elapsed=%s body=%q, want prompt 502", resp.StatusCode, time.Since(started), responseBody)
	}
	if notifier.calls() != 1 {
		t.Fatalf("restart notifier calls = %d, want no duplicate", notifier.calls())
	}
	restartedBroker.Close()
	if err := restartedHandler.Close(); err != nil {
		t.Fatal(err)
	}

	advanceNow(grantNotificationClaimLease + time.Second)
	recoveredHandler := newHandler()
	t.Cleanup(func() { _ = recoveredHandler.Close() })
	deadline := time.Now().Add(2 * time.Second)
	for notifier.calls() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if notifier.calls() != 2 {
		t.Fatalf("recovered notifier calls = %d, want two without a client retry", notifier.calls())
	}
	tokens := notifier.decisionTokens()
	if len(tokens) != 2 || tokens[0] == "" || tokens[0] == tokens[1] {
		t.Fatalf("notification tokens = %+v, want two distinct non-empty tokens", tokens)
	}
	stored, err := recoveredHandler.grants.ListForClient("agent")
	if err != nil || len(stored) != 1 || stored[0].Notification == nil || stored[0].NotificationDeliveryUnresolved {
		t.Fatalf("stored post-lease grant = %+v err=%v", stored, err)
	}
}
