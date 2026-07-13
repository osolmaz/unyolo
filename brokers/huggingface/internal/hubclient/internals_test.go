package hubclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opbinding"
)

func TestRequestAndBindingInternalsFailClosed(t *testing.T) {
	client, _ := New("https://huggingface.co", "secret")
	ctx := context.Background()
	if _, err := client.newRequest(ctx, callSpec{method: http.MethodPost, path: "/api/test", body: map[string]any{}, rawBody: []byte("x")}); err == nil {
		t.Fatal("conflicting request bodies accepted")
	}
	if _, err := client.newRequest(ctx, callSpec{method: http.MethodPost, path: "/api/test", rawBody: make([]byte, maxRequestBodyBytes+1)}); err == nil {
		t.Fatal("oversized request body accepted")
	}
	if _, err := client.newRequest(ctx, callSpec{method: http.MethodGet, path: "/api/test", origin: "attacker"}); err == nil {
		t.Fatal("unknown fixed origin accepted")
	}
	binding := opbinding.Binding{ArgumentProjection: "items"}
	if _, err := boundBody(binding, nil, json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing argument projection accepted")
	}
	binding = opbinding.Binding{FixedBody: map[string]any{"enabled": true}, BodyFromTarget: map[string]string{"name": "name"}}
	body, err := boundBody(binding, json.RawMessage(`{"name":"demo"}`), json.RawMessage(`{"value":1}`))
	if err != nil || body.(map[string]any)["name"] != "demo" {
		t.Fatalf("boundBody() = %#v, %v", body, err)
	}
	if _, err := boundBody(binding, json.RawMessage(`{}`), json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing target body field accepted")
	}
	for _, value := range []any{"segment", float64(42)} {
		if _, ok := scalarPathValue(value); !ok {
			t.Fatalf("scalar path value rejected: %#v", value)
		}
	}
	for _, value := range []any{"../bad", -1.0, 1.5, true} {
		if _, ok := scalarPathValue(value); ok {
			t.Fatalf("unsafe scalar path value accepted: %#v", value)
		}
	}
}

func TestSandboxInternalValidationAndDecoding(t *testing.T) {
	valid := SandboxCommand{Argv: []string{"echo", "hi"}, MaxOutputBytes: 1024}
	if err := validateSandboxCommand(valid); err != nil {
		t.Fatal(err)
	}
	invalid := []SandboxCommand{
		{MaxOutputBytes: 1024},
		{Argv: []string{"echo"}, ShellCommand: "echo", MaxOutputBytes: 1024},
		{Argv: []string{""}, MaxOutputBytes: 1024},
		{Argv: []string{"echo"}, Background: true, Stdin: "x", MaxOutputBytes: 1024},
		{Argv: []string{"echo"}, WorkingDir: "bad\x00path", MaxOutputBytes: 1024},
		{Argv: []string{"echo"}, Environment: map[string]string{"BAD-KEY": "x"}, MaxOutputBytes: 1024},
	}
	for _, command := range invalid {
		if err := validateSandboxCommand(command); err == nil {
			t.Fatalf("invalid command accepted: %+v", command)
		}
	}
	for _, value := range []any{"echo", []any{"echo", "hi"}} {
		if !validSandboxCommandValue(value) {
			t.Fatalf("valid command value rejected: %#v", value)
		}
	}
	for _, value := range []any{"", []any{}, []any{"echo", 1}, true} {
		if validSandboxCommandValue(value) {
			t.Fatalf("invalid command value accepted: %#v", value)
		}
	}
	if !validSandboxMode("") || !validSandboxMode("0644") || validSandboxMode("0999") || validSandboxMode("12") {
		t.Fatal("sandbox mode validation mismatch")
	}
	if !isHex("0123456789abcdef", 16) || isHex("not-hex-not-hex!", 16) {
		t.Fatal("hex validation mismatch")
	}
	for _, raw := range [][]byte{
		[]byte("{\"event\":\"unknown\"}\n"),
		[]byte("{\"event\":\"exit\",\"exit_code\":0}\n{\"event\":\"exit\",\"exit_code\":0}\n"),
		[]byte("{\"event\":\"exit\"}\n"),
	} {
		if _, err := decodeSandboxCommandEvents(raw, 1024); err == nil {
			t.Fatalf("invalid command event stream accepted: %s", raw)
		}
	}
}

func TestSandboxJobProjectionRejectsProviderDrift(t *testing.T) {
	const jobID = "687fb701029421ae5549d998"
	const nonce = "0123456789abcdef0123456789abcdef"
	var job sandboxJobWire
	if err := json.Unmarshal([]byte(sandboxJobFixture(jobID, nonce, modeDedicated)), &job); err != nil {
		t.Fatal(err)
	}
	if state, err := sandboxStateFromJob(job, "acme", ""); err != nil || state.Stage != "RUNNING" {
		t.Fatalf("sandboxStateFromJob() = %+v, %v", state, err)
	}
	mutations := []func(*sandboxJobWire){
		func(value *sandboxJobWire) { value.Owner.Name = "other" },
		func(value *sandboxJobWire) { value.Labels[sandboxLabel] = "0" },
		func(value *sandboxJobWire) { value.Labels[sandboxModeLabel] = "unknown" },
		func(value *sandboxJobWire) { value.Status.Stage = "MYSTERY" },
		func(value *sandboxJobWire) { value.Flavor = "root" },
	}
	for _, mutate := range mutations {
		copy := job
		copy.Labels = map[string]string{}
		for key, value := range job.Labels {
			copy.Labels[key] = value
		}
		mutate(&copy)
		if _, err := sandboxStateFromJob(copy, "acme", ""); err == nil {
			t.Fatal("drifted sandbox job accepted")
		}
	}
	if value, ok := optionalEnvironmentInt(map[string]any{"COUNT": "3"}, "COUNT", 1, 4); !ok || value != 3 {
		t.Fatalf("optionalEnvironmentInt() = %d, %v", value, ok)
	}
	for _, environment := range []map[string]any{{"COUNT": 3}, {"COUNT": "9"}, {"COUNT": "bad"}} {
		if _, ok := optionalEnvironmentInt(environment, "COUNT", 1, 4); ok {
			t.Fatalf("invalid environment integer accepted: %#v", environment)
		}
	}
}

func TestSandboxServerRequestBoundsAndEndpointSelection(t *testing.T) {
	client, _ := New("https://huggingface.co", "secret")
	endpoint := sandboxEndpoint{base: "https://job--49983.hf.jobs", token: "sandbox-token"}
	if _, err := client.sandboxServer(context.Background(), endpoint, sandboxRequest{method: http.MethodPost, path: "/v1/test", body: map[string]any{}, rawBody: []byte("x")}); err == nil {
		t.Fatal("conflicting sandbox request bodies accepted")
	}
	if _, err := client.sandboxServer(context.Background(), endpoint, sandboxRequest{method: http.MethodPost, path: "/v1/test", rawBody: make([]byte, maxRequestBodyBytes+1)}); err == nil {
		t.Fatal("oversized sandbox request accepted")
	}
	job := sandboxJobWire{ID: "job", Labels: map[string]string{sandboxNonceLabel: "0123456789abcdef0123456789abcdef"}}
	job.Status.ExposeURLs = []string{"https://attacker.example", "http://job--49983.hf.jobs", "https://job--49983.hf.jobs/path"}
	if _, err := client.sandboxEndpoint(job, SandboxRef{Namespace: "acme", JobID: "job"}); err == nil {
		t.Fatal("untrusted sandbox endpoint accepted")
	}
	job.Status.ExposeURLs = []string{"https://job--49983.hf.jobs"}
	if selected, err := client.sandboxEndpoint(job, SandboxRef{Namespace: "acme", JobID: "job"}); err != nil || !strings.HasPrefix(selected.base, "https://job--49983") {
		t.Fatalf("sandboxEndpoint() = %+v, %v", selected, err)
	}
	query := url.Values{"path": []string{"/tmp/file"}}
	if query.Encode() == "" {
		t.Fatal("query fixture is empty")
	}
}

func TestWireProjectionHelpers(t *testing.T) {
	for raw, want := range map[string]GatedMode{"false": GatedDisabled, `"auto"`: GatedAuto, `"manual"`: GatedManual, `"other"`: GatedUnknown} {
		if got := gatedFromWire(json.RawMessage(raw)); got != want {
			t.Errorf("gatedFromWire(%s) = %q, want %q", raw, got, want)
		}
	}
	refs := Refs{Branches: []GitRef{{Name: "main"}}}
	if _, found := refs.Branch("missing"); found {
		t.Fatal("missing branch found")
	}
	header := http.Header{"Retry-After": []string{"bad"}}
	if got := statusError(http.StatusTooManyRequests, header); got.RetryAfterSeconds != 0 {
		t.Fatalf("invalid retry-after = %d", got.RetryAfterSeconds)
	}
	if text := (&Error{Code: CodeForbidden, StatusCode: 403}).Error(); !strings.Contains(text, "403") {
		t.Fatalf("error text = %q", text)
	}
}
