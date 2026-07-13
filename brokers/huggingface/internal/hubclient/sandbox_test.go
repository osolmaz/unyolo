package hubclient

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type rewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Hostname(), ".hf.jobs") {
		cloned := request.Clone(request.Context())
		cloned.URL.Scheme = t.target.Scheme
		cloned.URL.Host = t.target.Host
		return t.base.RoundTrip(cloned)
	}
	return t.base.RoundTrip(request)
}

func TestSandboxClientDerivesTrustedServerCredentialsAndBoundsCommand(t *testing.T) {
	const jobID = "687fb701029421ae5549d998"
	const nonce = "0123456789abcdef0123456789abcdef"
	mac := hmac.New(sha256.New, []byte("hf-secret"))
	_, _ = io.WriteString(mac, "hf-sandbox:"+nonce)
	wantSandboxToken := hex.EncodeToString(mac.Sum(nil))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/jobs/acme/"+jobID:
			_, _ = io.WriteString(w, `{"id":"`+jobID+`","dockerImage":"python:3.12","environment":{},"flavor":"cpu-basic","labels":{"hf-sandbox":"1","hf-sandbox-mode":"dedicated","hf-sandbox-nonce":"`+nonce+`"},"status":{"stage":"RUNNING","exposeUrls":["https://`+jobID+`--49983.hf.jobs"]},"owner":{"name":"acme"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/exec":
			if r.Header.Get("Authorization") != "Bearer hf-secret" || r.Header.Get("X-Sandbox-Token") != wantSandboxToken {
				t.Fatalf("sandbox auth headers = %q, %q", r.Header.Get("Authorization"), r.Header.Get("X-Sandbox-Token"))
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload["shell"] != false {
				t.Fatalf("command payload = %#v, %v", payload, err)
			}
			_, _ = io.WriteString(w, "{\"event\":\"stdout\",\"data\":\"hello\\n\"}\n{\"event\":\"exit\",\"exit_code\":0,\"duration_ms\":12}\n")
		default:
			t.Fatalf("unexpected sandbox request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	client, err := New(server.URL, "hf-secret", WithHTTPTransport(rewriteTransport{target: target, base: server.Client().Transport}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.RunSandboxCommand(context.Background(), SandboxRef{Namespace: "acme", JobID: jobID}, SandboxCommand{
		Argv: []string{"printf", "hello\\n"}, MaxOutputBytes: 1024,
	})
	if err != nil || result.ExitCode == nil || *result.ExitCode != 0 || result.Stdout != "hello\n" {
		t.Fatalf("RunSandboxCommand() = %#v, %v", result, err)
	}
}

func TestSandboxClientRejectsRequesterControlledOrUntrustedServerEndpoints(t *testing.T) {
	const jobID = "687fb701029421ae5549d998"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = io.WriteString(w, `{"id":"`+jobID+`","dockerImage":"python:3.12","environment":{},"flavor":"cpu-basic","labels":{"hf-sandbox":"1","hf-sandbox-mode":"dedicated","hf-sandbox-nonce":"0123456789abcdef0123456789abcdef"},"status":{"stage":"RUNNING","exposeUrls":["https://attacker.example/v1"]},"owner":{"name":"acme"}}`)
	}))
	defer server.Close()
	client, _ := New(server.URL, "secret", WithHTTPTransport(server.Client().Transport))
	_, err := client.RunSandboxCommand(context.Background(), SandboxRef{Namespace: "acme", JobID: jobID}, SandboxCommand{
		ShellCommand: "id", MaxOutputBytes: 1024,
	})
	if err == nil || requests != 1 {
		t.Fatalf("untrusted endpoint result = %v, requests = %d", err, requests)
	}
}

func TestSandboxCreateUsesFixedBootstrapAndKeepsBrokerTokenInJobSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/jobs/acme" {
			t.Fatalf("create request = %s %s", r.Method, r.URL.Path)
		}
		var body sandboxJobBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Secrets["SBX_DL_TOKEN"] != "hf-secret" || body.Environment["SBX_DL_TOKEN"] != "" ||
			body.Labels[sandboxNonceLabel] == "" || body.Labels[sandboxNameLabel] != "review" ||
			body.Command[0] != "/bin/sh" || body.Expose.Ports[0] != SandboxServerPort ||
			body.Volumes[len(body.Volumes)-1].Source != "huggingface/sbx-server" {
			t.Fatalf("sandbox job body = %#v", body)
		}
		_, _ = io.WriteString(w, `{"id":"687fb701029421ae5549d998","dockerImage":"python:3.12","environment":{},"flavor":"cpu-basic","labels":{"hf-sandbox":"1","hf-sandbox-mode":"dedicated","hf-sandbox-nonce":"`+body.Labels[sandboxNonceLabel]+`"},"status":{"stage":"SCHEDULING"},"owner":{"name":"acme"}}`)
	}))
	defer server.Close()
	client, _ := New(server.URL, "hf-secret", WithHTTPTransport(server.Client().Transport))
	state, err := client.CreateSandbox(context.Background(), SandboxCreateSpec{Namespace: "acme", Name: "review", OperationID: "operation_123",
		Image: "python:3.12", Flavor: "cpu-basic", Environment: map[string]string{"MODE": "test"}, Secrets: map[string]string{"TOKEN": "value"}})
	if err != nil || state.Ref.JobID == "" || state.Stage != "SCHEDULING" {
		t.Fatalf("CreateSandbox() = %#v, %v", state, err)
	}
}

func TestSandboxCommandDecoderRejectsOutputOverflowAndMissingExit(t *testing.T) {
	if _, err := decodeSandboxCommandEvents([]byte("{\"event\":\"stdout\",\"data\":\"12345\"}\n{\"event\":\"exit\",\"exit_code\":0}\n"), 4); err == nil {
		t.Fatal("output overflow accepted")
	}
	if _, err := decodeSandboxCommandEvents([]byte("{\"event\":\"stdout\",\"data\":\"ok\"}\n"), 4); err == nil {
		t.Fatal("missing exit event accepted")
	}
}

func TestSandboxClientExercisesDedicatedAndPooledServerOperations(t *testing.T) {
	const jobID = "687fb701029421ae5549d998"
	const nonce = "0123456789abcdef0123456789abcdef"
	mode := modeDedicated
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/jobs/acme/"+jobID {
			_, _ = io.WriteString(w, sandboxJobFixture(jobID, nonce, mode))
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/jobs/acme/"+jobID+"/cancel":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec"):
			_, _ = io.WriteString(w, "{\"event\":\"ping\"}\n{\"event\":\"stderr\",\"data\":\"warn\"}\n{\"event\":\"exit\",\"exit_code\":0}\n")
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/processes"):
			_, _ = io.WriteString(w, `{"pid":42}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/files/stat"):
			_, _ = io.WriteString(w, `{"name":"result","path":"/tmp/result","type":"file","size":2,"mode":"0644"}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/processes"):
			_, _ = io.WriteString(w, `[{"pid":42,"cmd":["sleep","60"],"running":true}]`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes":
			_, _ = io.WriteString(w, `{"sandboxes":[{"id":"local-1"}],"rejected":0}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes":
			_, _ = io.WriteString(w, `[{"id":"local-1"}]`)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	client, err := New(server.URL, "hf-secret", WithHTTPTransport(rewriteTransport{target: target, base: server.Client().Transport}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dedicated := SandboxRef{Namespace: "acme", JobID: jobID}
	if state, err := client.SandboxState(ctx, dedicated); err != nil || state.Mode != modeDedicated {
		t.Fatalf("SandboxState() = %+v, %v", state, err)
	}
	if result, err := client.RunSandboxCommand(ctx, dedicated, SandboxCommand{ShellCommand: "echo hi", MaxOutputBytes: 4096}); err != nil || result.ExitCode == nil || result.Stderr != "warn" {
		t.Fatalf("RunSandboxCommand() = %+v, %v", result, err)
	}
	if result, err := client.RunSandboxCommand(ctx, dedicated, SandboxCommand{Argv: []string{"sleep", "60"}, Background: true, MaxOutputBytes: 4096}); err != nil || result.PID != 42 {
		t.Fatalf("RunSandboxCommand(background) = %+v, %v", result, err)
	}
	if info, err := client.SandboxFileStat(ctx, dedicated, "/tmp/result"); err != nil || info.Size != 2 {
		t.Fatalf("SandboxFileStat() = %+v, %v", info, err)
	}
	for name, call := range map[string]func() error{
		"write":  func() error { return client.WriteSandboxFile(ctx, dedicated, "/tmp/result", "0644", []byte("hi")) },
		"mkdir":  func() error { return client.MakeSandboxDirectory(ctx, dedicated, "/tmp/output") },
		"delete": func() error { return client.DeleteSandboxFile(ctx, dedicated, "/tmp/result", true) },
		"kill":   func() error { return client.KillSandboxProcess(ctx, dedicated, 42) },
	} {
		if err := call(); err != nil {
			t.Fatalf("%s operation: %v", name, err)
		}
	}
	if processes, err := client.SandboxProcesses(ctx, dedicated); err != nil || len(processes) != 1 || processes[0].PID != 42 {
		t.Fatalf("SandboxProcesses() = %+v, %v", processes, err)
	}
	if err := client.DeleteSandbox(ctx, dedicated); err != nil {
		t.Fatal(err)
	}

	mode = modePool
	host := SandboxRef{Namespace: "acme", JobID: jobID}
	local, err := client.CreateSandboxInPool(ctx, host, map[string]string{"MODE": "test"}, nil)
	if err != nil || local.LocalID != "local-1" {
		t.Fatalf("CreateSandboxInPool() = %+v, %v", local, err)
	}
	if state, err := client.SandboxState(ctx, local); err != nil || state.Ref.LocalID != "local-1" {
		t.Fatalf("pooled SandboxState() = %+v, %v", state, err)
	}
	if err := client.DeleteSandbox(ctx, local); err != nil {
		t.Fatal(err)
	}
}

func sandboxJobFixture(jobID, nonce, mode string) string {
	pool := ""
	environment := `{}`
	if mode == modePool {
		pool = `,"hf-sandbox-pool":"workers"`
		environment = `{"SBX_CAPACITY":"10","SBX_MAX_HOSTS":"3"}`
	}
	return `{"id":"` + jobID + `","dockerImage":"python:3.12","environment":` + environment + `,"flavor":"cpu-basic","labels":{"hf-sandbox":"1","hf-sandbox-mode":"` + mode + `","hf-sandbox-nonce":"` + nonce + `"` + pool + `},"status":{"stage":"RUNNING","exposeUrls":["https://` + jobID + `--49983.hf.jobs"]},"owner":{"name":"acme"}}`
}

func TestSandboxPoolJobLifecycle(t *testing.T) {
	const jobID = "687fb701029421ae5549d998"
	const nonce = "0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/jobs/acme":
			var body sandboxJobBody
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			body.Labels[sandboxNonceLabel] = nonce
			_, _ = io.WriteString(w, sandboxJobFixture(jobID, nonce, modePool))
		case r.Method == http.MethodGet && r.URL.Path == "/api/jobs/acme" && r.URL.Query().Get("label") != "":
			_, _ = io.WriteString(w, `[`+sandboxJobFixture(jobID, nonce, modePool)+`]`)
		default:
			t.Fatalf("unexpected pool request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "hf-secret", WithHTTPTransport(server.Client().Transport))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ref := SandboxPoolRef{Namespace: "acme", Name: "workers"}
	state, err := client.CreateSandboxPoolHost(ctx, SandboxPoolSpec{Ref: ref, OperationID: "operation-1", Image: "python:3.12", Flavor: "cpu-basic", SandboxesPerHost: 10, MaxHosts: 3})
	if err != nil || state.Mode != modePool {
		t.Fatalf("CreateSandboxPoolHost() = %+v, %v", state, err)
	}
	states, err := client.ListSandboxPool(ctx, ref)
	if err != nil || len(states) != 1 || states[0].Pool != "workers" {
		t.Fatalf("ListSandboxPool() = %+v, %v", states, err)
	}
	states, err = client.ListSandboxesByOperation(ctx, "acme", "operation-1")
	if err == nil || states != nil {
		// The fixture intentionally lacks the requested operation label; a
		// mismatched upstream result must fail closed.
		t.Fatalf("ListSandboxesByOperation() = %+v, %v", states, err)
	}
}
