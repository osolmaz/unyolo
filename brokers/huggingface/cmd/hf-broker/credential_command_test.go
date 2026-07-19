package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/credentialauth"
	"github.com/osolmaz/brokerkit/credentiallifecycle"
	"github.com/osolmaz/brokerkit/providercredential"
	bkservice "github.com/osolmaz/brokerkit/service"
)

func TestCredentialInspectReadsTokenFromStdinWithoutLeakingIt(t *testing.T) {
	var stdout strings.Builder
	deps := credentialTestDependencies()
	command := commandContext{ctx: context.Background(), stdin: strings.NewReader("hf_secret\n"), stdout: &stdout, stderr: io.Discard}
	if err := runCredential(command, []string{"inspect", "--token-stdin", "--json"}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"subject":"alice"`) || strings.Contains(stdout.String(), "hf_secret") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestCredentialRepairNoninteractiveRequiresExplicitPrivilege(t *testing.T) {
	var stdout strings.Builder
	deps := credentialTestDependencies()
	deps.euid = func() int { return 1000 }
	deps.openURL = func(context.Context, string) error {
		t.Fatal("noninteractive repair opened a browser")
		return nil
	}
	deps.runElevated = func(context.Context, string, []string, io.Writer, io.Writer) error {
		t.Fatal("noninteractive repair elevated implicitly")
		return nil
	}
	command := commandContext{ctx: context.Background(), stdin: strings.NewReader("hf_candidate\n"), stdout: &stdout, stderr: io.Discard}
	err := runCredential(command, []string{"repair", "--no-open", "--token-stdin", "--json"}, deps)
	if err == nil || !strings.Contains(stdout.String(), `"code":"credential_privilege_required"`) {
		t.Fatalf("noninteractive repair error/output = %v, %q", err, stdout.String())
	}
	if strings.Contains(stdout.String(), credentialauth.TokenFormURL) || strings.Contains(stdout.String(), "hf_candidate") {
		t.Fatalf("noninteractive output leaked presentation or token: %q", stdout.String())
	}
}

func TestCredentialInteractiveElevationPreservesExplicitOutputFlags(t *testing.T) {
	deps := credentialTestDependencies()
	var elevatedToken string
	var elevatedArgs []string
	deps.runElevated = func(_ context.Context, token string, args []string, _, _ io.Writer) error {
		elevatedToken = token
		elevatedArgs = append([]string(nil), args...)
		return nil
	}
	options := credentialOptions{jsonOutput: true, verbose: true}
	command := commandContext{ctx: t.Context(), stdout: io.Discard, stderr: io.Discard}
	if err := elevateCredentialRepair(command, options, deps, "hf_candidate"); err != nil {
		t.Fatal(err)
	}
	if elevatedToken != "hf_candidate\n" || strings.Join(elevatedArgs, " ") != "credential __activate --token-stdin --json --verbose" {
		t.Fatalf("elevated input = %q, args=%v", elevatedToken, elevatedArgs)
	}
}

func TestCredentialActivationBuildsExactReplacement(t *testing.T) {
	deps := credentialTestDependencies()
	deps.euid = func() int { return 0 }
	var plan bkservice.CredentialReplacePlan
	deps.replace = func(_ context.Context, candidate bkservice.CredentialReplacePlan) error {
		plan = candidate
		return nil
	}
	command := commandContext{ctx: context.Background(), stdin: strings.NewReader("hf_candidate\n"), stdout: io.Discard, stderr: io.Discard}
	if err := runCredential(command, []string{"__activate", "--token-stdin"}, deps); err != nil {
		t.Fatal(err)
	}
	if len(plan.Files) != 2 || plan.Files[0].Name != "hf-token" || plan.Files[1].Name != credentialStatusFileName || plan.Lifecycle == nil {
		t.Fatalf("replacement plan = %+v", plan)
	}
	if string(plan.Files[0].Data) != "hf_candidate\n" || strings.Contains(string(plan.Files[1].Data), "hf_candidate") {
		t.Fatal("replacement payload is incorrect or metadata leaked the token")
	}
}

func TestCredentialRepairInteractiveOutputIsCompactAndWidthAware(t *testing.T) {
	deps := credentialTestDependencies()
	deps.euid = func() int { return 0 }
	deps.terminalWidth = func(io.Writer) int { return 40 }
	deps.readHidden = func(_ io.Reader, output io.Writer) (string, error) {
		_, _ = io.WriteString(output, "Hugging Face token (input hidden): \n")
		return "hf_candidate", nil
	}
	var stdout, stderr strings.Builder
	command := commandContext{ctx: t.Context(), stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr}
	if err := runCredential(command, []string{"repair"}, deps); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	for _, want := range []string{"Hugging Face credential repair", "dedicated fine-grained token", "Credential ready", "Subject: alice", "Capabilities: 2"} {
		if !strings.Contains(output, want) {
			t.Fatalf("interactive output missing %q: %q", want, output)
		}
	}
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		if line == credentialauth.TokenFormURL {
			continue
		}
		if len(line) > 40 {
			t.Fatalf("line exceeded terminal width: %d %q", len(line), line)
		}
	}
	if strings.Count(output, credentialauth.TokenFormURL) != 1 || strings.Contains(output, `"operation":"credential.lifecycle"`) ||
		strings.Contains(output, "hf_candidate") || stderr.Len() != 0 {
		t.Fatalf("interactive output was noisy or unsafe: stdout=%q stderr=%q", output, stderr.String())
	}
}

func TestCredentialRepairJSONOutputIsPureAndSecretFree(t *testing.T) {
	deps := credentialTestDependencies()
	deps.euid = func() int { return 0 }
	deps.openURL = func(context.Context, string) error {
		t.Fatal("JSON repair opened a browser")
		return nil
	}
	deps.readHidden = func(io.Reader, io.Writer) (string, error) {
		t.Fatal("JSON repair prompted for input")
		return "", nil
	}
	var stdout, stderr strings.Builder
	command := commandContext{ctx: t.Context(), stdin: strings.NewReader("hf_candidate\n"), stdout: &stdout, stderr: &stderr}
	if err := runCredential(command, []string{"repair", "--token-stdin", "--json"}, deps); err != nil {
		t.Fatal(err)
	}
	var result credentialStatus
	decoder := json.NewDecoder(strings.NewReader(stdout.String()))
	if err := decoder.Decode(&result); err != nil || result.Status != "valid" || result.Snapshot.Subject != "alice" || len(result.Snapshot.Capabilities) != 2 {
		t.Fatalf("JSON repair result = %+v, %v; output=%q", result, err, stdout.String())
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("JSON repair emitted extra output: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), credentialauth.TokenFormURL) || strings.Contains(stdout.String(), "hf_candidate") || stderr.Len() != 0 {
		t.Fatalf("JSON output was noisy or unsafe: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestCredentialRepairFailureOutputIsReadableAndRedacted(t *testing.T) {
	deps := credentialTestDependencies()
	deps.euid = func() int { return 0 }
	deps.inspect = func(context.Context, string, string, uint64) (providercredential.Snapshot, error) {
		return providercredential.Snapshot{}, errors.New("Hugging Face did not accept this token")
	}
	var stdout strings.Builder
	command := commandContext{ctx: t.Context(), stdin: strings.NewReader("hf_candidate\n"), stdout: &stdout, stderr: io.Discard}
	err := runCredential(command, []string{"repair", "--no-open", "--token-stdin"}, deps)
	if err == nil || !strings.Contains(err.Error(), "Credential not changed") || !strings.Contains(err.Error(), "did not accept this token") {
		t.Fatalf("interactive failure = %v", err)
	}
	if strings.Contains(err.Error(), "hf_candidate") || strings.Contains(stdout.String(), "Credential ready") {
		t.Fatalf("interactive failure leaked or reported success: err=%q stdout=%q", err, stdout.String())
	}

	deps.inspect = func(context.Context, string, string, uint64) (providercredential.Snapshot, error) {
		return providercredential.Snapshot{}, errors.New("upstream exposed hf_candidate in an unsafe error")
	}
	stdout.Reset()
	command.stdin = strings.NewReader("hf_candidate\n")
	err = runCredential(command, []string{"repair", "--no-open", "--token-stdin", "--json"}, deps)
	if err == nil || strings.Contains(stdout.String(), "hf_candidate") || !strings.Contains(stdout.String(), `"code":"credential_repair_failed"`) {
		t.Fatalf("JSON failure was not redacted: err=%v output=%q", err, stdout.String())
	}
}

func TestCredentialRepairLifecycleAuditIsDurableAndVerboseOnly(t *testing.T) {
	for _, test := range []struct {
		name    string
		verbose bool
	}{
		{name: "normal"},
		{name: "verbose", verbose: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := credentialTestDependencies()
			deps.euid = func() int { return 0 }
			var durable, stderr strings.Builder
			deps.openAudit = func(_ string, verbose io.Writer) (io.WriteCloser, error) {
				writers := []io.Writer{&durable}
				if verbose != nil {
					writers = append(writers, verbose)
				}
				return nopWriteCloser{Writer: io.MultiWriter(writers...)}, nil
			}
			deps.replace = func(_ context.Context, plan bkservice.CredentialReplacePlan) error {
				return plan.Lifecycle.Record(credentiallifecycle.Event{
					Class: "huggingface-access", Action: credentiallifecycle.ActionRotated,
					Outcome: credentiallifecycle.OutcomeSucceeded, Provider: "huggingface",
				})
			}
			args := []string{"__activate", "--token-stdin"}
			if test.verbose {
				args = append(args, "--verbose")
			}
			command := commandContext{ctx: t.Context(), stdin: strings.NewReader("hf_candidate\n"), stdout: io.Discard, stderr: &stderr}
			if err := runCredential(command, args, deps); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(durable.String(), `"operation":"credential.lifecycle"`) || strings.Contains(durable.String(), "hf_candidate") {
				t.Fatalf("durable audit = %q", durable.String())
			}
			if test.verbose != strings.Contains(stderr.String(), `"operation":"credential.lifecycle"`) {
				t.Fatalf("verbose audit visibility = %t, stderr=%q", test.verbose, stderr.String())
			}
		})
	}
}

func TestCredentialAuditFileIsProtectedAndAppended(t *testing.T) {
	dir := t.TempDir()
	var verbose strings.Builder
	for index := 0; index < 2; index++ {
		output, err := openCredentialAudit(dir, &verbose)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(output, fmt.Sprintf("event-%d\n", index)); err != nil {
			t.Fatal(err)
		}
		if err := output.Close(); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, credentialAuditFileName)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "event-0\nevent-1\n" || verbose.String() != string(data) {
		t.Fatalf("audit data = %q, verbose=%q, err=%v", data, verbose.String(), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode = %v, err=%v", info.Mode().Perm(), err)
	}
}

func TestCredentialRootRepairIncrementsInstalledGeneration(t *testing.T) {
	deps := credentialTestDependencies()
	deps.euid = func() int { return 0 }
	existing, err := deps.inspect(t.Context(), "", "hf_candidate", 7)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(credentialStatus{Status: "valid", Snapshot: existing})
	if err != nil {
		t.Fatal(err)
	}
	deps.readFile = func(string) ([]byte, error) { return metadata, nil }
	inspect := deps.inspect
	inspectedGeneration := uint64(0)
	deps.inspect = func(ctx context.Context, baseURL, token string, generation uint64) (providercredential.Snapshot, error) {
		inspectedGeneration = generation
		return inspect(ctx, baseURL, token, generation)
	}
	command := commandContext{ctx: t.Context(), stdin: strings.NewReader("hf_candidate\n"), stdout: io.Discard, stderr: io.Discard}
	if err := runCredential(command, []string{"repair", "--no-open", "--token-stdin"}, deps); err != nil {
		t.Fatal(err)
	}
	if inspectedGeneration != 8 {
		t.Fatalf("root repair generation = %d, want 8", inspectedGeneration)
	}
}

func TestCredentialActivationRefusesCorruptGenerationMetadata(t *testing.T) {
	deps := credentialTestDependencies()
	deps.euid = func() int { return 0 }
	deps.readFile = func(string) ([]byte, error) { return []byte(`{"status":"valid","snapshot":{}}`), nil }
	deps.replace = func(context.Context, bkservice.CredentialReplacePlan) error {
		t.Fatal("replacement ran with corrupt generation metadata")
		return nil
	}
	command := commandContext{ctx: context.Background(), stdin: strings.NewReader("hf_candidate\n"), stdout: io.Discard, stderr: io.Discard}
	if err := runCredential(command, []string{"__activate", "--token-stdin"}, deps); err == nil || !strings.Contains(err.Error(), "status is invalid") {
		t.Fatalf("activation error = %v", err)
	}
}

func TestCredentialRepairRejectsCandidateBeforeElevation(t *testing.T) {
	deps := credentialTestDependencies()
	deps.inspect = func(context.Context, string, string, uint64) (providercredential.Snapshot, error) {
		return providercredential.Snapshot{}, errors.New("rejected")
	}
	deps.runElevated = func(context.Context, string, []string, io.Writer, io.Writer) error {
		t.Fatal("invalid token was elevated")
		return nil
	}
	command := commandContext{ctx: context.Background(), stdin: strings.NewReader("hf_candidate\n"), stdout: io.Discard, stderr: io.Discard}
	if err := runCredential(command, []string{"repair", "--no-open", "--token-stdin"}, deps); err == nil {
		t.Fatal("repair accepted invalid candidate")
	}
}

func TestCredentialRequirementsCommandWasRemoved(t *testing.T) {
	command := commandContext{ctx: context.Background(), stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard}
	if err := runCredential(command, []string{"requirements"}, credentialTestDependencies()); err == nil {
		t.Fatal("legacy requirements command still exists")
	}
}

func TestCredentialStatusReadsProtectedMetadata(t *testing.T) {
	deps := credentialTestDependencies()
	deps.euid = func() int { return 0 }
	snapshot, err := deps.inspect(t.Context(), "", "hf_candidate", 7)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(credentialStatus{Status: "valid", Snapshot: snapshot})
	deps.readFile = func(string) ([]byte, error) { return data, nil }
	var output strings.Builder
	command := commandContext{ctx: t.Context(), stdin: strings.NewReader(""), stdout: &output, stderr: io.Discard}
	if err := runCredential(command, []string{"status", "--json"}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"generation":7`) {
		t.Fatalf("status output = %s", output.String())
	}
	generation, err := nextCredentialGeneration(deps)
	if err != nil || generation != 8 {
		t.Fatalf("next generation = %d, %v", generation, err)
	}
}

func TestActiveCredentialStatusPreservesGeneration(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, hfTokenFileName)
	deps := credentialTestDependencies()
	snapshot, err := deps.inspect(t.Context(), "", "hf_candidate", 7)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(credentialStatus{Status: "valid", Snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, credentialStatusFileName), data, 0o640); err != nil {
		t.Fatal(err)
	}
	status, err := loadActiveCredentialStatus(tokenFile)
	if err != nil || status == nil || status.Snapshot.Generation != 7 {
		t.Fatalf("active status = %+v, %v", status, err)
	}
	status.Snapshot.CapabilityDigest = strings.Repeat("0", 64)
	data, _ = json.Marshal(status)
	if err := os.WriteFile(filepath.Join(dir, credentialStatusFileName), data, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadActiveCredentialStatus(tokenFile); err == nil {
		t.Fatal("tampered credential metadata was accepted")
	}
}

func TestCredentialStatusElevatesWithoutReadingToken(t *testing.T) {
	deps := credentialTestDependencies()
	deps.euid = func() int { return 1000 }
	called := false
	deps.runElevated = func(_ context.Context, token string, args []string, _, _ io.Writer) error {
		called = true
		if token != "" || strings.Join(args, " ") != "credential __status --json" {
			t.Fatalf("elevated status = %q %v", token, args)
		}
		return nil
	}
	command := commandContext{ctx: t.Context(), stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard}
	if err := runCredential(command, []string{"status", "--json"}, deps); err != nil || !called {
		t.Fatalf("status = %v, called=%v", err, called)
	}
	if err := runCredential(command, []string{"status", "--token-stdin"}, deps); err == nil {
		t.Fatal("status accepted token input")
	}
	var output strings.Builder
	command.stdout = &output
	if err := runCredential(command, []string{"status", "--token-stdin", "--json"}, deps); err == nil ||
		!strings.Contains(output.String(), `"code":"credential_usage_invalid"`) {
		t.Fatalf("JSON status usage error = %v, output=%q", err, output.String())
	}
	output.Reset()
	deps.runElevated = func(_ context.Context, _ string, _ []string, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, `{"schema_version":1,"status":"error"}`+"\n")
		return credentialPresentedError{code: 1}
	}
	if err := runCredential(command, []string{"status", "--json"}, deps); err == nil ||
		strings.Count(output.String(), `"status":"error"`) != 1 {
		t.Fatalf("elevated JSON status error = %v, output=%q", err, output.String())
	}
}

func TestCredentialErrorClassificationAndPresentationHelpers(t *testing.T) {
	tests := []struct {
		message string
		code    string
	}{
		{"credential repair --json requires --token-stdin", "credential_usage_invalid"},
		{"invalid credential repair options", "credential_usage_invalid"},
		{"noninteractive credential repair must run with root privileges; invoke hf-broker through an approved privilege boundary", "credential_privilege_required"},
		{"Hugging Face token has an invalid format", "credential_input_invalid"},
		{"interactive token input requires a terminal; use --token-stdin", "credential_input_invalid"},
		{"HF Broker requires a dedicated fine-grained Hugging Face token", "credential_kind_unsupported"},
		{"Hugging Face did not accept this token", "credential_authentication_failed"},
		{"Hugging Face credential inspection was rate limited", "credential_provider_unavailable"},
		{"HF Broker credential status is invalid; run hf-broker credential repair", "credential_status_invalid"},
		{"HF Broker credential status is unavailable; run hf-broker credential repair", "credential_status_unavailable"},
		{"unsafe hf_secret_value", "credential_repair_failed"},
	}
	for _, test := range tests {
		code, message := safeCredentialError(errors.New(test.message))
		if code != test.code || strings.Contains(message, "hf_secret_value") {
			t.Fatalf("safeCredentialError(%q) = %q, %q", test.message, code, message)
		}
	}
	if width := credentialTerminalWidth(&strings.Builder{}); width != defaultCredentialWidth {
		t.Fatalf("nonterminal width = %d", width)
	}
	for _, args := range [][]string{{"--json"}, {"-json"}, {"--json=true"}, {"-json=1"}, {"--json=True"}} {
		if !credentialFlagPresent(args, "--json") {
			t.Fatalf("JSON flag %v was not recognized", args)
		}
	}
	for _, args := range [][]string{{"--json=false"}, {"-json=0"}, {"--json=invalid"}} {
		if credentialFlagPresent(args, "--json") {
			t.Fatalf("disabled or invalid JSON flag %v was enabled", args)
		}
	}
	failure := presentCredentialError(commandContext{stdout: io.Discard}, []string{"repair"}, errors.New("post-activation failure hf_secret_value"))
	if !strings.Contains(failure.Error(), "Credential repair failed") || strings.Contains(failure.Error(), "hf_secret_value") {
		t.Fatalf("ambiguous repair failure = %q", failure)
	}
	if err := validateCredentialRepairInput(credentialOptions{}, true); err == nil {
		t.Fatal("activation without standard-input token was accepted")
	}
	deps := credentialTestDependencies()
	deps.openURL = func(context.Context, string) error {
		t.Fatal("--no-open invoked browser")
		return nil
	}
	var output strings.Builder
	command := commandContext{ctx: t.Context(), stdout: &output, stderr: io.Discard}
	if err := presentCredentialForm(command, credentialOptions{noOpen: true}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), credentialauth.TokenFormURL) {
		t.Fatalf("--no-open presentation = %q", output.String())
	}
}

func TestCredentialInputAndPresentationFailures(t *testing.T) {
	if _, err := readCredentialStdin(nil); err == nil {
		t.Fatal("nil stdin accepted")
	}
	if _, err := readCredentialStdin(strings.NewReader(strings.Repeat("x", 64*1024+2))); err == nil {
		t.Fatal("oversized stdin accepted")
	}
	deps := credentialTestDependencies()
	deps.openURL = func(context.Context, string) error { return errors.New("no browser") }
	deps.euid = func() int { return 0 }
	deps.readHidden = func(_ io.Reader, output io.Writer) (string, error) {
		_, _ = io.WriteString(output, "Hugging Face token (input hidden): \n")
		return "hf_candidate", nil
	}
	var stdout, stderr strings.Builder
	command := commandContext{ctx: t.Context(), stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr}
	if err := runCredential(command, []string{"repair"}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "dedicated fine-grained token") || !strings.Contains(stdout.String(), "\n"+credentialauth.TokenFormURL+"\n") ||
		!strings.Contains(stderr.String(), "Browser opening was unavailable") {
		t.Fatalf("presentation output = %q %q", stdout.String(), stderr.String())
	}
	if credentialUpstream(func(string) string { return "https://hub.example" }) != "https://hub.example" || credentialUpstream(nil) != config.DefaultUpstreamHubURL {
		t.Fatal("credential upstream selection failed")
	}
	clearString(nil)
}

func TestDefaultCredentialDependenciesAndTextOutput(t *testing.T) {
	deps := defaultCredentialDependencies()
	if deps.inspect == nil || deps.replace == nil || deps.openURL == nil || deps.readHidden == nil ||
		deps.euid == nil || deps.runElevated == nil || deps.readFile == nil || deps.openAudit == nil || deps.terminalWidth == nil {
		t.Fatal("default credential dependency is nil")
	}
	if _, err := readHiddenCredential(strings.NewReader("token"), io.Discard); err == nil {
		t.Fatal("non-terminal hidden credential input was accepted")
	}
	snapshot, err := credentialTestDependencies().inspect(t.Context(), "", "hf_candidate", 4)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := printCredentialSnapshot(&output, snapshot, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "alice: fine_grained_user_token") || !strings.Contains(output.String(), "generation 4") {
		t.Fatalf("text snapshot = %q", output.String())
	}
	name, args, err := browserCommand("https://example.test")
	if err != nil || len(args) != 1 || args[0] != "https://example.test" ||
		runtime.GOOS == "linux" && name != "xdg-open" || runtime.GOOS == "darwin" && name != "open" {
		t.Fatalf("browser command = %q %v, %v", name, args, err)
	}
	output.Reset()
	token, err := readHiddenCredentialFile(os.Stdin, &output, func(int) ([]byte, error) { return []byte("hf_candidate"), nil })
	if err != nil || token != "hf_candidate" || !strings.Contains(output.String(), "input hidden") {
		t.Fatalf("hidden credential = %q, %q, %v", token, output.String(), err)
	}
	if _, err := readHiddenCredentialFile(os.Stdin, io.Discard, func(int) ([]byte, error) { return nil, errors.New("read") }); err == nil {
		t.Fatal("hidden credential read failure was accepted")
	}
}

func TestActiveCredentialServiceInspectsConfiguredAuthority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/whoami-v2" || request.Header.Get("Authorization") != "Bearer hf_candidate" {
			t.Fatalf("unexpected credential inspection request: %s %s", request.Method, request.URL.Path)
		}
		_, _ = io.WriteString(writer, `{"name":"alice","auth":{"accessToken":{"role":"fineGrained","fineGrained":{"global":["repo.content.read"],"scoped":[]}}}}`)
	}))
	t.Cleanup(server.Close)

	credential, err := activeCredentialService(t.Context(), config.Config{
		HFToken: "hf_candidate", UpstreamHubURL: server.URL, HFTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := credential.Snapshot()
	if err != nil || snapshot.Subject != "alice" || snapshot.Generation != 1 || snapshot.VerificationState != providercredential.VerificationValid {
		t.Fatalf("active credential snapshot = %+v, %v", snapshot, err)
	}
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, hfTokenFileName)
	snapshot.Generation = 7
	status, err := json.Marshal(credentialStatus{Status: "valid", Snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, credentialStatusFileName), status, 0o600); err != nil {
		t.Fatal(err)
	}
	credential, err = activeCredentialService(t.Context(), config.Config{
		HFToken: "hf_candidate", HFTokenFile: tokenFile, UpstreamHubURL: server.URL, HFTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = credential.Snapshot()
	if err != nil || snapshot.Generation != 7 {
		t.Fatalf("persisted active credential snapshot = %+v, %v", snapshot, err)
	}
	snapshot.FingerprintSHA256 = strings.Repeat("b", 64)
	status, _ = json.Marshal(credentialStatus{Status: "valid", Snapshot: snapshot})
	if err := os.WriteFile(filepath.Join(dir, credentialStatusFileName), status, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := activeCredentialService(t.Context(), config.Config{
		HFToken: "hf_candidate", HFTokenFile: tokenFile, UpstreamHubURL: server.URL,
	}); err == nil {
		t.Fatal("credential metadata for another token was accepted")
	}
	if _, err := activeCredentialService(t.Context(), config.Config{UpstreamHubURL: server.URL}); err == nil {
		t.Fatal("empty configured credential was accepted")
	}
}

func credentialTestDependencies() credentialDependencies {
	return credentialDependencies{
		inspect: func(_ context.Context, _ string, token string, generation uint64) (providercredential.Snapshot, error) {
			if token != "hf_secret" && token != "hf_candidate" {
				return providercredential.Snapshot{}, errors.New("unexpected token")
			}
			return providercredential.Normalize(providercredential.Snapshot{
				Provider: "huggingface", CredentialKind: "fine_grained_user_token", Subject: "alice",
				FingerprintSHA256: strings.Repeat("a", 64), Generation: generation,
				VerifiedAt: time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC), VerificationState: providercredential.VerificationValid,
				Capabilities: []providercredential.Capability{
					{Domain: "global", Permission: "repo.read", AccessLevel: providercredential.AccessRead},
					{Domain: "repo", Permission: "repo.write", AccessLevel: providercredential.AccessWrite},
				},
			})
		},
		replace:       func(context.Context, bkservice.CredentialReplacePlan) error { return nil },
		openURL:       func(context.Context, string) error { return nil },
		readHidden:    func(io.Reader, io.Writer) (string, error) { return "hf_candidate", nil },
		euid:          func() int { return 1000 },
		runElevated:   func(context.Context, string, []string, io.Writer, io.Writer) error { return nil },
		readFile:      func(string) ([]byte, error) { return nil, os.ErrNotExist },
		openAudit:     func(string, io.Writer) (io.WriteCloser, error) { return nopWriteCloser{Writer: io.Discard}, nil },
		terminalWidth: func(io.Writer) int { return defaultCredentialWidth },
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
