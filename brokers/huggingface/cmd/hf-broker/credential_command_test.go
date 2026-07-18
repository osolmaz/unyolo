package main

import (
	"context"
	"encoding/json"
	"errors"
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

func TestCredentialRepairValidatesBeforeElevation(t *testing.T) {
	var stdout strings.Builder
	deps := credentialTestDependencies()
	deps.euid = func() int { return 1000 }
	var elevatedToken string
	deps.runElevated = func(_ context.Context, token string, args []string, _, _ io.Writer) error {
		elevatedToken = token
		if strings.Join(args, " ") != "credential __activate --token-stdin --json" {
			t.Fatalf("elevated args = %v", args)
		}
		return nil
	}
	command := commandContext{ctx: context.Background(), stdin: strings.NewReader("hf_candidate\n"), stdout: &stdout, stderr: io.Discard}
	if err := runCredential(command, []string{"repair", "--no-open", "--token-stdin", "--json"}, deps); err != nil {
		t.Fatal(err)
	}
	if elevatedToken != "hf_candidate\n" || !strings.Contains(stdout.String(), credentialauth.TokenFormURL) {
		t.Fatalf("elevated token/output mismatch: %q %q", elevatedToken, stdout.String())
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
	if len(plan.Files) != 2 || plan.Files[0].Name != "hf-token" || plan.Files[1].Name != credentialStatusFileName {
		t.Fatalf("replacement plan = %+v", plan)
	}
	if string(plan.Files[0].Data) != "hf_candidate\n" || strings.Contains(string(plan.Files[1].Data), "hf_candidate") {
		t.Fatal("replacement payload is incorrect or metadata leaked the token")
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
	deps.euid = func() int { return 1000 }
	var stdout, stderr strings.Builder
	command := commandContext{ctx: t.Context(), stdin: strings.NewReader("hf_candidate\n"), stdout: &stdout, stderr: &stderr}
	if err := runCredential(command, []string{"repair", "--token-stdin"}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), credentialauth.TokenFormURL) || !strings.Contains(stderr.String(), "Could not open") {
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
		deps.euid == nil || deps.runElevated == nil || deps.readFile == nil {
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
	if err != nil || token != "hf_candidate" || !strings.Contains(output.String(), "Paste the new") {
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
			})
		},
		replace:     func(context.Context, bkservice.CredentialReplacePlan) error { return nil },
		openURL:     func(context.Context, string) error { return nil },
		readHidden:  func(io.Reader, io.Writer) (string, error) { return "hf_candidate", nil },
		euid:        func() int { return 1000 },
		runElevated: func(context.Context, string, []string, io.Writer, io.Writer) error { return nil },
		readFile:    func(string) ([]byte, error) { return nil, os.ErrNotExist },
	}
}
