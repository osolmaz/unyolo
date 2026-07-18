package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

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
