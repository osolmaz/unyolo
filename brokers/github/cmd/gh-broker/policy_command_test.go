package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyRenderCheckAndDoctor(t *testing.T) {
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope.json")
	profile := filepath.Join(dir, "profile.json")
	manifest := filepath.Join(dir, "manifest.json")
	var stdout, stderr bytes.Buffer
	err := runWithArgs(context.Background(), []string{
		"policy", "render", "--client", "agent-a", "--deny-operation", "repo.delete",
		"--output", scope, "--profile-out", profile, "--manifest-out", manifest,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Rendered request-all-agent-operations for 1436 operation(s)") {
		t.Fatalf("render output = %q", stdout.String())
	}
	stdout.Reset()
	if err := runWithArgs(context.Background(), []string{"policy", "check", "--file", scope}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Policy is valid") {
		t.Fatalf("check output = %q", stdout.String())
	}
	stdout.Reset()
	if err := runWithArgs(context.Background(), []string{"doctor", "policy", "--profile", profile, "--manifest", manifest, "--scope", scope}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Policy status: current") {
		t.Fatalf("doctor output = %q", stdout.String())
	}
}

func TestPolicyRenderRequiresExplicitReplace(t *testing.T) {
	dir := t.TempDir()
	args := []string{"render", "--output", filepath.Join(dir, "scope.json"), "--profile-out", filepath.Join(dir, "profile.json"), "--manifest-out", filepath.Join(dir, "manifest.json")}
	if err := runPolicy(ioDiscard{}, ioDiscard{}, args); err != nil {
		t.Fatal(err)
	}
	err := runPolicy(ioDiscard{}, ioDiscard{}, args)
	if err == nil || !strings.Contains(err.Error(), "use --replace") {
		t.Fatalf("second render error = %v", err)
	}
	if err := runPolicy(ioDiscard{}, ioDiscard{}, append(args, "--replace")); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorPolicyReportsModifiedArtifact(t *testing.T) {
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope.json")
	profile := filepath.Join(dir, "profile.json")
	manifest := filepath.Join(dir, "manifest.json")
	if err := runPolicy(ioDiscard{}, ioDiscard{}, []string{"render", "--output", scope, "--profile-out", profile, "--manifest-out", manifest}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(scope) // #nosec G304 -- test reads its own temp output.
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte("preset-"), []byte("changed-"), 1)
	if err := os.WriteFile(scope, data, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err = runDoctorPolicy(&stdout, ioDiscard{}, []string{"--profile", profile, "--manifest", manifest, "--scope", scope})
	var status exitError
	if !errors.As(err, &status) || status.code != 1 || !strings.Contains(stdout.String(), "Policy status: modified") {
		t.Fatalf("doctor error = %v output = %q", err, stdout.String())
	}
}
