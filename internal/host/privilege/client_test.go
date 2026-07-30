package privilege

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	deploymentplan "github.com/osolmaz/unyolo/deployment/plan"
	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
)

type bufferCloser struct{ bytes.Buffer }

func (*bufferCloser) Close() error { return nil }

func framedReader(t *testing.T, value any) io.ReadCloser {
	t.Helper()
	var output bytes.Buffer
	if err := deploymentruntime.WriteFrame(&output, value); err != nil {
		t.Fatal(err)
	}
	return io.NopCloser(bytes.NewReader(output.Bytes()))
}

func TestClientPlanApplyAndCancel(t *testing.T) {
	plan := deploymentplan.Plan{Digest: "sha256:" + string(bytes.Repeat([]byte("a"), 64))}
	input := &bufferCloser{}
	client := &Client{input: input, output: framedReader(t, Response{APIVersion: APIVersion, PlanDigest: plan.Digest, Plan: plan})}
	response, err := client.Plan("/tmp/profile")
	if err != nil || response.PlanDigest != plan.Digest || input.Len() == 0 {
		t.Fatalf("plan = %#v, %v", response, err)
	}

	command := exec.CommandContext(t.Context(), "true")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	input = &bufferCloser{}
	client = &Client{
		command: command, input: input,
		output: framedReader(t, Result{APIVersion: APIVersion, Status: "succeeded"}),
	}
	result, err := client.Apply(plan.Digest, map[string][]byte{"zeta": []byte("secret"), "alpha": []byte("other")})
	if err != nil || result.Status != "succeeded" || input.Len() == 0 {
		t.Fatalf("apply = %#v, %v", result, err)
	}

	command = exec.CommandContext(t.Context(), "true")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	client = &Client{command: command, input: &bufferCloser{}, output: framedReader(t, Result{APIVersion: APIVersion, Status: "cancelled"})}
	if err := client.Cancel(); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadAndChecksum(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/ok":
			_, _ = io.WriteString(writer, "content")
		case "/large":
			_, _ = io.WriteString(writer, "too large")
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	destination := filepath.Join(root, "download")
	if err := download(t.Context(), server.URL+"/ok", destination, 7); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "content" {
		t.Fatalf("download = %q, %v", data, err)
	}
	if err := download(t.Context(), server.URL+"/large", filepath.Join(root, "large"), 2); err == nil {
		t.Fatal("oversized download was accepted")
	}
	if err := download(t.Context(), server.URL+"/missing", filepath.Join(root, "missing"), 10); err == nil {
		t.Fatal("missing download was accepted")
	}
	checksums := filepath.Join(root, "checksums")
	if err := os.WriteFile(checksums, []byte(""+string(bytes.Repeat([]byte("a"), 64))+"  file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := checksumFor(checksums, "file"); err != nil || got != string(bytes.Repeat([]byte("a"), 64)) {
		t.Fatalf("checksum = %q, %v", got, err)
	}
	if _, err := checksumFor(checksums, "missing"); err == nil {
		t.Fatal("missing checksum was accepted")
	}
}

func TestGitHubTokenResolutionAndRootCommand(t *testing.T) {
	t.Setenv("GH_TOKEN", "environment-value")
	token, err := githubToken(t.Context(), "/unused")
	if err != nil || string(token) != "environment-value" {
		t.Fatalf("environment token = %q, %v", token, err)
	}
	clear(token)

	t.Setenv("GH_TOKEN", "")
	bin := t.TempDir()
	gh := filepath.Join(bin, "gh")
	if err := os.WriteFile(gh, []byte("#!/bin/sh\nprintf 'configured-value\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if digest, digestErr := trustedGitHubCLI(gh); digestErr != nil || len(digest) != 64 {
		t.Fatalf("trusted verifier digest = %q, %v", digest, digestErr)
	}
	token, err = githubToken(t.Context(), gh)
	if err != nil || string(token) != "configured-value" {
		t.Fatalf("configured token = %q, %v", token, err)
	}
	command := rootWorkerCommand(t.Context(), "/tmp/bootstrap", strings.Repeat("a", 64), gh, strings.Repeat("b", 64), "0.4.1", "unyolo/v0.4.1", token)
	for _, argument := range command.Args {
		if strings.Contains(argument, string(token)) {
			t.Fatal("GitHub token was included in a process argument")
		}
	}
	if !strings.Contains(strings.Join(command.Args, "\x00"), "--preserve-env=GH_TOKEN") {
		t.Fatalf("sudo arguments = %#v", command.Args)
	}
	var bindings int
	for _, value := range command.Env {
		if strings.HasPrefix(value, "GH_TOKEN=") {
			bindings++
		}
	}
	if bindings != 1 {
		t.Fatalf("GitHub token environment bindings = %d", bindings)
	}
	clear(token)

	t.Setenv("GH_TOKEN", strings.Repeat("x", maxGitHubTokenBytes+1))
	if token, err := githubToken(t.Context(), gh); err == nil || token != nil {
		t.Fatal("oversized GitHub token was accepted")
	}
}

func TestClientRejectsInvalidWorkerData(t *testing.T) {
	if client, err := Start(t.Context(), "latest", "", io.Discard); err == nil || client != nil {
		t.Fatal("invalid release was accepted")
	}
	client := &Client{input: &bufferCloser{}, output: framedReader(t, Response{APIVersion: "old"})}
	if _, err := client.Plan("/tmp/profile"); err == nil {
		t.Fatal("invalid worker plan was accepted")
	}
	if err := (*Client)(nil).Close(); err != nil {
		t.Fatal(err)
	}
}
