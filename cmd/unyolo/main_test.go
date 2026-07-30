package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/protocol/contract"
)

type testManager struct{}

func (testManager) Stop(context.Context, string) error    { return nil }
func (testManager) Start(context.Context, string) error   { return nil }
func (testManager) Enable(context.Context, string) error  { return nil }
func (testManager) Disable(context.Context, string) error { return nil }
func (testManager) Reload(context.Context) error          { return nil }
func (testManager) Status(context.Context, string) (bundle.ServiceStatus, error) {
	return bundle.ServiceStatus{Active: true}, nil
}

func TestRunVersionUsageAndBundlePlan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"version"}, &stdout, &stderr); err != nil || strings.TrimSpace(stdout.String()) != version {
		t.Fatalf("version output=%q err=%v", stdout.String(), err)
	}
	for _, args := range [][]string{{}, {"bad"}, {"system", "bad"}} {
		if err := run(t.Context(), args, &stdout, &stderr); err == nil {
			t.Fatalf("run(%v) error=nil", args)
		}
	}
	manifestPath, _, _, _ := testBundle(t, "bundle-plan", "plan")
	stdout.Reset()
	args := []string{"--development", "--manifest", manifestPath, "--json"}
	if err := runActivation(t.Context(), "plan", args, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), `"bundle_id":"bundle-plan"`) {
		t.Fatalf("plan output=%q err=%v", stdout.String(), err)
	}
}

func TestRunDevelopmentInstall(t *testing.T) {
	original := newNativeManager
	newNativeManager = func() bundle.ServiceManager { return testManager{} }
	t.Cleanup(func() { newNativeManager = original })
	manifestPath, artifacts, _, _ := testBundle(t, "bundle-install", "install")
	root, state := t.TempDir(), t.TempDir()
	args := []string{"system", "install", "--development", "--manifest", manifestPath,
		"--artifacts", artifacts, "--root", root, "--state-dir", state}
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Activated unYOLO bundle bundle-install") {
		t.Fatalf("install output=%q", stdout.String())
	}
}

func TestRunStatusDoctorAndRollback(t *testing.T) {
	original := newNativeManager
	newNativeManager = func() bundle.ServiceManager { return testManager{} }
	t.Cleanup(func() { newNativeManager = original })
	root, state := t.TempDir(), t.TempDir()
	installer := bundle.Installer{Paths: bundle.Paths{Root: root, StateDir: state}, Manager: testManager{}, Development: true}
	activateTestBundle(t, installer, "bundle-one", "one")
	activateTestBundle(t, installer, "bundle-two", "two")

	base := []string{"--root", root, "--state-dir", state}
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), append([]string{"system", "status"}, base...), &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "bundle-two") {
		t.Fatalf("status output=%q err=%v", stdout.String(), err)
	}
	stdout.Reset()
	if err := run(t.Context(), append([]string{"system", "doctor"}, append(base, "--json")...), &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), `"healthy":true`) {
		t.Fatalf("doctor output=%q err=%v", stdout.String(), err)
	}
	stdout.Reset()
	if err := run(t.Context(), append([]string{"system", "rollback"}, base...), &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "Rolled back") {
		t.Fatalf("rollback output=%q err=%v", stdout.String(), err)
	}
}

func TestActivationModeAndParsingErrors(t *testing.T) {
	production := bundle.DefaultPaths()
	if err := validateDevelopmentActivation("install", hostFlags{root: production.Root, state: t.TempDir()}, production); err == nil {
		t.Fatal("development production-root error=nil")
	}
	if err := validateProductionActivation("install", hostFlags{root: t.TempDir(), state: t.TempDir()}, production); err == nil {
		t.Fatal("production custom-root error=nil")
	}
	if err := validateProductionActivation("plan", hostFlags{}, production); err != nil {
		t.Fatal(err)
	}
	if _, err := parseActivationOptions("plan", nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing manifest error=nil")
	}
	if _, err := parseHostOptions("status", []string{"extra"}, &bytes.Buffer{}, "status"); err == nil {
		t.Fatal("positional status error=nil")
	}
	if err := writeStatus(&failingWriter{}, false, bundle.Report{Healthy: true}); err == nil {
		t.Fatal("write status error=nil")
	}
}

type failingWriter struct{}

func (*failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write failed") }

func activateTestBundle(t *testing.T, installer bundle.Installer, id, body string) {
	t.Helper()
	manifestPath, artifacts, manifest, data := testBundle(t, id, body)
	_ = manifestPath
	if err := installer.Activate(t.Context(), manifest, data, artifacts); err != nil {
		t.Fatal(err)
	}
}

func testBundle(t *testing.T, id, body string) (string, string, bundle.Manifest, []byte) {
	t.Helper()
	artifacts := t.TempDir()
	artifact := []byte(body)
	if err := os.WriteFile(filepath.Join(artifacts, "broker"), artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifact)
	manifest := bundle.Manifest{
		APIVersion: bundle.APIVersion, BundleID: id, SourceCommit: strings.Repeat("a", 40),
		OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH,
		OperatorContractDigest: contract.OperatorV1Digest, AgentContractDigest: contract.AgentV1Digest,
		Components: []bundle.Component{{Name: "broker", Source: "broker", Destination: "bin/broker",
			SHA256: fmt.Sprintf("sha256:%x", digest), BuildID: "dev-test", Role: bundle.RoleCompanion,
			StateFormatDigest: "sha256:" + strings.Repeat("0", 64)}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(artifacts, "manifest.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, artifacts, manifest, data
}
