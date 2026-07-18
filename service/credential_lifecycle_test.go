package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/credentiallifecycle"
)

func TestRecordManagedCredentialChangesReportsExactCutover(t *testing.T) {
	var output bytes.Buffer
	reporter, err := credentiallifecycle.New(audit.New(&output), "hf-broker", "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	files := []ManagedFile{
		{Name: "provider", Data: []byte("new-provider-canary"), CredentialClass: "huggingface-access"},
		{Name: "client", Data: []byte("client-canary"), CredentialClass: "broker-client"},
	}
	previous := []previousManagedCredential{{existed: true, data: []byte("old-provider-canary")}, {}}
	if err := recordManagedCredentialChanges(reporter, files, previous, map[string]string{"telegram-bot": "sha256:1234567890abcdef"}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{`"lifecycle_action":"rotated"`, `"lifecycle_action":"created"`, `"lifecycle_action":"revoked"`, `"target":"huggingface-access"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("lifecycle audit missing %s: %s", want, got)
		}
	}
	for _, forbidden := range []string{"new-provider-canary", "old-provider-canary", "client-canary"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("lifecycle audit leaked %q: %s", forbidden, got)
		}
	}
}

func TestValidateCredentialClassesRejectsDuplicatesAndOpenValues(t *testing.T) {
	if err := validateCredentialClasses([]ManagedFile{{CredentialClass: "broker-client"}}, nil); err != nil {
		t.Fatalf("valid class error = %v", err)
	}
	if err := validateCredentialClasses([]ManagedFile{{CredentialClass: "broker-client"}}, []ManagedFileRef{{CredentialClass: "broker-client"}}); err == nil {
		t.Fatal("duplicate class error = nil")
	}
	if err := validateCredentialClasses([]ManagedFile{{CredentialClass: "broker client"}}, nil); err == nil {
		t.Fatal("open class error = nil")
	}
	if err := validateCredentialClasses(nil, []ManagedFileRef{{CredentialClass: "broker client"}}); err == nil {
		t.Fatal("open retired class error = nil")
	}
	if err := recordManagedCredentialChanges(nil, nil, nil, nil); err != nil {
		t.Fatalf("nil reporter error = %v", err)
	}
	var output bytes.Buffer
	reporter, _ := credentiallifecycle.New(audit.New(&output), "hf-broker", "local-operator")
	file := ManagedFile{CredentialClass: "broker-client", Data: []byte("same-canary")}
	if err := recordManagedCredentialChanges(reporter, []ManagedFile{file}, []previousManagedCredential{{existed: true, data: file.Data}}, nil); err != nil || output.Len() != 0 {
		t.Fatalf("unchanged credential record = %q, %v", output.String(), err)
	}
}

func TestCaptureCredentialRemovalsSkipsAndClearsSecretData(t *testing.T) {
	empty := ManagedFileRef{Name: "empty"}
	classed := ManagedFileRef{Name: "secret", CredentialClass: "broker-client-secret"}
	secret := []byte("secret-value")
	calls := 0
	result, err := captureCredentialRemovals([]ManagedFileRef{empty, classed}, func(file ManagedFileRef) (bool, []byte, error) {
		calls++
		if file.Name != classed.Name {
			t.Fatalf("unexpected capture for %s", file.Name)
		}
		return true, secret, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || result[classed.CredentialClass] == "" {
		t.Fatalf("captures=%d result=%v", calls, result)
	}
	for _, value := range secret {
		if value != 0 {
			t.Fatalf("secret data was not cleared: %q", secret)
		}
	}
}

func TestCredentialReplacementRollbackAndLifecycleAudit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("old-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := openCredentialRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	files := []ManagedFile{
		{Area: ManagedFileConfig, Name: "token", Data: []byte("new-token"), Mode: 0o600, Owner: ManagedFileOwnerService, CredentialClass: "provider-access"},
		{Area: ManagedFileConfig, Name: "metadata", Data: []byte("new-metadata"), Mode: 0o600, Owner: ManagedFileOwnerRoot, CredentialClass: "provider-metadata"},
	}
	snapshots, err := captureCredentialFiles(root, files)
	if err != nil {
		t.Fatal(err)
	}
	defer clearCredentialSnapshots(snapshots)
	if err := writeCredentialFiles(root, files, os.Geteuid(), os.Getegid(), true); err != nil {
		t.Fatal(err)
	}
	runner := &credentialRecordingRunner{}
	plan := credentialTestPlan(dir, files)
	cause := errors.New("readiness failed")
	if err := rollbackCredentialReplacement(context.Background(), root, snapshots, os.Geteuid(), os.Getegid(), runner, plan, cause); !errors.Is(err, cause) {
		t.Fatalf("rollback error = %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "token")); err != nil || string(data) != "old-token" {
		t.Fatalf("restored token = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "metadata")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new metadata remained after rollback: %v", err)
	}

	var output bytes.Buffer
	reporter, err := credentiallifecycle.New(audit.New(&output), "hf-broker", "local-operator")
	if err != nil {
		t.Fatal(err)
	}
	plan.Lifecycle = reporter
	if err := recordCredentialReplacement(plan, snapshots); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"lifecycle_action":"rotated"`, `"lifecycle_action":"created"`, `"provider":"test"`} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("credential lifecycle audit missing %s: %s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "old-token") || strings.Contains(output.String(), "new-token") {
		t.Fatalf("credential lifecycle audit leaked a token: %s", output.String())
	}
}
