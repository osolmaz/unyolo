package service

import (
	"bytes"
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
