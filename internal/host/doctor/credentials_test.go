package doctor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCredentialFileStatusIsSecretSafeAndReportsLifecycle(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "provider-value-canary")
	if err := os.WriteFile(path, []byte("private-value-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	updated := now.Add(-91 * 24 * time.Hour)
	if err := os.Chtimes(path, updated, updated); err != nil {
		t.Fatal(err)
	}
	status := CredentialFileStatus("provider-access", path, now, DefaultCredentialRotationAge, now.Add(7*24*time.Hour), CredentialRevocationManual)
	if status.Source != CredentialSourceProtectedFile || status.Age != "91-days" || status.Expiry != "within-14-days" || status.Rotation != "due" {
		t.Fatalf("status = %+v", status)
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), path) || strings.Contains(string(data), "private-value-canary") {
		t.Fatalf("credential status leaked protected data: %s", data)
	}
}

func TestCredentialStatusesHandleUnknownAndStoredMetadata(t *testing.T) {
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	missing := CredentialFileStatus("missing", filepath.Join(t.TempDir(), "missing"), now, DefaultCredentialRotationAge, time.Time{}, CredentialRevocationLocal)
	stored := StoredCredentialStatus("oauth-user", now.Add(-time.Hour), now.Add(time.Hour), now, DefaultCredentialRotationAge, CredentialRevocationAutomatic)
	inline := InlineCredentialStatus("inline", CredentialRevocationManual)
	values := NormalizeCredentialStatuses([]CredentialStatus{stored, inline, missing, {}, stored})
	if len(values) != 3 || values[0].Class != "inline" || missing.Age != "unknown" || stored.Expiry != "within-14-days" || stored.Rotation != "due" {
		t.Fatalf("values=%+v missing=%+v stored=%+v", values, missing, stored)
	}
	report := WithCredentials(NewReport(Identity{User: "agent-a"}), values...)
	var output bytes.Buffer
	if err := WriteText(&output, report); err != nil || !strings.Contains(output.String(), "credential oauth-user") {
		t.Fatalf("credential text report = %q, %v", output.String(), err)
	}
}
