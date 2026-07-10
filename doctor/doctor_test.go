package doctor

import (
	"bytes"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRootEquivalentAndSeparationChecks(t *testing.T) {
	if got := RootEquivalentCheck(Identity{User: "root", UID: 0}); got.Status != CheckFail {
		t.Fatalf("root check = %+v", got)
	}
	if got := RootEquivalentCheck(Identity{User: "bob", UID: 1000, GroupNames: []string{"docker"}}); got.Status != CheckFail {
		t.Fatalf("docker check = %+v", got)
	}
	if got := RootEquivalentCheck(Identity{User: "bob", UID: 1000, GroupNames: []string{"users"}}); got.Status != CheckPass {
		t.Fatalf("normal check = %+v", got)
	}
	if !RootEquivalentGroup("wheel") || RootEquivalentGroup("users") {
		t.Fatal("RootEquivalentGroup() mismatch")
	}
	if got := SeparationCheck(Identity{UID: 1000}, Identity{UID: 1000}); got.Status != CheckFail {
		t.Fatalf("same uid separation = %+v", got)
	}
	if got := SeparationCheck(Identity{UID: 1000}, Identity{UID: 1001}); got.Status != CheckPass {
		t.Fatalf("different uid separation = %+v", got)
	}
}

func TestSecretFileChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("do-not-print"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	agent := Identity{User: "agent", UID: int(stat.Uid) + 1, GID: int(stat.Gid) + 1}
	checks := SecretFileChecks(path, agent)
	for _, check := range checks {
		if check.Status != CheckPass {
			t.Fatalf("private secret check = %+v", checks)
		}
		if strings.Contains(check.Message, "do-not-print") {
			t.Fatal("secret leaked in doctor message")
		}
	}
	ownerChecks := SecretFileChecks(path, Identity{User: "owner", UID: int(stat.Uid), GID: int(stat.Gid)})
	if ownerChecks[2].Status != CheckFail || ownerChecks[3].Status != CheckFail {
		t.Fatalf("owner secret checks = %+v", ownerChecks)
	}
	if checks := SecretFileChecks(filepath.Join(t.TempDir(), "missing"), agent); checks[0].Status != CheckUnknown {
		t.Fatalf("missing secret checks = %+v", checks)
	}
}

func TestReportOutputAndExitCodes(t *testing.T) {
	agent := Identity{User: "bob", UID: 1000, GID: 1000}
	tests := []struct {
		checkStatus CheckStatus
		wantStatus  Status
		wantCode    int
	}{
		{checkStatus: CheckPass, wantStatus: StatusOK, wantCode: 0},
		{checkStatus: CheckFail, wantStatus: StatusUnsafe, wantCode: 1},
		{checkStatus: CheckUnknown, wantStatus: StatusInconclusive, wantCode: 2},
	}
	for _, tc := range tests {
		report := NewReport(agent, Check{Status: tc.checkStatus, Name: "one", Message: string(tc.checkStatus)})
		if report.Status != tc.wantStatus || ExitCode(report.Status) != tc.wantCode {
			t.Fatalf("report(%s) = %+v code=%d", tc.checkStatus, report, ExitCode(report.Status))
		}
	}
	assertReportOutput(t, agent)
}

func assertReportOutput(t *testing.T, agent Identity) {
	t.Helper()
	unsafe := NewReport(agent, Check{Status: CheckFail, Name: "one", Message: "bad"})
	var text bytes.Buffer
	if err := WriteText(&text, unsafe); err != nil || !strings.Contains(text.String(), "UNSAFE") {
		t.Fatalf("WriteText() = %q err=%v", text.String(), err)
	}
	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, unsafe); err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil || decoded.Status != StatusUnsafe {
		t.Fatalf("WriteJSON() decoded=%+v err=%v", decoded, err)
	}
}

func TestLookupAndValidateIdentity(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := LookupIdentity(current.Username)
	if err != nil || identity.User == "" || len(identity.GroupIDs) == 0 {
		t.Fatalf("LookupIdentity() = %+v err=%v", identity, err)
	}
	if err := ValidateIdentity(identity); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIdentity(Identity{UID: -1}); err == nil {
		t.Fatal("ValidateIdentity(invalid) error = nil")
	}
	if _, err := LookupIdentity("brokerkit-no-such-user"); err == nil {
		t.Fatal("LookupIdentity(missing) error = nil")
	}
}
