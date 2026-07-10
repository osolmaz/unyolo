package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
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
	if got := RootEquivalentCheck(Identity{User: "bob", UID: 1000, GID: 1000, GroupNames: []string{"docker"}}); got.Status != CheckFail {
		t.Fatalf("docker check = %+v", got)
	}
	if got := RootEquivalentCheck(Identity{User: "bob", UID: 1000, GID: 1000, GroupNames: []string{"users"}}); got.Status != CheckPass {
		t.Fatalf("normal check = %+v", got)
	}
	if got := RootEquivalentCheck(Identity{User: "bob", UID: 1000, GID: 0}); got.Status != CheckFail {
		t.Fatalf("primary root gid check = %+v", got)
	}
	if got := RootEquivalentCheck(Identity{User: "bob", UID: 1000, GID: 1000, GroupIDs: []int{0}}); got.Status != CheckFail {
		t.Fatalf("supplementary root gid check = %+v", got)
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

func TestIdentityGroupsFailsWhenGroupNameIsUnknown(t *testing.T) {
	oldLookup := lookupGroupByID
	lookupGroupByID = func(string) (*user.Group, error) { return nil, errors.New("lookup unavailable") }
	t.Cleanup(func() { lookupGroupByID = oldLookup })
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := identityGroups(current); err == nil {
		t.Fatal("identityGroups() error = nil")
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
	if ownerChecks[3].Status != CheckFail || ownerChecks[4].Status != CheckFail {
		t.Fatalf("owner secret checks = %+v", ownerChecks)
	}
	if checks := SecretFileChecks(filepath.Join(t.TempDir(), "missing"), agent); checks[0].Status != CheckUnknown {
		t.Fatalf("missing secret checks = %+v", checks)
	}
}

func TestSecretFileOwnerCanGainAccessDespiteModeZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("do-not-print"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	ownerChecks := SecretFileChecks(path, Identity{User: "owner", UID: int(stat.Uid), GID: int(stat.Gid)})
	if ownerChecks[3].Status != CheckFail || ownerChecks[4].Status != CheckFail {
		t.Fatalf("mode-zero owner secret checks = %+v", ownerChecks)
	}
}

func TestSecretFileChecksRejectReplaceableAndSymlinkPaths(t *testing.T) {
	root := t.TempDir()
	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o777); err != nil { // #nosec G301 -- world-writable directory is the isolation failure fixture.
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil { // #nosec G302 -- world-writable directory is the isolation failure fixture.
		t.Fatal(err)
	}
	secret := filepath.Join(writable, "secret")
	if err := os.WriteFile(secret, []byte("do-not-print"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(writable)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	agent := Identity{User: "agent", UID: int(stat.Uid) + 1, GID: int(stat.Gid) + 1}
	if got := SecretFileChecks(secret, agent)[0]; got.Status != CheckFail {
		t.Fatalf("replaceable path check = %+v", got)
	}

	stableDir := filepath.Join(root, "stable")
	if err := os.Mkdir(stableDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stableSecret := filepath.Join(stableDir, "secret")
	if err := os.WriteFile(stableSecret, []byte("do-not-print"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(stableDir, "secret-link")
	if err := os.Symlink(stableSecret, link); err != nil {
		t.Fatal(err)
	}
	if got := SecretFileChecks(link, agent)[0]; got.Status != CheckUnknown {
		t.Fatalf("symlink path check = %+v", got)
	}
}

func TestSecretFileChecksRejectsParentTraversalBeforeCleaning(t *testing.T) {
	root := t.TempDir()
	stable := filepath.Join(root, "stable")
	actual := filepath.Join(root, "actual")
	if err := os.Mkdir(stable, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(actual, 0o777); err != nil { // #nosec G301 -- writable directory is the isolation failure fixture.
		t.Fatal(err)
	}
	if err := os.Chmod(actual, 0o777); err != nil { // #nosec G302 -- writable directory is the isolation failure fixture.
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(actual, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actual, "secret"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(actual, "sub"), filepath.Join(stable, "hop")); err != nil {
		t.Fatal(err)
	}
	path := stable + string(filepath.Separator) + "hop" + string(filepath.Separator) + ".." + string(filepath.Separator) + "secret"
	checks := SecretFileChecks(path, Identity{User: "agent", UID: os.Getuid() + 1, GID: os.Getgid() + 1})
	if checks[0].Status != CheckUnknown {
		t.Fatalf("parent traversal check = %+v", checks[0])
	}
}

func TestAgentCanReplaceChildStickyDirectoryRules(t *testing.T) {
	root := t.TempDir()
	parentPath := filepath.Join(root, "sticky")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parentPath, os.ModeSticky|0o777); err != nil { // #nosec G302 -- sticky world-writable directory is the fixture.
		t.Fatal(err)
	}
	childPath := filepath.Join(parentPath, "child")
	if err := os.WriteFile(childPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Stat(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	child, err := os.Stat(childPath)
	if err != nil {
		t.Fatal(err)
	}
	stat := child.Sys().(*syscall.Stat_t)
	owner := Identity{User: "owner", UID: int(stat.Uid), GID: int(stat.Gid)}
	if !agentCanReplaceChild(parent, child, owner) {
		t.Fatal("owner should be able to replace a child in a sticky directory")
	}
	other := Identity{User: "other", UID: int(stat.Uid) + 1, GID: int(stat.Gid) + 1}
	if agentCanReplaceChild(parent, child, other) {
		t.Fatal("unrelated user should not replace another owner's sticky-directory child")
	}
}

func TestAgentCanReplaceChildWhenOwningModeZeroDirectory(t *testing.T) {
	parentPath := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	childPath := filepath.Join(parentPath, "child")
	if err := os.WriteFile(childPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	child, err := os.Stat(childPath)
	if err != nil {
		t.Fatal(err)
	}
	stat := child.Sys().(*syscall.Stat_t)
	owner := Identity{User: "owner", UID: int(stat.Uid), GID: int(stat.Gid)}
	if err := os.Chmod(parentPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parentPath, 0o700) }) // #nosec G302 -- restore owner traversal for test cleanup.
	parent, err := os.Stat(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !agentCanReplaceChild(parent, child, owner) {
		t.Fatal("directory owner should be able to chmod and replace its child")
	}
}

func TestAgentCanReplaceChildFailsClosedForNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := file.Sys().(*syscall.Stat_t)
	other := Identity{User: "other", UID: int(stat.Uid) + 1, GID: int(stat.Gid) + 1}
	if !agentCanReplaceChild(file, file, other) {
		t.Fatal("a non-directory parent must fail closed")
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
