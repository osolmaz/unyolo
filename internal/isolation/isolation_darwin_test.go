//go:build darwin

package isolation

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinAgentAdminAndWheelAreUnsafe(t *testing.T) {
	var admin Report
	runAgentChecks(&admin, identity{uid: 501, groups: map[string]bool{"admin": true}})
	if !darwinHasCheck(admin, CheckFail, "agent_not_root_equivalent_group") {
		t.Fatalf("checks = %+v, want admin group failure", admin.Checks)
	}

	var wheel Report
	runAgentChecks(&wheel, identity{uid: 501, groups: map[string]bool{"wheel": true}})
	if !darwinHasCheck(wheel, CheckFail, "agent_not_root_equivalent_group") {
		t.Fatalf("checks = %+v, want wheel group failure", wheel.Checks)
	}

	var normal Report
	runAgentChecks(&normal, identity{uid: 501, groups: map[string]bool{"staff": true}})
	if !darwinHasCheck(normal, CheckPass, "agent_not_root_equivalent_group") {
		t.Fatalf("checks = %+v, want non-admin group pass", normal.Checks)
	}

	var unknown Report
	runAgentChecks(&unknown, identity{uid: 501, groups: map[string]bool{"staff": true}, groupsUnknown: true})
	if !darwinHasCheck(unknown, CheckUnknown, "agent_not_root_equivalent_group") {
		t.Fatalf("checks = %+v, want unknown live group check", unknown.Checks)
	}

	var riskyUnknown Report
	runAgentChecks(&riskyUnknown, identity{uid: 501, groups: map[string]bool{"admin": true}, groupsUnknown: true})
	if !darwinHasCheck(riskyUnknown, CheckFail, "agent_not_root_equivalent_group") {
		t.Fatalf("checks = %+v, want known risky group to fail even when live groups are incomplete", riskyUnknown.Checks)
	}
}

func TestDarwinRunWithCurrentPIDChecksUIDAndLeavesEnvUnknown(t *testing.T) {
	report, err := Run(context.Background(), Options{
		AgentUID:    os.Getuid(),
		AgentUIDSet: true,
		AgentPID:    os.Getpid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Agent.UID != os.Getuid() {
		t.Fatalf("agent UID = %d, want current UID %d", report.Agent.UID, os.Getuid())
	}
	if !darwinHasCheck(report, CheckPass, "agent_process_uid") {
		t.Fatalf("checks = %+v, want process UID pass", report.Checks)
	}
	if !darwinHasCheck(report, CheckUnknown, "agent_env_no_hf_token") {
		t.Fatalf("checks = %+v, want process environment unknown", report.Checks)
	}
}

func TestDarwinResolveImplicitIdentity(t *testing.T) {
	current, err := resolveImplicitIdentity(0)
	if err != nil {
		t.Fatal(err)
	}
	if current.uid != os.Getuid() {
		t.Fatalf("current uid = %d, want %d", current.uid, os.Getuid())
	}
	fromPID, err := resolveImplicitIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if fromPID.uid != os.Getuid() || fromPID.pid != os.Getpid() {
		t.Fatalf("pid identity = %+v, want current pid uid", fromPID)
	}
	if _, err := resolveImplicitIdentity(999999999); err == nil {
		t.Fatalf("resolveImplicitIdentity() error = nil, want missing process error")
	}
}

func TestDarwinBrokerPIDChecksUIDSeparationAndEnvUnknown(t *testing.T) {
	report, err := Run(context.Background(), Options{
		AgentUID:    syntheticDarwinOtherUID(),
		AgentUIDSet: true,
		BrokerPID:   os.Getpid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !darwinHasCheck(report, CheckPass, "broker_separate_uid") {
		t.Fatalf("checks = %+v, want broker UID separation pass", report.Checks)
	}
	if !darwinHasCheck(report, CheckUnknown, "broker_env_not_readable") {
		t.Fatalf("checks = %+v, want broker environment unknown", report.Checks)
	}
}

func TestDarwinTokenFileStatMissingAndSymlink(t *testing.T) {
	var missing Report
	if _, ok := tokenFileStat(&missing, filepath.Join(t.TempDir(), "missing-token")); ok {
		t.Fatalf("tokenFileStat() ok = true, want false for missing token")
	}
	if !darwinHasCheck(missing, CheckUnknown, "token_file") {
		t.Fatalf("checks = %+v, want missing token unknown", missing.Checks)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target-token")
	link := filepath.Join(dir, "token-link")
	if err := os.WriteFile(target, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var linked Report
	stat, ok := tokenFileStat(&linked, link)
	if !ok {
		t.Fatalf("tokenFileStat() ok = false, checks=%+v", linked.Checks)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if stat.path != resolvedTarget {
		t.Fatalf("stat path = %q, want target %q", stat.path, resolvedTarget)
	}
	if !darwinHasCheck(linked, CheckWarn, "token_file_symlink") {
		t.Fatalf("checks = %+v, want symlink warning", linked.Checks)
	}
}

func TestDarwinTokenFileModeChecks(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    syntheticDarwinOtherUID(),
		AgentUIDSet: true,
		TokenFile:   token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusInconclusive {
		t.Fatalf("status = %q checks=%+v, want inconclusive from ACL uncertainty", report.Status, report.Checks)
	}
	if !darwinHasCheck(report, CheckPass, "token_file_not_readable") {
		t.Fatalf("checks = %+v, want token unreadable pass", report.Checks)
	}
	if !darwinHasCheck(report, CheckPass, "token_file_not_writable") {
		t.Fatalf("checks = %+v, want token unwritable pass", report.Checks)
	}
	if !darwinHasCheck(report, CheckUnknown, "token_file_acl") {
		t.Fatalf("checks = %+v, want ACL unknown", report.Checks)
	}
}

func TestDarwinWorldReadableTokenFileIsUnsafe(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    syntheticDarwinOtherUID(),
		AgentUIDSet: true,
		TokenFile:   token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusUnsafe {
		t.Fatalf("status = %q checks=%+v, want unsafe", report.Status, report.Checks)
	}
	if !darwinHasCheck(report, CheckFail, "token_file_not_readable") {
		t.Fatalf("checks = %+v, want readable token failure", report.Checks)
	}
}

func TestDarwinWritableTokenParentIsUnsafe(t *testing.T) {
	dir := t.TempDir()
	openDir := filepath.Join(dir, "open")
	if err := os.Mkdir(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(openDir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    syntheticDarwinOtherUID(),
		AgentUIDSet: true,
		TokenFile:   token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !darwinHasCheck(report, CheckFail, "token_file_parent_not_writable") {
		t.Fatalf("checks = %+v, want writable parent failure", report.Checks)
	}
}

func TestDarwinTokenSymlinkChecksResolvedParent(t *testing.T) {
	dir := t.TempDir()
	safeDir := filepath.Join(dir, "safe")
	openDir := filepath.Join(dir, "open")
	linkDir := filepath.Join(safeDir, "link")
	if err := os.Mkdir(safeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(openDir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(openDir, linkDir); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    syntheticDarwinOtherUID(),
		AgentUIDSet: true,
		TokenFile:   filepath.Join(linkDir, "hf-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !darwinHasCheck(report, CheckFail, "token_file_resolved_parent_not_writable") {
		t.Fatalf("checks = %+v, want resolved parent writable failure", report.Checks)
	}
}

func TestDarwinParentFailureMessages(t *testing.T) {
	tests := []struct {
		name    string
		check   string
		failure parentFailure
		want    string
	}{
		{name: "token writable", check: "token_file_parent_not_writable", failure: parentWritable, want: "agent can write a token-file parent directory"},
		{name: "token symlink", check: "token_file_parent_not_writable", failure: parentSymlinkReplace, want: "agent can replace a symlinked token-file parent directory entry"},
		{name: "socket writable", check: "socket_parent_not_writable", failure: parentWritable, want: "agent can write parent directory /tmp/x"},
		{name: "socket symlink", check: "socket_parent_not_writable", failure: parentSymlinkReplace, want: "agent can replace symlinked parent directory entry /tmp/x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parentFailureMessage(tc.check, "/tmp/x", tc.failure); got != tc.want {
				t.Fatalf("parentFailureMessage() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDarwinSocketChecksAndProbe(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "hf-broker-sock-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	socketPath := filepath.Join(dir, "broker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Run(context.Background(), Options{
		AgentUID:    syntheticDarwinOtherUID(),
		AgentUIDSet: true,
		Socket:      socketPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !darwinHasCheck(report, CheckPass, "socket_is_socket") {
		t.Fatalf("checks = %+v, want socket pass", report.Checks)
	}
	if !darwinHasCheck(report, CheckUnknown, "socket_acl") {
		t.Fatalf("checks = %+v, want socket ACL unknown", report.Checks)
	}

	result := RunProbe("", 0, socketPath)
	if !result.SocketConnectable {
		t.Fatalf("RunProbe() = %+v, want connectable socket for current user", result)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hf_secret_value") {
		t.Fatalf("probe result leaked token")
	}
}

func TestDarwinActiveProbeSkippedWithoutTarget(t *testing.T) {
	var report Report
	runActiveProbeChecks(context.Background(), &report, identity{uid: os.Getuid()}, Options{HelperPath: "/bin/echo"})
	if !darwinHasCheck(report, CheckWarn, "active_probe") {
		t.Fatalf("checks = %+v, want skipped active probe warning", report.Checks)
	}
}

func TestDarwinActiveProbeCannotSwitchUserWithoutRoot(t *testing.T) {
	var report Report
	runActiveProbeChecks(context.Background(), &report, identity{uid: syntheticDarwinOtherUID()}, Options{
		HelperPath: "/bin/echo",
		TokenFile:  "/tmp/hf-token",
	})
	if os.Geteuid() == 0 {
		t.Skip("root can switch user for active probe")
	}
	if !darwinHasCheck(report, CheckUnknown, "active_probe") {
		t.Fatalf("checks = %+v, want active probe unknown", report.Checks)
	}
}

func TestDarwinActiveProbeReportsHelperFailure(t *testing.T) {
	var report Report
	runActiveProbeChecks(context.Background(), &report, identity{uid: os.Getuid()}, Options{
		HelperPath: "/path/does/not/exist",
		TokenFile:  "/tmp/hf-token",
	})
	if !darwinHasCheck(report, CheckUnknown, "active_probe") {
		t.Fatalf("checks = %+v, want active probe failure unknown", report.Checks)
	}
}

func TestDarwinActiveProbeReportsReadableToken(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "probe-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '{\"token_file_readable\":true,\"token_file_writable\":false,\"socket_connectable\":false}\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    os.Getuid(),
		AgentUIDSet: true,
		TokenFile:   token,
		HelperPath:  helper,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !darwinHasCheck(report, CheckFail, "active_probe_token_file") {
		t.Fatalf("checks = %+v, want active probe token failure", report.Checks)
	}
}

func TestDarwinWriteTextDoesNotLeakSecrets(t *testing.T) {
	report := Report{
		Status: StatusUnsafe,
		Checks: []Check{
			{Status: CheckFail, Name: "token_file_not_readable", Message: "agent can read the token file"},
		},
	}
	var out bytes.Buffer
	if err := WriteText(&out, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "hf_secret_value") {
		t.Fatalf("text output leaked secret")
	}
}

func darwinHasCheck(report Report, status CheckStatus, name string) bool {
	for _, check := range report.Checks {
		if check.Status == status && check.Name == name {
			return true
		}
	}
	return false
}

func syntheticDarwinOtherUID() int {
	uid := os.Getuid() + 100000
	if uid == 0 {
		return 100000
	}
	return uid
}
