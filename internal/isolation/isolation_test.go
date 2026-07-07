//go:build linux

package isolation

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseProcStatus(t *testing.T) {
	status, err := ParseProcStatus([]byte("Name:\ttest\nUid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\nGroups:\t1002 2000\nCapEff:\t0000000000200000\nCapPrm:\t0000000000000002\n"))
	if err != nil {
		t.Fatalf("ParseProcStatus() error = %v", err)
	}
	if status.uid != 1001 {
		t.Fatalf("uid = %d, want 1001", status.uid)
	}
	if status.capEff != 1<<21 {
		t.Fatalf("capEff = %#x, want CAP_SYS_ADMIN bit", status.capEff)
	}
	if status.capPrm != 1<<1 {
		t.Fatalf("capPrm = %#x, want CAP_DAC_OVERRIDE bit", status.capPrm)
	}
	if status.gid != 1002 || len(status.gids) != 2 || status.gids[1] != 2000 {
		t.Fatalf("groups = gid %d gids %+v, want gid 1002 groups [1002 2000]", status.gid, status.gids)
	}
}

func TestParseProcStatusUsesFilesystemIDs(t *testing.T) {
	status, err := ParseProcStatus([]byte("Uid:\t1001\t1002\t1003\t1004\nGid:\t2001\t2002\t2003\t2004\nGroups:\t3001 3002\n"))
	if err != nil {
		t.Fatalf("ParseProcStatus() error = %v", err)
	}
	if status.uid != 1004 || status.gid != 2004 {
		t.Fatalf("ids = uid %d gid %d, want filesystem ids 1004/2004", status.uid, status.gid)
	}
	if !status.hasUID(1002) || status.allUIDsMatch(1001) {
		t.Fatalf("uid values = %+v, want full uid set preserved", status.uidValues)
	}
}

func TestParseProcStatusAllowsEmptyGroups(t *testing.T) {
	status, err := ParseProcStatus([]byte("Uid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\nGroups:\t\n"))
	if err != nil {
		t.Fatalf("ParseProcStatus() error = %v", err)
	}
	if len(status.gids) != 0 {
		t.Fatalf("groups = %+v, want empty supplementary group list", status.gids)
	}
}

func TestParseProcStatusErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "missing uid", body: "Name:\ttest\nCapEff:\t0000000000000000\n", want: "uid field is missing"},
		{name: "missing gid", body: "Uid:\t1000\n", want: "gid field is missing"},
		{name: "empty uid", body: "Uid:\t\n", want: "uid field is empty"},
		{name: "bad uid", body: "Uid:\tnope\n", want: "parse uid"},
		{name: "bad cap", body: "Uid:\t1000\nCapEff:\tnope\n", want: "parse CapEff"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseProcStatus([]byte(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseProcStatus() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunDetectsRootAndDangerousGroups(t *testing.T) {
	report, err := Run(context.Background(), Options{AgentUID: 0, AgentUIDSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusUnsafe {
		t.Fatalf("status = %q, want unsafe", report.Status)
	}
	if !hasCheck(report, CheckFail, "agent_not_root") {
		t.Fatalf("checks = %+v, want root failure", report.Checks)
	}
}

func TestCapabilityCheckTreatsSetFCAPAsDangerous(t *testing.T) {
	var report Report
	runCapabilityCheck(&report, 1<<31)
	if !hasCheck(report, CheckFail, "agent_capabilities") {
		t.Fatalf("checks = %+v, want CAP_SETFCAP failure", report.Checks)
	}
}

func TestRunResolvesImplicitCurrentUser(t *testing.T) {
	report, err := Run(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Agent.UID != os.Getuid() {
		t.Fatalf("agent UID = %d, want current UID %d", report.Agent.UID, os.Getuid())
	}
}

func TestRunResolvesAgentFromPID(t *testing.T) {
	report, err := Run(context.Background(), Options{AgentPID: os.Getpid()})
	if err != nil {
		t.Fatal(err)
	}
	if report.Agent.UID != os.Getuid() {
		t.Fatalf("agent UID = %d, want current UID %d", report.Agent.UID, os.Getuid())
	}
}

func TestRunFailsForMissingAgentPID(t *testing.T) {
	_, err := Run(context.Background(), Options{AgentPID: 999999999})
	if err == nil || !strings.Contains(err.Error(), "read agent process status") {
		t.Fatalf("Run() error = %v, want missing process status", err)
	}
}

func TestRunRejectsNegativePIDs(t *testing.T) {
	_, err := Run(context.Background(), Options{AgentPID: -1})
	if err == nil || !strings.Contains(err.Error(), "--agent-pid must be non-negative") {
		t.Fatalf("Run() error = %v, want agent PID validation", err)
	}
	_, err = Run(context.Background(), Options{BrokerPID: -1})
	if err == nil || !strings.Contains(err.Error(), "--broker-pid must be non-negative") {
		t.Fatalf("Run() error = %v, want broker PID validation", err)
	}
}

func TestRunRequiresPIDForUnknownUID(t *testing.T) {
	_, err := Run(context.Background(), Options{AgentUID: syntheticOtherUID(), AgentUIDSet: true})
	if err == nil || !strings.Contains(err.Error(), "pass --agent-pid") {
		t.Fatalf("Run() error = %v, want unknown UID to require process group facts", err)
	}
}

func TestRunWithoutCredentialTargetIsInconclusive(t *testing.T) {
	report, err := Run(context.Background(), Options{AgentUID: knownOtherUID(t), AgentUIDSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusInconclusive {
		t.Fatalf("status = %q checks=%+v, want inconclusive", report.Status, report.Checks)
	}
	if !hasCheck(report, CheckUnknown, "credential_target") {
		t.Fatalf("checks = %+v, want missing credential target check", report.Checks)
	}
}

func TestBrokerTokenFileEnvRequiresTokenFileTarget(t *testing.T) {
	var report Report
	addBrokerEnvCredentialTargetCheck(&report, "", []string{"HF_BROKER_HF_TOKEN_FILE=/etc/hf-broker/hf-token"}, nil, "/", nil)
	if !hasCheck(report, CheckUnknown, "credential_target") {
		t.Fatalf("checks = %+v, want unchecked token-file credential target", report.Checks)
	}
}

func TestBrokerTokenFileEnvMustMatchCheckedTokenFile(t *testing.T) {
	dir := localTempDir(t)
	checked := filepath.Join(dir, "checked-token")
	actual := filepath.Join(dir, "actual-token")
	if err := os.WriteFile(checked, []byte("checked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(actual, []byte("actual"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mismatch Report
	addBrokerEnvCredentialTargetCheck(&mismatch, checked, []string{"HF_BROKER_HF_TOKEN_FILE=" + actual}, nil, "/", nil)
	if !hasCheck(mismatch, CheckUnknown, "credential_target") {
		t.Fatalf("checks = %+v, want mismatched token-file credential target", mismatch.Checks)
	}
	var match Report
	addBrokerEnvCredentialTargetCheck(&match, checked, []string{"HF_BROKER_HF_TOKEN_FILE=" + checked}, nil, "/", nil)
	if !hasCheck(match, CheckPass, "credential_target") {
		t.Fatalf("checks = %+v, want matched token-file credential target", match.Checks)
	}
	var absoluteMatch Report
	addBrokerEnvCredentialTargetCheck(&absoluteMatch, checked, []string{"HF_BROKER_HF_TOKEN_FILE=" + checked}, nil, "", os.ErrNotExist)
	if !hasCheck(absoluteMatch, CheckPass, "credential_target") {
		t.Fatalf("checks = %+v, want absolute token-file credential target to not require cwd", absoluteMatch.Checks)
	}
}

func TestBrokerTokenFileEnvResolvesRelativePathFromBrokerCWD(t *testing.T) {
	dir := localTempDir(t)
	brokerDir := filepath.Join(dir, "broker")
	doctorDir := filepath.Join(dir, "doctor")
	if err := os.Mkdir(brokerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(doctorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	brokerToken := filepath.Join(brokerDir, "hf-token")
	doctorToken := filepath.Join(doctorDir, "hf-token")
	if err := os.WriteFile(brokerToken, []byte("broker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(doctorToken, []byte("doctor"), 0o600); err != nil {
		t.Fatal(err)
	}

	var mismatch Report
	addBrokerEnvCredentialTargetCheck(&mismatch, doctorToken, []string{"HF_BROKER_HF_TOKEN_FILE=hf-token"}, nil, brokerDir, nil)
	if !hasCheck(mismatch, CheckUnknown, "credential_target") {
		t.Fatalf("checks = %+v, want relative broker token path mismatch", mismatch.Checks)
	}

	var match Report
	addBrokerEnvCredentialTargetCheck(&match, brokerToken, []string{"HF_BROKER_HF_TOKEN_FILE=hf-token"}, nil, brokerDir, nil)
	if !hasCheck(match, CheckPass, "credential_target") {
		t.Fatalf("checks = %+v, want relative broker token path match", match.Checks)
	}
}

func TestBrokerTokenFileEnvRequiresBrokerCWD(t *testing.T) {
	var report Report
	addBrokerEnvCredentialTargetCheck(&report, "/etc/hf-broker/hf-token", []string{"HF_BROKER_HF_TOKEN_FILE=hf-token"}, nil, "", os.ErrNotExist)
	if !hasCheck(report, CheckUnknown, "credential_target") {
		t.Fatalf("checks = %+v, want missing broker cwd to be inconclusive", report.Checks)
	}
}

func TestBrokerEnvTokenCanBeCredentialTarget(t *testing.T) {
	var report Report
	addBrokerEnvCredentialTargetCheck(&report, "", []string{"HF_BROKER_HF_TOKEN=hf_secret_value"}, nil, "", nil)
	if !hasCheck(report, CheckPass, "credential_target") {
		t.Fatalf("checks = %+v, want broker env token credential target", report.Checks)
	}
}

func TestRunKeepsConfiguredIdentityForPIDMismatch(t *testing.T) {
	agentUID := syntheticOtherUID()
	report, err := Run(context.Background(), Options{
		AgentUID:    agentUID,
		AgentUIDSet: true,
		AgentPID:    os.Getpid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Agent.UID != agentUID {
		t.Fatalf("reported agent UID = %d, want configured UID %d", report.Agent.UID, agentUID)
	}
	if !hasCheck(report, CheckFail, "agent_process_uid") {
		t.Fatalf("checks = %+v, want process UID mismatch failure", report.Checks)
	}
}

func TestTokenFileReadabilityByModeBits(t *testing.T) {
	dir := localTempDir(t)
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    knownOtherUID(t),
		AgentUIDSet: true,
		TokenFile:   token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusOK {
		t.Fatalf("status = %q checks=%+v, want ok", report.Status, report.Checks)
	}
	if !hasCheck(report, CheckPass, "token_file_not_readable") {
		t.Fatalf("checks = %+v, want unreadable token pass", report.Checks)
	}
}

func TestAgentOwnedTokenFileIsUnsafe(t *testing.T) {
	dir := localTempDir(t)
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o000); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    os.Getuid(),
		AgentUIDSet: true,
		TokenFile:   token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(report, CheckFail, "token_file_not_readable") || !hasCheck(report, CheckFail, "token_file_not_writable") {
		t.Fatalf("checks = %+v, want owner access failures", report.Checks)
	}
}

func TestTokenFileWorldReadableIsUnsafe(t *testing.T) {
	dir := localTempDir(t)
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    knownOtherUID(t),
		AgentUIDSet: true,
		TokenFile:   token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusUnsafe {
		t.Fatalf("status = %q, want unsafe", report.Status)
	}
	if !hasCheck(report, CheckFail, "token_file_not_readable") {
		t.Fatalf("checks = %+v, want readable token failure", report.Checks)
	}
}

func TestRunProbeChecksWriteOnlyTokenFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-restricted files")
	}
	dir := localTempDir(t)
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o200); err != nil {
		t.Fatal(err)
	}
	result := RunProbe(token, 0, "")
	if result.TokenFileReadable {
		t.Fatalf("TokenFileReadable = true, want false")
	}
	if !result.TokenFileWritable {
		t.Fatalf("TokenFileWritable = false, want true")
	}
}

func TestTokenFileACLIsInconclusive(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl not available")
	}
	agentUID := knownOtherUID(t)
	dir := localTempDir(t)
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(setfacl, "-m", "u:"+strconv.Itoa(agentUID)+":r", token)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("setfacl could not set numeric user ACL: %v %s", err, string(out))
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    agentUID,
		AgentUIDSet: true,
		TokenFile:   token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusInconclusive {
		t.Fatalf("status = %q checks=%+v, want inconclusive", report.Status, report.Checks)
	}
	if !hasCheck(report, CheckUnknown, "token_file_acl") {
		t.Fatalf("checks = %+v, want POSIX ACL unknown check", report.Checks)
	}
}

func TestTokenFileSymlinkUsesTargetMode(t *testing.T) {
	dir := localTempDir(t)
	target := filepath.Join(dir, "target-token")
	link := filepath.Join(dir, "token-link")
	if err := os.WriteFile(target, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(absTarget, link); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    knownOtherUID(t),
		AgentUIDSet: true,
		TokenFile:   link,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusOK {
		t.Fatalf("status = %q checks=%+v, want ok", report.Status, report.Checks)
	}
	if !hasCheck(report, CheckWarn, "token_file_symlink") || !hasCheck(report, CheckPass, "token_file_not_readable") {
		t.Fatalf("checks = %+v, want symlink warning and unreadable target pass", report.Checks)
	}
}

func TestTokenFileSymlinkChecksTargetParent(t *testing.T) {
	dir := localTempDir(t)
	openDir := filepath.Join(dir, "open-target")
	if err := os.Mkdir(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(openDir, "target-token")
	link := filepath.Join(dir, "token-link")
	if err := os.WriteFile(target, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(absTarget, link); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    knownOtherUID(t),
		AgentUIDSet: true,
		TokenFile:   link,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(report, CheckFail, "token_file_resolved_parent_not_writable") {
		t.Fatalf("checks = %+v, want target parent writable failure", report.Checks)
	}
}

func TestTokenFileSymlinkedParentDoesNotUseSymlinkModeBits(t *testing.T) {
	dir := localTempDir(t)
	targetDir := filepath.Join(dir, "target")
	linkDir := filepath.Join(dir, "link")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, linkDir); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(targetDir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    knownOtherUID(t),
		AgentUIDSet: true,
		TokenFile:   filepath.Join(linkDir, "hf-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasCheck(report, CheckFail, "token_file_entry_not_replaceable") || hasCheck(report, CheckFail, "token_file_parent_not_writable") {
		t.Fatalf("checks = %+v, want symlinked parent path not to fail on symlink mode bits", report.Checks)
	}
}

func TestTokenFileIntermediateSymlinkChecksResolvedParent(t *testing.T) {
	dir := localTempDir(t)
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
		AgentUID:    knownOtherUID(t),
		AgentUIDSet: true,
		TokenFile:   filepath.Join(linkDir, "hf-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(report, CheckFail, "token_file_resolved_parent_not_writable") {
		t.Fatalf("checks = %+v, want resolved parent writable failure", report.Checks)
	}
}

func TestTokenFileSymlinkedParentEntryOwnedByAgentIsUnsafe(t *testing.T) {
	dir := localTempDir(t)
	targetDir := filepath.Join(dir, "target")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(targetDir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp(os.TempDir(), "hf-broker-parent-link-*")
	if err != nil {
		t.Fatal(err)
	}
	linkDir := tmp.Name()
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(linkDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, linkDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(linkDir)
	})
	report, err := Run(context.Background(), Options{
		AgentUID:    os.Getuid(),
		AgentUIDSet: true,
		TokenFile:   filepath.Join(linkDir, "hf-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(report, CheckFail, "token_file_parent_not_writable") {
		t.Fatalf("checks = %+v, want symlinked parent entry replacement failure", report.Checks)
	}
}

func TestWritableParentIsUnsafe(t *testing.T) {
	dir := localTempDir(t)
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
		AgentUID:    knownOtherUID(t),
		AgentUIDSet: true,
		TokenFile:   token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusUnsafe {
		t.Fatalf("status = %q, want unsafe", report.Status)
	}
	if !hasCheck(report, CheckFail, "token_file_parent_not_writable") {
		t.Fatalf("checks = %+v, want parent writable failure", report.Checks)
	}
}

func TestRunChecksCurrentAgentProcessAndBrokerPID(t *testing.T) {
	report, err := Run(context.Background(), Options{
		AgentUID:    os.Getuid(),
		AgentUIDSet: true,
		AgentPID:    os.Getpid(),
		BrokerPID:   os.Getpid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(report, CheckPass, "agent_process_uid") {
		t.Fatalf("checks = %+v, want agent process UID pass", report.Checks)
	}
	if !hasCheck(report, CheckFail, "broker_separate_uid") {
		t.Fatalf("checks = %+v, want broker same UID failure", report.Checks)
	}
	if !hasNamedCheck(report, "agent_capabilities") {
		t.Fatalf("checks = %+v, want capability check", report.Checks)
	}
	if !hasNamedCheck(report, "agent_env_no_hf_token") {
		t.Fatalf("checks = %+v, want env check", report.Checks)
	}
}

func TestSocketChecks(t *testing.T) {
	dir := localTempDir(t)
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
		AgentUID:    knownOtherUID(t),
		AgentUIDSet: true,
		Socket:      socketPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(report, CheckPass, "socket_is_socket") {
		t.Fatalf("checks = %+v, want socket pass", report.Checks)
	}
	if !hasCheck(report, CheckPass, "socket_not_world_writable") {
		t.Fatalf("checks = %+v, want socket mode pass", report.Checks)
	}
	if !hasCheck(report, CheckPass, "socket_not_agent_writable") {
		t.Fatalf("checks = %+v, want agent socket mode pass", report.Checks)
	}
}

func TestSocketWritableByAgentGroupIsUnsafe(t *testing.T) {
	dir := localTempDir(t)
	socketPath := filepath.Join(dir, "broker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
	}()
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}
	report := Report{}
	runSocketChecks(&report, identity{
		uid:  syntheticOtherUID(),
		gids: map[int]bool{os.Getgid(): true},
	}, socketPath)
	if !hasCheck(report, CheckFail, "socket_not_agent_writable") {
		t.Fatalf("checks = %+v, want agent-writable socket failure", report.Checks)
	}
}

func TestSocketIntermediateSymlinkChecksResolvedParent(t *testing.T) {
	dir := localTempDir(t)
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
	socketPath := filepath.Join(openDir, "broker.sock")
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
	if err := os.Symlink(openDir, linkDir); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    knownOtherUID(t),
		AgentUIDSet: true,
		Socket:      filepath.Join(linkDir, "broker.sock"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(report, CheckFail, "socket_resolved_parent_not_writable") {
		t.Fatalf("checks = %+v, want resolved socket parent writable failure", report.Checks)
	}
}

func TestSocketACLIsInconclusive(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl not available")
	}
	agentUID := knownOtherUID(t)
	dir := localTempDir(t)
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
	cmd := exec.Command(setfacl, "-m", "u:"+strconv.Itoa(agentUID)+":rw", socketPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("setfacl could not set numeric user ACL: %v %s", err, string(out))
	}
	report := Report{}
	runSocketChecks(&report, identity{
		uid:  agentUID,
		gids: map[int]bool{},
	}, socketPath)
	if !hasCheck(report, CheckUnknown, "socket_acl") {
		t.Fatalf("checks = %+v, want socket ACL unknown", report.Checks)
	}
}

func TestActiveProbeUsesHelper(t *testing.T) {
	dir := localTempDir(t)
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "probe-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '{\"token_file_readable\":true,\"broker_env_readable\":false}\\n'\n"), 0o700); err != nil {
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
	if !hasCheck(report, CheckFail, "active_probe_token_file") {
		t.Fatalf("checks = %+v, want active probe token failure", report.Checks)
	}
}

func TestActiveProbeRunsForSocketOnlyChecks(t *testing.T) {
	dir := localTempDir(t)
	helper := filepath.Join(dir, "probe-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '{\"socket_connectable\":true}\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Options{
		AgentUID:    os.Getuid(),
		AgentUIDSet: true,
		Socket:      "/tmp/hf-broker.sock",
		HelperPath:  helper,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(report, CheckFail, "active_probe_socket_connect") {
		t.Fatalf("checks = %+v, want socket active probe failure", report.Checks)
	}
}

func TestActiveProbeScrubsEnvironment(t *testing.T) {
	t.Setenv("HF_BROKER_HF_TOKEN", "hf_secret_value")
	cmd, ok := activeProbeCommand(context.Background(), identity{uid: os.Getuid(), gid: os.Getgid()}, Options{
		HelperPath: "/bin/echo",
		TokenFile:  "/tmp/token",
	})
	if !ok {
		t.Fatal("active probe command did not build")
	}
	for _, item := range cmd.Env {
		if strings.Contains(item, "hf_secret_value") || strings.HasPrefix(item, "HF_BROKER_HF_TOKEN=") {
			t.Fatalf("active probe env leaked secret: %q", item)
		}
	}
}

func TestActiveProbeCannotSwitchUserWithoutRoot(t *testing.T) {
	_, ok, err := runActiveProbe(context.Background(), identity{uid: syntheticOtherUID()}, Options{
		HelperPath: "/bin/echo",
		TokenFile:  "/tmp/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok && os.Geteuid() != 0 {
		t.Fatalf("active probe unexpectedly ran as another user")
	}
}

func TestCredentialHelpers(t *testing.T) {
	cred := identity{uid: 42, gids: map[int]bool{9: true, 3: true}}.credential()
	if cred.Uid != 42 || cred.Gid != 3 {
		t.Fatalf("credential = %+v, want uid 42 gid 3", cred)
	}
	withPrimary := identity{uid: 42, gid: 9, gidSet: true, gids: map[int]bool{9: true, 3: true}}.credential()
	if withPrimary.Gid != 9 {
		t.Fatalf("credential with primary gid = %+v, want gid 9", withPrimary)
	}
	if firstCredentialGroup(nil) != 0 {
		t.Fatalf("firstCredentialGroup(nil) != 0")
	}
}

func TestCanAccessTreatsOwnerAsAccessible(t *testing.T) {
	agent := identity{uid: 42, gids: map[int]bool{}}
	stat := fileStat{uid: 42, gid: 7, mode: 0}
	if !canRead(agent, stat) || !canWrite(agent, stat) {
		t.Fatalf("owner-controlled path should be treated as readable and writable")
	}
}

func TestStickyDirectoryDoesNotAllowOtherUserReplacement(t *testing.T) {
	agent := identity{uid: 42, gids: map[int]bool{}}
	stat := fileStat{uid: 7, gid: 7, mode: os.ModeDir | os.ModeSticky | 0o777}
	if canReplaceDirectoryEntry(agent, stat) {
		t.Fatalf("sticky directory owned by another UID should not allow replacement")
	}
}

func TestStickyDirectoryAllowsEntryOwnerReplacement(t *testing.T) {
	agent := identity{uid: 42, gids: map[int]bool{}}
	entry := fileStat{uid: 42, gid: 7, mode: os.ModeSymlink | 0o777}
	parent := fileStat{uid: 7, gid: 7, mode: os.ModeDir | os.ModeSticky | 0o777}
	if !canReplacePathEntry(agent, entry, parent) {
		t.Fatalf("sticky directory should allow entry owner replacement")
	}
	other := identity{uid: 43, gids: map[int]bool{}}
	if canReplacePathEntry(other, entry, parent) {
		t.Fatalf("sticky directory should not allow unrelated user replacement")
	}
}

func TestIdentityWithProcessStatusUsesRuntimeGroups(t *testing.T) {
	agent := identityWithProcessStatus(identity{user: "agent", uid: 1, gid: 1}, procStatus{
		uid:       2,
		gid:       3,
		gidValues: []int{6, 7, 8, 3},
		gids:      []int{4, 5},
	})
	if agent.uid != 2 || agent.gid != 3 || !agent.gids[3] || !agent.gids[4] || !agent.gids[5] || !agent.gids[6] || !agent.gids[7] || !agent.gids[8] {
		t.Fatalf("agent = %+v, want process uid/gid/groups", agent)
	}
}

func TestRunProbeDoesNotReturnContents(t *testing.T) {
	dir := localTempDir(t)
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := RunProbe(token, os.Getpid(), "")
	if !result.TokenFileReadable || !result.BrokerEnvReadable {
		t.Fatalf("RunProbe() = %+v, want readable token and environ for current process", result)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hf_secret_value") {
		t.Fatalf("probe result leaked token")
	}
}

func TestWriteTextDoesNotLeakEnvValues(t *testing.T) {
	report := Report{
		Status: StatusUnsafe,
		Checks: []Check{
			{Status: CheckFail, Name: "agent_env_no_hf_token", Message: "agent process environment contains an HF token variable name"},
		},
	}
	var out bytes.Buffer
	if err := WriteText(&out, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "hf_secret_value") {
		t.Fatalf("text output leaked secret")
	}
	if !strings.Contains(out.String(), "UNSAFE") {
		t.Fatalf("text output = %q, want status", out.String())
	}
}

func TestWriteJSONAndExitCode(t *testing.T) {
	report := Report{Status: StatusInconclusive, Checks: []Check{{Status: CheckUnknown, Name: "active_probe", Message: "not run"}}}
	var out bytes.Buffer
	if err := WriteJSON(&out, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"status": "inconclusive"`) {
		t.Fatalf("json output = %q", out.String())
	}
	if ExitCode(StatusOK) != 0 || ExitCode(StatusUnsafe) != 1 || ExitCode(StatusInconclusive) != 2 {
		t.Fatalf("unexpected exit codes")
	}
}

func TestEnvHasSecretName(t *testing.T) {
	if !envHasSecretName([]string{"HF_BROKER_HF_TOKEN=secret"}) {
		t.Fatalf("envHasSecretName() = false, want true")
	}
	if !envHasSecretName([]string{"HF_BROKER_HF_TOKEN_FILE=/etc/hf-broker/hf-token"}) {
		t.Fatalf("envHasSecretName() = false, want token file variable to count")
	}
	if !envHasSecretName([]string{"HF_TOKEN_PATH=/home/agent/.cache/huggingface/token"}) {
		t.Fatalf("envHasSecretName() = false, want HF token path variable to count")
	}
	if envHasSecretName([]string{"PATH=/bin"}) {
		t.Fatalf("envHasSecretName() = true, want false")
	}
}

func hasCheck(report Report, status CheckStatus, name string) bool {
	for _, check := range report.Checks {
		if check.Status == status && check.Name == name {
			return true
		}
	}
	return false
}

func hasNamedCheck(report Report, name string) bool {
	for _, check := range report.Checks {
		if check.Name == name {
			return true
		}
	}
	return false
}

func syntheticOtherUID() int {
	uid := os.Getuid() + 100000
	if uid == 0 {
		return 100000
	}
	return uid
}

func knownOtherUID(t *testing.T) int {
	t.Helper()
	for _, name := range []string{"nobody", "daemon"} {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		uid, err := strconv.Atoi(u.Uid)
		if err == nil && uid != 0 && uid != os.Getuid() {
			return uid
		}
	}
	t.Skip("no resolvable non-root test user")
	return 0
}

func localTempDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
