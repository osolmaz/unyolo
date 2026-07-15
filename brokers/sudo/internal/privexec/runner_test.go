package privexec

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"golang.org/x/sys/unix"
)

func TestOutputBudgetCapsCombinedStreams(t *testing.T) {
	t.Parallel()
	budget := newOutputBudget(5)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	killed := 0
	budget.setKill(func() { killed++ })
	_, _ = budget.writer(&stdout).Write([]byte("abc"))
	_, _ = budget.writer(&stderr).Write([]byte("def"))
	_, _ = budget.writer(&stdout).Write([]byte("more"))
	if stdout.String() != "abc" || stderr.String() != "de" || killed != 1 || !budget.truncatedOutput() {
		t.Fatalf("stdout=%q stderr=%q killed=%d truncated=%v", stdout.String(), stderr.String(), killed, budget.truncatedOutput())
	}
}

func TestExecutePlanIsolatedChildSetup(t *testing.T) {
	if os.Getenv("SUDO_BROKER_EXEC_CHILD_TEST") == "1" {
		value := plan.Plan{TargetUID: uint32(os.Getuid()), TargetGID: uint32(os.Getgid()), Executable: "/usr/bin/true", // #nosec G115 -- ids are non-negative.
			WorkingDirectory: "/", Environment: []string{"LANG=C", "LC_ALL=C"}, TimeoutSeconds: 5, MaxOutputBytes: 1 << 30}
		if err := executePlan(value); err == nil {
			t.Fatal("privilege transition unexpectedly returned")
		}
		return
	}
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestExecutePlanIsolatedChildSetup$") // #nosec G204 -- current test binary and fixed selector.
	command.Env = append(os.Environ(), "SUDO_BROKER_EXEC_CHILD_TEST=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated child setup: %v: %s", err, output)
	}
}

func TestRunnerStartsOnlyTrustedFixedExecutable(t *testing.T) {
	t.Parallel()
	if _, err := NewRunner("/usr/bin/true", uint32(os.Getuid())); err != nil { // #nosec G115 -- uid is non-negative.
		t.Fatal(err)
	}
	value := plan.Plan{Schema: plan.SchemaV1, RequestID: "request", ClientID: "bob", Operation: "exec.command", CommandID: "true",
		TargetUser: "current", TargetUID: uint32(os.Getuid()), TargetGID: uint32(os.Getgid()), Executable: "/usr/bin/true", // #nosec G115 -- ids are non-negative.
		WorkingDirectory: "/", Environment: []string{"LANG=C", "LC_ALL=C"}, TimeoutSeconds: 5, MaxOutputBytes: 100,
		CatalogDigest: strings.Repeat("a", 64), RequestedDurationSeconds: 60, RequestedMaxUses: 1, CreatedAt: time.Now().UTC()}
	runner := &Runner{SelfPath: "/usr/bin/true", BrokerUID: uint32(os.Getuid())} // #nosec G115 -- uid is non-negative.
	outcome, err := runner.Run(context.Background(), value)
	if err != nil || !outcome.Started || outcome.ExitCode != 0 {
		t.Fatalf("Run() = %+v, %v", outcome, err)
	}
	if _, err := (*Runner)(nil).Run(context.Background(), value); err == nil {
		t.Fatal("nil runner was accepted")
	}
	if err := validateExecutableDescriptor(-1); err == nil {
		t.Fatal("invalid executable descriptor was accepted")
	}
}

func TestRunInternalChildIsNotPublicPrivilegePath(t *testing.T) {
	t.Parallel()
	handled, err := RunInternalChild(nil)
	if handled || err != nil {
		t.Fatalf("empty child = %v, %v", handled, err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root can enter the internal child path")
	}
	if handled, err := RunInternalChild([]string{"--internal-exec", "3"}); !handled || err == nil || !strings.Contains(err.Error(), "requires root") {
		if !handled || err == nil {
			t.Fatalf("unprivileged child = %v, %v", handled, err)
		}
	}
}

func TestInternalPlanDescriptorAndReadValidation(t *testing.T) {
	t.Parallel()
	if fd, handled, err := internalPlanDescriptor([]string{"--internal-exec", "3"}); fd != 3 || !handled || err != nil {
		t.Fatalf("descriptor = %d, %v, %v", fd, handled, err)
	}
	for _, args := range [][]string{
		{"--internal-exec"},
		{"--internal-exec", "2"},
		{"--internal-exec", "65"},
		{"--internal-exec", "x"},
		{"prefix", "--internal-exec", "3", "suffix"},
	} {
		if _, handled, err := internalPlanDescriptor(args); !handled || err == nil {
			t.Fatalf("invalid descriptor args %v = handled %v err %v", args, handled, err)
		}
	}
	if _, handled, err := internalPlanDescriptor([]string{"serve"}); handled || err != nil {
		t.Fatalf("public args = handled %v err %v", handled, err)
	}

	readPlan, writePlan, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := plan.EncodeCanonical(testChildPlan())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePlan.Write(canonical); err != nil {
		t.Fatal(err)
	}
	_ = writePlan.Close()
	planFD, err := unix.Dup(int(readPlan.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = readPlan.Close()
	decoded, err := readInternalPlan(planFD)
	if err != nil || decoded.RequestID != "request" {
		t.Fatalf("readInternalPlan() = %+v, %v", decoded, err)
	}
}

func testChildPlan() plan.Plan {
	return plan.Plan{
		Schema: plan.SchemaV1, RequestID: "request", ClientID: "bob", Operation: "exec.command", CommandID: "true",
		TargetUser: "current", TargetUID: uint32(os.Getuid()), TargetGID: uint32(os.Getgid()), Executable: "/usr/bin/true", // #nosec G115 -- ids are non-negative.
		WorkingDirectory: "/", Environment: []string{"LANG=C", "LC_ALL=C"}, TimeoutSeconds: 5, MaxOutputBytes: 100,
		CatalogDigest: strings.Repeat("a", 64), RequestedDurationSeconds: 60, RequestedMaxUses: 1, CreatedAt: time.Now().UTC(),
	}
}
