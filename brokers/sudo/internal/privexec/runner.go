//go:build linux || darwin

// Package privexec performs the final no-shell Unix privilege transition.
package privexec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/osolmaz/unyolo/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/plan"
)

const maxChildPlanBytes = 2 << 20

type Runner struct {
	SelfPath  string
	BrokerUID uint32
	ChildArgs []string
}

func NewRunner(selfPath string, brokerUID uint32) (*Runner, error) {
	if err := hostcheck.ValidateRootFile(selfPath); err != nil {
		return nil, errors.New("privileged helper binary is not trusted")
	}
	return &Runner{SelfPath: selfPath, BrokerUID: brokerUID}, nil
}

func (r *Runner) Run(ctx context.Context, value plan.Plan) (executorprotocol.Outcome, error) {
	canonical, err := r.validatedCanonicalPlan(value)
	if err != nil {
		return executorprotocol.Outcome{}, err
	}
	planPipe, err := newPlanPipe()
	if err != nil {
		return executorprotocol.Outcome{}, err
	}
	defer planPipe.Close()
	command := r.childCommand(ctx, planPipe.read)
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return executorprotocol.Outcome{}, err
	}
	defer func() { _ = devNull.Close() }()
	command.Stdin = devNull
	budget := newOutputBudget(value.MaxOutputBytes)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = budget.writer(&stdout)
	command.Stderr = budget.writer(&stderr)
	startedAt := time.Now()
	if err := startChild(command, planPipe.read); err != nil {
		return executorprotocol.Outcome{Started: false}, err
	}
	budget.setKill(func() { _ = killProcessGroup(command.Process.Pid) })
	writeDone := planPipe.writeAsync(canonical)
	waitErr, timedOut := waitForChild(ctx, command)
	<-writeDone
	outcome := runnerOutcome(command, budget, stdout.Bytes(), stderr.Bytes(), timedOut, time.Since(startedAt))
	return finishChildOutcome(outcome, waitErr)
}

func (r *Runner) validatedCanonicalPlan(value plan.Plan) ([]byte, error) {
	if r == nil || r.SelfPath == "" {
		return nil, errors.New("privileged runner is unavailable")
	}
	if err := hostcheck.ValidateExecution(value, r.BrokerUID); err != nil {
		return nil, err
	}
	return plan.EncodeCanonical(value)
}

func startChild(command *exec.Cmd, readPlan *os.File) error {
	if err := command.Start(); err != nil {
		return err
	}
	_ = readPlan.Close()
	return nil
}

func finishChildOutcome(outcome executorprotocol.Outcome, waitErr error) (executorprotocol.Outcome, error) {
	if exitError := (*exec.ExitError)(nil); errors.As(waitErr, &exitError) {
		outcome.Signal = exitSignal(exitError)
		return outcome, nil
	}
	if waitErr != nil {
		return outcome, waitErr
	}
	return outcome, nil
}

func exitSignal(exitError *exec.ExitError) string {
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok {
		return ""
	}
	return signaledStatus(status)
}

func signaledStatus(status syscall.WaitStatus) string {
	if status.Signaled() {
		return status.Signal().String()
	}
	return ""
}

type planPipe struct {
	read  *os.File
	write *os.File
}

func newPlanPipe() (planPipe, error) {
	readPlan, writePlan, err := os.Pipe()
	return planPipe{read: readPlan, write: writePlan}, err
}

func (p planPipe) Close() {
	_ = p.read.Close()
	_ = p.write.Close()
}

func (p planPipe) writeAsync(canonical []byte) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		_, _ = p.write.Write(canonical)
		_ = p.write.Close()
		close(done)
	}()
	return done
}

func (r *Runner) childCommand(ctx context.Context, readPlan *os.File) *exec.Cmd {
	arguments := append([]string(nil), r.ChildArgs...)
	arguments = append(arguments, "--internal-exec", "3")
	command := exec.CommandContext(ctx, r.SelfPath, arguments...) // #nosec G204 -- root-owned self path and fixed arguments only.
	command.Env = []string{}
	command.ExtraFiles = []*os.File{readPlan}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return command
}

func waitForChild(ctx context.Context, command *exec.Cmd) (error, bool) {
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	select {
	case waitErr := <-waitDone:
		return waitErr, false
	case <-ctx.Done():
		_ = killProcessGroup(command.Process.Pid)
		return <-waitDone, true
	}
}

func runnerOutcome(command *exec.Cmd, budget *outputBudget, stdout []byte, stderr []byte, timedOut bool, duration time.Duration) executorprotocol.Outcome {
	return executorprotocol.Outcome{
		Started: true, ExitCode: command.ProcessState.ExitCode(), TimedOut: timedOut,
		Truncated: budget.truncatedOutput(), Duration: duration, Stdout: stdout, Stderr: stderr,
	}
}

func RunInternalChild(args []string) (bool, error) {
	fd, handled, err := internalPlanDescriptor(args)
	if !handled || err != nil {
		return handled, err
	}
	return true, runInternalPlanDescriptor(fd)
}

func runInternalPlanDescriptor(fd int) error {
	if err := requireInternalRoot(); err != nil {
		return err
	}
	value, err := readInternalPlan(fd)
	if err != nil {
		return err
	}
	return executeInternalPlan(value)
}

func requireInternalRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("internal execution requires root")
	}
	return nil
}

func executeInternalPlan(value plan.Plan) error {
	if err := hostcheck.ValidateExecution(value, ^uint32(0)); err != nil {
		return err
	}
	return executePlan(value)
}

func internalPlanDescriptor(args []string) (int, bool, error) {
	index := internalExecFlagIndex(args)
	if index < 0 {
		return 0, false, nil
	}
	if index+2 != len(args) {
		return 0, true, errors.New("invalid internal execution arguments")
	}
	fd, err := strconv.Atoi(args[index+1])
	if err != nil || fd < 3 || fd > 64 {
		return 0, true, errors.New("invalid internal plan descriptor")
	}
	return fd, true, nil
}

func internalExecFlagIndex(args []string) int {
	for candidate, value := range args {
		if value == "--internal-exec" {
			return candidate
		}
	}
	return -1
}

func readInternalPlan(fd int) (plan.Plan, error) {
	file := os.NewFile(uintptr(fd), "sudo-plan") // #nosec G115 -- descriptor range is validated.
	if file == nil {
		return plan.Plan{}, errors.New("internal plan descriptor is unavailable")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxChildPlanBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxChildPlanBytes {
		return plan.Plan{}, errors.New("internal execution plan is invalid")
	}
	value, err := plan.DecodeCanonical(data)
	if err != nil {
		return plan.Plan{}, errors.New("internal execution plan is invalid")
	}
	return value, nil
}

type outputBudget struct {
	mu        sync.Mutex
	remaining int
	truncated bool
	kill      func()
	killed    bool
}

func newOutputBudget(limit uint32) *outputBudget { return &outputBudget{remaining: int(limit)} }

func (b *outputBudget) writer(destination *bytes.Buffer) io.Writer {
	return writerFunc(func(value []byte) (int, error) {
		b.mu.Lock()
		written := len(value)
		keep := min(len(value), b.remaining)
		if keep > 0 {
			_, _ = destination.Write(value[:keep])
			b.remaining -= keep
		}
		var kill func()
		if keep < len(value) {
			b.truncated = true
			if !b.killed && b.kill != nil {
				b.killed = true
				kill = b.kill
			}
		}
		b.mu.Unlock()
		if kill != nil {
			kill()
		}
		return written, nil
	})
}

func (b *outputBudget) setKill(kill func()) {
	b.mu.Lock()
	b.kill = kill
	shouldKill := b.truncated && !b.killed
	if shouldKill {
		b.killed = true
	}
	b.mu.Unlock()
	if shouldKill {
		kill()
	}
}

func (b *outputBudget) truncatedOutput() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(value []byte) (int, error) { return f(value) }
