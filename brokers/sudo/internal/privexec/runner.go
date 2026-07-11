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

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
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
	if r == nil || r.SelfPath == "" {
		return executorprotocol.Outcome{}, errors.New("privileged runner is unavailable")
	}
	if err := hostcheck.ValidateExecution(value, r.BrokerUID); err != nil {
		return executorprotocol.Outcome{}, err
	}
	canonical, err := plan.EncodeCanonical(value)
	if err != nil {
		return executorprotocol.Outcome{}, err
	}
	readPlan, writePlan, err := os.Pipe()
	if err != nil {
		return executorprotocol.Outcome{}, err
	}
	defer func() { _ = readPlan.Close(); _ = writePlan.Close() }()
	arguments := append([]string(nil), r.ChildArgs...)
	arguments = append(arguments, "--internal-exec", "3")
	command := exec.CommandContext(ctx, r.SelfPath, arguments...) // #nosec G204 -- root-owned self path and fixed arguments only.
	command.Env = []string{}
	command.ExtraFiles = []*os.File{readPlan}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
	if err := command.Start(); err != nil {
		return executorprotocol.Outcome{Started: false}, err
	}
	_ = readPlan.Close()
	budget.setKill(func() { _ = killProcessGroup(command.Process.Pid) })
	writeDone := make(chan struct{})
	go func() {
		_, _ = writePlan.Write(canonical)
		_ = writePlan.Close()
		close(writeDone)
	}()
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	var waitErr error
	timedOut := false
	select {
	case waitErr = <-waitDone:
	case <-ctx.Done():
		timedOut = true
		_ = killProcessGroup(command.Process.Pid)
		waitErr = <-waitDone
	}
	<-writeDone
	outcome := executorprotocol.Outcome{
		Started: true, ExitCode: command.ProcessState.ExitCode(), TimedOut: timedOut,
		Truncated: budget.truncatedOutput(), Duration: time.Since(startedAt), Stdout: stdout.Bytes(), Stderr: stderr.Bytes(),
	}
	if exitError := (*exec.ExitError)(nil); errors.As(waitErr, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			outcome.Signal = status.Signal().String()
		}
		return outcome, nil
	}
	if waitErr != nil {
		return outcome, waitErr
	}
	return outcome, nil
}

func RunInternalChild(args []string) (bool, error) {
	index := -1
	for candidate, value := range args {
		if value == "--internal-exec" {
			index = candidate
			break
		}
	}
	if index < 0 {
		return false, nil
	}
	if index+2 != len(args) {
		return true, errors.New("invalid internal execution arguments")
	}
	if os.Geteuid() != 0 {
		return true, errors.New("internal execution requires root")
	}
	fd, err := strconv.Atoi(args[index+1])
	if err != nil || fd < 3 || fd > 64 {
		return true, errors.New("invalid internal plan descriptor")
	}
	file := os.NewFile(uintptr(fd), "sudo-plan") // #nosec G115 -- descriptor range is validated.
	if file == nil {
		return true, errors.New("internal plan descriptor is unavailable")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxChildPlanBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxChildPlanBytes {
		return true, errors.New("internal execution plan is invalid")
	}
	value, err := plan.DecodeCanonical(data)
	if err != nil {
		return true, errors.New("internal execution plan is invalid")
	}
	if err := hostcheck.ValidateExecution(value, ^uint32(0)); err != nil {
		return true, err
	}
	return true, executePlan(value)
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
