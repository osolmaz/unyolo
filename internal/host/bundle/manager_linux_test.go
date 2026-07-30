//go:build linux

package bundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
)

type runnerCall struct {
	name string
	args []string
}

type scriptedRunner struct {
	calls   []runnerCall
	active  bool
	showPID string
	showErr error
}

func (r *scriptedRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, runnerCall{name: name, args: append([]string(nil), args...)})
	if len(args) > 0 && args[0] == "is-active" && !r.active {
		return nil, errors.New("inactive")
	}
	if len(args) > 0 && args[0] == "show" {
		return []byte(r.showPID), r.showErr
	}
	return nil, nil
}

func TestSystemdManagerLifecycleAndStatus(t *testing.T) {
	runner := &scriptedRunner{active: true, showPID: fmt.Sprintf("%d\n", os.Getpid())}
	manager := newNativeManager(runner)
	if err := manager.Stop(t.Context(), "gh-broker.service"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context(), "gh-broker.service"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Enable(t.Context(), "gh-broker.service"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Disable(t.Context(), "retired.service"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status(t.Context(), "gh-broker.service")
	if err != nil || !status.Active || status.PID != os.Getpid() || status.Executable == "" {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
	want := []runnerCall{
		{name: "systemctl", args: []string{"stop", "gh-broker.service"}},
		{name: "systemctl", args: []string{"start", "gh-broker.service"}},
		{name: "systemctl", args: []string{"enable", "gh-broker.service"}},
		{name: "systemctl", args: []string{"disable", "retired.service"}},
		{name: "systemctl", args: []string{"daemon-reload"}},
		{name: "systemctl", args: []string{"is-active", "--quiet", "gh-broker.service"}},
		{name: "systemctl", args: []string{"show", "--property=MainPID", "--value", "gh-broker.service"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestSystemdManagerRejectsInactiveAndInvalidProcesses(t *testing.T) {
	runner := &scriptedRunner{}
	manager := newNativeManager(runner)
	status, err := manager.Status(t.Context(), "gh-broker.service")
	if err != nil || status.Active {
		t.Fatalf("inactive Status() = %+v, %v", status, err)
	}
	runner.active, runner.showPID = true, "invalid"
	if _, err := manager.Status(t.Context(), "gh-broker.service"); err == nil {
		t.Fatal("invalid MainPID was accepted")
	}
	runner.showErr = errors.New("show failed")
	if _, err := manager.Status(t.Context(), "gh-broker.service"); err == nil {
		t.Fatal("systemctl show failure was ignored")
	}
}
