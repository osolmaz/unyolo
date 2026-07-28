//go:build darwin

package bundle

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type darwinRunner struct {
	calls []string
	fail  bool
}

func (r *darwinRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+":"+args[0])
	if r.fail {
		return nil, errors.New("command failed")
	}
	if name == "launchctl" && args[0] == "print" {
		return []byte("pid = 42\n"), nil
	}
	if name == "ps" {
		return []byte("/Library/Application Support/unyolo/current/bin/gh-broker\n"), nil
	}
	return nil, nil
}

func TestLaunchdManagerLifecycleAndStatus(t *testing.T) {
	runner := &darwinRunner{}
	manager := newNativeManager(runner)
	if err := manager.Stop(t.Context(), "io.unyolo.github"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context(), "io.unyolo.github"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status(t.Context(), "io.unyolo.github")
	if err != nil || !status.Active || status.PID != 42 || status.Executable == "" {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
	if !reflect.DeepEqual(runner.calls, []string{"launchctl:kill", "launchctl:kickstart", "launchctl:print", "ps:-p"}) {
		t.Fatalf("calls = %v", runner.calls)
	}
}

func TestLaunchdManagerRejectsMissingProcess(t *testing.T) {
	if pid := launchdPID("state = running\n"); pid != 0 {
		t.Fatalf("launchdPID() = %d", pid)
	}
	runner := &darwinRunner{fail: true}
	status, err := newNativeManager(runner).Status(t.Context(), "io.unyolo.github")
	if err != nil || status.Active {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
}
