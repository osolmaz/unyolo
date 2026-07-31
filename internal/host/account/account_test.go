package account

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls [][]string
	run   func(string, ...string) ([]byte, error)
}

func (runner *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	runner.calls = append(runner.calls, append([]string{name}, args...))
	return runner.run(name, args...)
}

func TestLinuxListFiltersSystemAccounts(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{run: func(string, ...string) ([]byte, error) {
		return []byte("root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000:Bob:/home/bob:/bin/bash\nservice:x:999:999::/srv/service:/usr/sbin/nologin\n"), nil
	}}
	values, err := (Backend{OS: "linux", Runner: runner}).List(context.Background())
	if err != nil || len(values) != 1 || values[0].Name != "bob" {
		t.Fatalf("List() = %+v, %v", values, err)
	}
}

func TestLinuxManagedPlanUsesFixedSafeCommand(t *testing.T) {
	t.Parallel()
	backend := Backend{OS: "linux", Runner: &fakeRunner{run: func(string, ...string) ([]byte, error) { return nil, errors.New("missing") }}}
	plan, err := backend.PlanCreate("unyolo-agent", "/var/lib/unyolo-agent", 0)
	if err != nil || plan.Record.Shell != "/usr/sbin/nologin" || !plan.System {
		t.Fatalf("PlanCreate() = %+v, %v", plan, err)
	}
	if _, err := backend.PlanCreate("root", "/root", 0); err == nil {
		t.Fatal("unsafe root account accepted")
	}
}

func TestMacListAndInspection(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{run: func(name string, args ...string) ([]byte, error) {
		joined := strings.Join(append([]string{name}, args...), " ")
		switch {
		case strings.Contains(joined, "-list /Users UniqueID"):
			return []byte("root 0\nalice 501\nhidden 502\n"), nil
		case strings.Contains(joined, "/Users/alice"):
			return []byte("UniqueID: 501\nPrimaryGroupID: 20\nNFSHomeDirectory: /Users/alice\nUserShell: /bin/zsh\nIsHidden: 0\n"), nil
		case strings.Contains(joined, "/Users/hidden"):
			return []byte("UniqueID: 502\nPrimaryGroupID: 502\nNFSHomeDirectory: /Users/hidden\nUserShell: /usr/bin/false\nIsHidden: 1\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}}
	values, err := (Backend{OS: "darwin", Runner: runner}).List(context.Background())
	if err != nil || len(values) != 1 || values[0].Name != "alice" {
		t.Fatalf("List() = %+v, %v", values, err)
	}
}

func TestMacManagedPlan(t *testing.T) {
	t.Parallel()
	backend := Backend{OS: "darwin"}
	plan, err := backend.PlanCreate("unyolo-agent", "/Users/Shared/unyolo-agent", 550)
	if err != nil || !plan.Record.Hidden || plan.Record.Shell != "/usr/bin/false" || plan.Record.UID != 550 {
		t.Fatalf("PlanCreate() = %+v, %v", plan, err)
	}
	if _, err := backend.PlanCreate("unyolo-agent", filepath.Join("relative", "home"), 550); err == nil {
		t.Fatal("relative home accepted")
	}
	if _, err := backend.PlanCreate("unyolo-agent", "/Users/Shared/unyolo-agent", 500); err == nil {
		t.Fatal("system UID accepted")
	}
}
