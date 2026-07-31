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

func TestMacPickUIDFindsFirstFreeSlot(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{run: func(name string, args ...string) ([]byte, error) {
		joined := strings.Join(append([]string{name}, args...), " ")
		if strings.Contains(joined, "-list /Users UniqueID") {
			return []byte("root 0\nalice 501\nbob 502\n"), nil
		}
		return nil, errors.New("unexpected command")
	}}
	backend := Backend{OS: "darwin", Runner: runner}
	uid, err := backend.PickUID(context.Background())
	if err != nil || uid != 503 {
		t.Fatalf("PickUID() = %d, %v", uid, err)
	}
}

func TestPickUIDRejectsNonDarwin(t *testing.T) {
	t.Parallel()
	if _, err := (Backend{OS: "linux"}).PickUID(context.Background()); err == nil {
		t.Fatal("linux PickUID succeeded")
	}
}

func TestGroupCreateRoutesPerPlatform(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		backend string
		exists  bool
		expect  []string
	}{
		{"linux-new", "linux", false, []string{"getent group broker", "groupadd --system broker"}},
		{"linux-exists", "linux", true, []string{"getent group broker"}},
		{"darwin-new", "darwin", false, []string{"dscl . -read /Groups/broker", "dseditgroup -o create broker"}},
		{"darwin-exists", "darwin", true, []string{"dscl . -read /Groups/broker"}},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()
			runner := &fakeRunner{run: func(name string, args ...string) ([]byte, error) {
				joined := strings.Join(append([]string{name}, args...), " ")
				if strings.HasPrefix(joined, "getent group") || strings.HasPrefix(joined, "dscl . -read /Groups/") {
					if testcase.exists {
						return []byte("broker\n"), nil
					}
					return nil, errors.New("missing")
				}
				return nil, nil
			}}
			if err := (Backend{OS: testcase.backend, Runner: runner}).EnsureGroup(context.Background(), "broker"); err != nil {
				t.Fatalf("EnsureGroup() = %v", err)
			}
			got := formatCalls(runner.calls)
			if !equalStrings(got, testcase.expect) {
				t.Fatalf("calls = %v, want %v", got, testcase.expect)
			}
		})
	}
}

func TestGroupRemovePerPlatform(t *testing.T) {
	t.Parallel()
	linuxRunner := &fakeRunner{run: func(string, ...string) ([]byte, error) { return []byte("broker:x:100:\n"), nil }}
	if err := (Backend{OS: "linux", Runner: linuxRunner}).RemoveGroup(context.Background(), "broker"); err != nil {
		t.Fatalf("linux RemoveGroup() = %v", err)
	}
	if formatCalls(linuxRunner.calls)[1] != "groupdel broker" {
		t.Fatalf("linux calls = %v", linuxRunner.calls)
	}
	darwinRunner := &fakeRunner{run: func(string, ...string) ([]byte, error) { return []byte("ok"), nil }}
	if err := (Backend{OS: "darwin", Runner: darwinRunner}).RemoveGroup(context.Background(), "broker"); err != nil {
		t.Fatalf("darwin RemoveGroup() = %v", err)
	}
	if formatCalls(darwinRunner.calls)[1] != "dseditgroup -o delete broker" {
		t.Fatalf("darwin calls = %v", darwinRunner.calls)
	}
}

func TestGroupMembersParsing(t *testing.T) {
	t.Parallel()
	linuxRunner := &fakeRunner{run: func(string, ...string) ([]byte, error) {
		return []byte("broker:x:100:alice,bob\n"), nil
	}}
	members, err := (Backend{OS: "linux", Runner: linuxRunner}).GroupMembers(context.Background(), "broker")
	if err != nil || len(members) != 2 || members[0] != "alice" || members[1] != "bob" {
		t.Fatalf("linux GroupMembers() = %v, %v", members, err)
	}
	darwinRunner := &fakeRunner{run: func(string, ...string) ([]byte, error) {
		return []byte("GroupMembership: alice bob\n"), nil
	}}
	members, err = (Backend{OS: "darwin", Runner: darwinRunner}).GroupMembers(context.Background(), "broker")
	if err != nil || len(members) != 2 || members[0] != "alice" || members[1] != "bob" {
		t.Fatalf("darwin GroupMembers() = %v, %v", members, err)
	}
}

func TestGroupMemberAddRemovePerPlatform(t *testing.T) {
	t.Parallel()
	linuxRunner := &fakeRunner{run: func(string, ...string) ([]byte, error) { return nil, nil }}
	backend := Backend{OS: "linux", Runner: linuxRunner}
	if err := backend.AddGroupMember(context.Background(), "broker", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := backend.RemoveGroupMember(context.Background(), "broker", "alice"); err != nil {
		t.Fatal(err)
	}
	expected := []string{"usermod --append --groups broker alice", "gpasswd --delete alice broker"}
	if got := formatCalls(linuxRunner.calls); !equalStrings(got, expected) {
		t.Fatalf("linux calls = %v", got)
	}
	darwinRunner := &fakeRunner{run: func(string, ...string) ([]byte, error) { return nil, nil }}
	backend = Backend{OS: "darwin", Runner: darwinRunner}
	if err := backend.AddGroupMember(context.Background(), "broker", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := backend.RemoveGroupMember(context.Background(), "broker", "alice"); err != nil {
		t.Fatal(err)
	}
	expected = []string{
		"dseditgroup -o edit -a alice -t user broker",
		"dseditgroup -o edit -d alice -t user broker",
	}
	if got := formatCalls(darwinRunner.calls); !equalStrings(got, expected) {
		t.Fatalf("darwin calls = %v", got)
	}
}

func TestRemoveAccountSkipsMissing(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{run: func(name string, args ...string) ([]byte, error) {
		joined := strings.Join(append([]string{name}, args...), " ")
		if strings.HasPrefix(joined, "getent passwd") {
			return nil, errors.New("missing")
		}
		return nil, nil
	}}
	if err := (Backend{OS: "linux", Runner: runner}).RemoveAccount(context.Background(), "broker"); err != nil {
		t.Fatalf("RemoveAccount() = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unexpected calls: %v", runner.calls)
	}
}

func TestRemoveAccountDeletesExisting(t *testing.T) {
	t.Parallel()
	linuxRunner := &fakeRunner{run: func(name string, args ...string) ([]byte, error) {
		joined := strings.Join(append([]string{name}, args...), " ")
		if strings.HasPrefix(joined, "getent passwd") {
			return []byte("broker:x:1000:1000::/home/broker:/bin/false\n"), nil
		}
		return nil, nil
	}}
	if err := (Backend{OS: "linux", Runner: linuxRunner}).RemoveAccount(context.Background(), "broker"); err != nil {
		t.Fatalf("linux RemoveAccount() = %v", err)
	}
	if formatCalls(linuxRunner.calls)[1] != "userdel --remove broker" {
		t.Fatalf("linux calls = %v", linuxRunner.calls)
	}
	darwinRunner := &fakeRunner{run: func(name string, args ...string) ([]byte, error) {
		joined := strings.Join(append([]string{name}, args...), " ")
		if strings.Contains(joined, "-read /Users/broker") {
			return []byte("UniqueID: 550\nPrimaryGroupID: 550\nNFSHomeDirectory: /Users/broker\nUserShell: /usr/bin/false\nIsHidden: 1\n"), nil
		}
		return nil, nil
	}}
	if err := (Backend{OS: "darwin", Runner: darwinRunner}).RemoveAccount(context.Background(), "broker"); err != nil {
		t.Fatalf("darwin RemoveAccount() = %v", err)
	}
	last := darwinRunner.calls[len(darwinRunner.calls)-1]
	if strings.Join(last, " ") != "dscl . -delete /Users/broker" {
		t.Fatalf("darwin final call = %v", last)
	}
}

func TestMacApplyCreateRejectsExistingHome(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	runner := &fakeRunner{run: func(string, ...string) ([]byte, error) { return nil, errors.New("missing") }}
	backend := Backend{OS: "darwin", Runner: runner}
	plan, err := backend.PlanCreate("unyolo-agent", home, 601)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.ApplyCreate(context.Background(), plan); err == nil {
		t.Fatal("preexisting home accepted")
	}
}

func TestVerifyRejectsDrift(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{run: func(name string, args ...string) ([]byte, error) {
		joined := strings.Join(append([]string{name}, args...), " ")
		if strings.Contains(joined, "-read /Users/broker") {
			return []byte("UniqueID: 500\nPrimaryGroupID: 500\nNFSHomeDirectory: /Users/broker\nUserShell: /usr/bin/false\nIsHidden: 1\n"), nil
		}
		return nil, errors.New("unexpected")
	}}
	backend := Backend{OS: "darwin", Runner: runner}
	if err := backend.Verify(context.Background(), Record{Name: "broker", UID: 501, GID: 501, Home: "/Users/broker", Shell: "/usr/bin/false", Hidden: true}); err == nil {
		t.Fatal("verify accepted mismatched UID")
	}
}

func formatCalls(calls [][]string) []string {
	result := make([]string, len(calls))
	for index, call := range calls {
		result[index] = strings.Join(call, " ")
	}
	return result
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
