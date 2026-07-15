package service

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestRenderSystemd(t *testing.T) {
	body, err := RenderSystemd(SystemdUnit{
		Description: "test broker", User: "broker", Group: "broker",
		EnvironmentFile: "/etc/test/env", ExecStart: "/usr/bin/test serve",
		StateDir: "/var/lib/test", ConfigDir: "/etc/test", PathValidation: PathValidationPreview,
		AfterUnits: []string{"test-helper.service"}, RequiresUnits: []string{"test-helper.service"},
		RuntimeDirectory: "test-broker", RuntimeDirectoryMode: 0o750,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"After=network-online.target", "EnvironmentFile=/etc/test/env", "ExecStart=/usr/bin/test serve",
		"After=network-online.target test-helper.service", "Requires=test-helper.service", "RuntimeDirectory=test-broker", "RuntimeDirectoryMode=0750",
		"ProtectSystem=strict", "ProtectHome=true", "ReadWritePaths=/var/lib/test", "NoNewPrivileges=true", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("unit missing %q:\n%s", want, body)
		}
	}
}

func TestRenderSystemdSocket(t *testing.T) {
	body, err := RenderSystemdSocket(SystemdSocketUnit{
		Description: "test agent listener", ListenStream: "/run/brokerkit/test/agent/broker.sock",
		Service: "test-broker.service", FileDescriptorName: "agent", SocketUser: "root",
		SocketGroup: "test-broker-agent", SocketMode: 0o660, DirectoryMode: 0o750,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ListenStream=/run/brokerkit/test/agent/broker.sock", "FileDescriptorName=agent", "SocketGroup=test-broker-agent", "SocketMode=0660", "DirectoryMode=0750", "Service=test-broker.service", "WantedBy=sockets.target"} {
		if !strings.Contains(body, want) {
			t.Fatalf("socket unit missing %q:\n%s", want, body)
		}
	}
	for _, mutate := range []func(*SystemdSocketUnit){
		func(unit *SystemdSocketUnit) { unit.ListenStream = "relative.sock" },
		func(unit *SystemdSocketUnit) { unit.FileDescriptorName = "bad/name" },
		func(unit *SystemdSocketUnit) { unit.SocketGroup = "bad=name" },
		func(unit *SystemdSocketUnit) { unit.SocketMode = 0o666 },
		func(unit *SystemdSocketUnit) { unit.DirectoryMode = 0o751 },
		func(unit *SystemdSocketUnit) { unit.Service = "bad.socket" },
	} {
		unit := SystemdSocketUnit{Description: "test", ListenStream: "/run/test.sock", Service: "test.service", FileDescriptorName: "agent", SocketUser: "root", SocketGroup: "agent", SocketMode: 0o660, DirectoryMode: 0o750}
		mutate(&unit)
		if _, err := RenderSystemdSocket(unit); err == nil {
			t.Fatalf("RenderSystemdSocket(%+v) error = nil", unit)
		}
	}
}

func TestRenderSystemdRejectsUnsafeValues(t *testing.T) {
	base := SystemdUnit{
		Description: "test", User: "broker", Group: "broker", EnvironmentFile: "/etc/test/env",
		ExecStart: "/usr/bin/test serve", StateDir: "/var/lib/test", ConfigDir: "/etc/test", PathValidation: PathValidationPreview,
	}
	for _, mutate := range []func(*SystemdUnit){
		func(unit *SystemdUnit) { unit.Description = "" },
		func(unit *SystemdUnit) { unit.Description = "continued\\" },
		func(unit *SystemdUnit) { unit.Description = "bad\tdescription" },
		func(unit *SystemdUnit) { unit.ExecStart = "/usr/bin/test\x00serve" },
		func(unit *SystemdUnit) { unit.User = "broker\nUser=root" },
		func(unit *SystemdUnit) { unit.User = "%u" },
		func(unit *SystemdUnit) { unit.Group = "%g" },
		func(unit *SystemdUnit) { unit.EnvironmentFile = "relative" },
		func(unit *SystemdUnit) { unit.ExecStart = "test serve" },
		func(unit *SystemdUnit) { unit.StateDir = "/var/lib/test broker" },
		func(unit *SystemdUnit) { unit.ConfigDir = "/etc/test%N" },
		func(unit *SystemdUnit) { unit.ExecStart = "/usr/bin/test %N" },
		func(unit *SystemdUnit) { unit.ExecStart = "/usr/bin/test $MODE" },
		func(unit *SystemdUnit) { unit.ExecStart = "/usr/bin/test ; /bin/sh" },
		func(unit *SystemdUnit) { unit.ExecStart = "/home/bob/.local/bin/test" },
		func(unit *SystemdUnit) { unit.EnvironmentFile = "/run/user/1000/test.env" },
		func(unit *SystemdUnit) { unit.ConfigDir = "/root/test" },
		func(unit *SystemdUnit) { unit.StateDir = "/" },
		func(unit *SystemdUnit) { unit.ConfigDir = "/etc/test/../test" },
		func(unit *SystemdUnit) { unit.HomeAccess = "invalid" },
		func(unit *SystemdUnit) { unit.ExtraDirectives = []string{"bad"} },
		func(unit *SystemdUnit) { unit.ExtraDirectives = []string{"User=root"} },
		func(unit *SystemdUnit) { unit.ExtraDirectives = []string{"ProtectSystem=false"} },
		func(unit *SystemdUnit) { unit.ExtraDirectives = []string{"ExecStart=/bin/sh"} },
		func(unit *SystemdUnit) { unit.AfterUnits = []string{"bad unit.service"} },
		func(unit *SystemdUnit) { unit.RequiresUnits = []string{"../helper.service"} },
		func(unit *SystemdUnit) { unit.RuntimeDirectory = "../run" },
		func(unit *SystemdUnit) { unit.RuntimeDirectoryMode = 0o777 },
	} {
		unit := base
		mutate(&unit)
		if _, err := RenderSystemd(unit); err == nil {
			t.Fatalf("RenderSystemd(%+v) error = nil", unit)
		}
	}
}

func TestTrustedStateDirectoryRequiresConfiguredServiceOwner(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0o750); err != nil { // #nosec G302 -- service state ownership fixture.
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	oldLookup := lookupSystemUser
	lookupSystemUser = func(name string) (*user.User, error) {
		switch name {
		case "broker":
			return &user.User{Username: name, Uid: strconv.FormatUint(uint64(stat.Uid), 10)}, nil
		case "unrelated":
			return &user.User{Username: name, Uid: strconv.FormatUint(uint64(stat.Uid)+1, 10)}, nil
		default:
			return nil, fmt.Errorf("unknown user")
		}
	}
	t.Cleanup(func() { lookupSystemUser = oldLookup })
	if err := validateTrustedServiceComponent("state directory", path, info, "broker"); err != nil {
		t.Fatalf("configured owner rejected: %v", err)
	}
	if err := validateTrustedServiceComponent("state directory", path, info, "unrelated"); err == nil {
		t.Fatal("unrelated state directory owner accepted")
	}
}

func TestStrictSystemdExecutableValidation(t *testing.T) {
	rootAccount, err := user.LookupId("0")
	if err != nil {
		t.Fatal(err)
	}
	rootGroup, err := user.LookupGroupId("0")
	if err != nil {
		t.Fatal(err)
	}
	environmentFile, err := filepath.EvalSymlinks("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	stateRoot, err := filepath.EvalSymlinks("/var")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.EvalSymlinks("/usr/bin")
	if err != nil {
		t.Fatal(err)
	}
	unit := SystemdUnit{
		Description: "test", User: rootAccount.Username, Group: rootGroup.Name, EnvironmentFile: environmentFile,
		ExecStart: executable, StateDir: filepath.Join(stateRoot, "lib", "brokerkit-test-missing"), ConfigDir: filepath.Dir(environmentFile),
	}
	if _, err := RenderSystemd(unit); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("RenderSystemd(directory executable) error = %v", err)
	}
	unit.PathValidation = PathValidationPreview
	if _, err := RenderSystemd(unit); err != nil {
		t.Fatalf("RenderSystemd(preview directory executable): %v", err)
	}
}

func TestIdentityCanExecute(t *testing.T) {
	tests := []struct {
		name       string
		mode       os.FileMode
		ownerUID   uint64
		ownerGID   uint64
		uid        uint64
		gid        uint64
		canExecute bool
	}{
		{name: "owner", mode: 0o100, ownerUID: 10, uid: 10, canExecute: true},
		{name: "owner denied", mode: 0o010, ownerUID: 10, ownerGID: 20, uid: 10, gid: 20},
		{name: "group", mode: 0o010, ownerUID: 10, ownerGID: 20, uid: 11, gid: 20, canExecute: true},
		{name: "other", mode: 0o001, ownerUID: 10, ownerGID: 20, uid: 11, gid: 21, canExecute: true},
		{name: "root any execute", mode: 0o001, ownerUID: 10, ownerGID: 20, canExecute: true},
		{name: "root no execute", mode: 0o600, ownerUID: 10, ownerGID: 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := identityCanExecute(tc.mode, tc.ownerUID, tc.ownerGID, tc.uid, tc.gid); got != tc.canExecute {
				t.Fatalf("identityCanExecute() = %t, want %t", got, tc.canExecute)
			}
		})
	}
}

func TestIdentityCanExecuteWithSupplementaryGroup(t *testing.T) {
	groups := map[uint64]struct{}{30: {}}
	if !identityCanExecuteWithGroups(0o750, 10, 30, 20, groups) {
		t.Fatal("supplementary group execute permission rejected")
	}
	if identityCanExecuteWithGroups(0o740, 10, 30, 20, groups) {
		t.Fatal("missing supplementary group execute permission accepted")
	}
}

func TestValidateExecutableAncestorAccess(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- private executable-ancestor fixture.
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	ownerUID := uint64(info.Sys().(*syscall.Stat_t).Uid)
	path := filepath.Join(directory, "broker")
	if err := validateExecutableAncestorAccess(path, ownerUID+1, map[uint64]struct{}{}); err == nil || !strings.Contains(err.Error(), "not searchable") {
		t.Fatalf("validateExecutableAncestorAccess() error = %v", err)
	}
	if err := validateExecutableAncestorAccess(path, 0, map[uint64]struct{}{}); err != nil {
		t.Fatalf("root ancestor access rejected: %v", err)
	}
}

func TestSystemIdentityAccessIDsIncludesSupplementaryGroups(t *testing.T) {
	oldUser := lookupSystemUser
	oldGroup := lookupSystemGroup
	oldGroupIDs := lookupSystemGroupIDs
	lookupSystemUser = func(string) (*user.User, error) { return &user.User{Username: "broker", Uid: "10"}, nil }
	lookupSystemGroup = func(string) (*user.Group, error) { return &user.Group{Name: "broker", Gid: "20"}, nil }
	lookupSystemGroupIDs = func(*user.User) ([]string, error) { return []string{"20", "30"}, nil }
	t.Cleanup(func() {
		lookupSystemUser = oldUser
		lookupSystemGroup = oldGroup
		lookupSystemGroupIDs = oldGroupIDs
	})
	uid, groups, err := systemIdentityAccessIDs("broker", "broker")
	if err != nil || uid != 10 {
		t.Fatalf("systemIdentityAccessIDs() uid=%d err=%v", uid, err)
	}
	for _, gid := range []uint64{20, 30} {
		if _, ok := groups[gid]; !ok {
			t.Fatalf("systemIdentityAccessIDs() missing gid %d", gid)
		}
	}
}

func TestRenderSystemdRejectsUntrustedExistingPathComponents(t *testing.T) {
	root := t.TempDir()
	unit := SystemdUnit{
		Description: "test", User: "broker", Group: "broker", EnvironmentFile: filepath.Join(root, "config", "env"),
		ExecStart: "/usr/bin/test serve", StateDir: "/var/lib/test", ConfigDir: filepath.Join(root, "config"),
	}
	if _, err := RenderSystemd(unit); err == nil {
		t.Fatal("RenderSystemd(user-owned config ancestor) error = nil")
	}
	unit.PathValidation = PathValidationPreview
	if _, err := RenderSystemd(unit); err != nil {
		t.Fatalf("RenderSystemd(test path override): %v", err)
	}
	unit.PathValidation = "invalid"
	if _, err := RenderSystemd(unit); err == nil {
		t.Fatal("RenderSystemd(invalid path validation) error = nil")
	}
}

func TestRenderSystemdHomeAccessPolicies(t *testing.T) {
	base := SystemdUnit{
		Description: "test", User: "broker", Group: "broker", EnvironmentFile: "/etc/test/env",
		ExecStart: "/usr/bin/test serve", StateDir: "/var/lib/test", ConfigDir: "/etc/test", PathValidation: PathValidationPreview,
	}
	for policy, want := range map[HomeAccess]string{
		HomeAccessDeny: "ProtectHome=true", HomeAccessReadOnly: "ProtectHome=read-only", HomeAccessAllow: "ProtectHome=false",
	} {
		unit := base
		unit.HomeAccess = policy
		body, err := RenderSystemd(unit)
		if err != nil || !strings.Contains(body, want) {
			t.Fatalf("RenderSystemd(%q) body=%q err=%v", policy, body, err)
		}
	}
	base.HomeAccess = HomeAccessAllow
	body, err := RenderSystemd(base)
	if err != nil {
		t.Fatalf("home-enabled service: %v", err)
	}
	if !strings.Contains(body, "ReadWritePaths=/var/lib/test -/home -/root -/run/user") {
		t.Fatalf("home-enabled service lacks writable home paths:\n%s", body)
	}
}

func TestRenderSystemdPrivilegeEscalationPolicies(t *testing.T) {
	base := SystemdUnit{
		Description: "test", User: "broker", Group: "broker", EnvironmentFile: "/etc/test/env",
		ExecStart: "/usr/bin/test serve", StateDir: "/var/lib/test", ConfigDir: "/etc/test", PathValidation: PathValidationPreview,
	}
	for policy, want := range map[PrivilegeEscalation]string{
		PrivilegeEscalationDeny:  "NoNewPrivileges=true",
		PrivilegeEscalationAllow: "NoNewPrivileges=false",
	} {
		unit := base
		unit.PrivilegeEscalation = policy
		body, err := RenderSystemd(unit)
		if err != nil || !strings.Contains(body, want) {
			t.Fatalf("RenderSystemd(%q) body=%q err=%v", policy, body, err)
		}
	}
	base.PrivilegeEscalation = "invalid"
	if _, err := RenderSystemd(base); err == nil {
		t.Fatal("RenderSystemd(invalid privilege escalation) error = nil")
	}
}

func TestRenderSystemdHostFilesystemAccessPolicies(t *testing.T) {
	base := SystemdUnit{
		Description: "test", User: "broker", Group: "broker", EnvironmentFile: "/etc/test/env",
		ExecStart: "/usr/bin/test serve", StateDir: "/var/lib/test", ConfigDir: "/etc/test", PathValidation: PathValidationPreview,
	}
	for access, want := range map[HostFilesystemAccess]string{
		HostFilesystemAccessDeny:  "ProtectSystem=strict",
		HostFilesystemAccessAllow: "ProtectSystem=false",
	} {
		unit := base
		unit.HostFilesystemAccess = access
		body, err := RenderSystemd(unit)
		if err != nil || !strings.Contains(body, want) {
			t.Fatalf("RenderSystemd(%q) body=%q err=%v", access, body, err)
		}
	}
	base.HostFilesystemAccess = "invalid"
	if _, err := RenderSystemd(base); err == nil {
		t.Fatal("RenderSystemd(invalid host filesystem access) error = nil")
	}
}

func TestRenderSystemdRejectsWritableInputOverlap(t *testing.T) {
	base := SystemdUnit{
		Description: "test", User: "broker", Group: "broker", EnvironmentFile: "/etc/test/env",
		ExecStart: "/usr/bin/test serve", StateDir: "/var/lib/test", ConfigDir: "/etc/test", PathValidation: PathValidationPreview,
	}
	for _, mutate := range []func(*SystemdUnit){
		func(unit *SystemdUnit) { unit.ConfigDir = unit.StateDir },
		func(unit *SystemdUnit) { unit.ConfigDir = unit.StateDir + "/config" },
		func(unit *SystemdUnit) { unit.StateDir = unit.ConfigDir + "/state" },
		func(unit *SystemdUnit) { unit.ConfigDir = "/" },
		func(unit *SystemdUnit) { unit.EnvironmentFile = unit.StateDir + "/env" },
		func(unit *SystemdUnit) { unit.ExecStart = unit.StateDir + "/broker serve" },
		func(unit *SystemdUnit) { unit.HomeAccess = HomeAccessAllow; unit.ExecStart = "/home/bob/bin/test" },
		func(unit *SystemdUnit) {
			unit.HomeAccess = HomeAccessReadOnly
			unit.EnvironmentFile = "/run/user/1000/test.env"
		},
	} {
		unit := base
		mutate(&unit)
		if _, err := RenderSystemd(unit); err == nil {
			t.Fatalf("RenderSystemd(%+v) error = nil", unit)
		}
	}
}

func TestProtectedHomePath(t *testing.T) {
	for _, path := range []string{"/home", "/home/bob/bin", "/root/x", "/run/user/1000/x"} {
		if !protectedHomePath(path) {
			t.Fatalf("protectedHomePath(%q) = false", path)
		}
	}
	for _, path := range []string{"/etc/test", "/var/lib/test", "/homeward/test", "/run/users/test"} {
		if protectedHomePath(path) {
			t.Fatalf("protectedHomePath(%q) = true", path)
		}
	}
}

func TestValidateExtraSystemdDirectives(t *testing.T) {
	if err := validateExtraDirectives([]string{"ProtectKernelTunables=true"}); err != nil {
		t.Fatalf("safe extra directive: %v", err)
	}
	for _, directive := range []string{
		"", "bad", " bad=value", "Bad.Key=value", "[Unit]=value", "User=root",
		"ReadWriteDirectories=/", "ProtectKernelTunables=false", "RootDirectory=/",
	} {
		if err := validateExtraDirectives([]string{directive}); err == nil {
			t.Fatalf("validateExtraDirectives(%q) error = nil", directive)
		}
	}
}

func TestSystemdPathCharacters(t *testing.T) {
	for _, value := range []string{"/etc/test-broker/config_1.0+local", "/A/Z"} {
		if err := validateSystemdPath("path", value); err != nil {
			t.Fatalf("validateSystemdPath(%q): %v", value, err)
		}
	}
	for _, value := range []string{"/etc/a b", "/etc/a%b", "/etc/a\\b"} {
		if err := validateSystemdPath("path", value); err == nil {
			t.Fatalf("validateSystemdPath(%q) error = nil", value)
		}
	}
}
