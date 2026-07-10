package service

import (
	"strings"
	"testing"
)

func TestRenderSystemd(t *testing.T) {
	body, err := RenderSystemd(SystemdUnit{
		Description: "test broker", User: "broker", Group: "broker",
		EnvironmentFile: "/etc/test/env", ExecStart: "/usr/local/bin/test serve",
		StateDir: "/var/lib/test", ConfigDir: "/etc/test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"After=network-online.target", "EnvironmentFile=/etc/test/env", "ExecStart=/usr/local/bin/test serve",
		"ProtectSystem=strict", "ProtectHome=true", "ReadWritePaths=/var/lib/test", "NoNewPrivileges=true", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("unit missing %q:\n%s", want, body)
		}
	}
}

func TestRenderSystemdRejectsUnsafeValues(t *testing.T) {
	base := SystemdUnit{
		Description: "test", User: "broker", Group: "broker", EnvironmentFile: "/etc/test/env",
		ExecStart: "/usr/bin/test serve", StateDir: "/var/lib/test", ConfigDir: "/etc/test",
	}
	for _, mutate := range []func(*SystemdUnit){
		func(unit *SystemdUnit) { unit.Description = "" },
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
		func(unit *SystemdUnit) { unit.ExtraDirectives = []string{"bad"} },
		func(unit *SystemdUnit) { unit.ExtraDirectives = []string{"User=root"} },
		func(unit *SystemdUnit) { unit.ExtraDirectives = []string{"ProtectSystem=false"} },
		func(unit *SystemdUnit) { unit.ExtraDirectives = []string{"ExecStart=/bin/sh"} },
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
