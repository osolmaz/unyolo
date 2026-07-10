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
		ExtraDirectives: []string{"NoNewPrivileges=true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"After=network-online.target", "EnvironmentFile=/etc/test/env", "ExecStart=/usr/local/bin/test serve",
		"ProtectSystem=strict", "ReadWritePaths=/var/lib/test", "NoNewPrivileges=true", "WantedBy=multi-user.target",
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
		func(unit *SystemdUnit) { unit.EnvironmentFile = "relative" },
		func(unit *SystemdUnit) { unit.ExecStart = "test serve" },
		func(unit *SystemdUnit) { unit.ExtraDirectives = []string{"bad"} },
	} {
		unit := base
		mutate(&unit)
		if _, err := RenderSystemd(unit); err == nil {
			t.Fatalf("RenderSystemd(%+v) error = nil", unit)
		}
	}
}
