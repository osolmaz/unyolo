package service

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestRenderLaunchd(t *testing.T) {
	body, err := RenderLaunchd(LaunchdUnit{
		Label: "io.unyolo.huggingface", ProgramArguments: []string{"/usr/local/bin/hf-broker", "serve"},
		UserName: "_hf_broker", GroupName: "_hf_broker", KeepAlive: true,
		Environment: map[string]string{"HF_BROKER_ENDPOINT": "activation://agent", "HF_BROKER_OPERATOR_ENDPOINT": "activation://operator"},
		Sockets: []LaunchdSocket{
			{Name: "agent", Path: "/var/run/unyolo/huggingface/agent/broker.sock", Owner: "root", Group: "hf-broker-agent", Mode: 0o660, DirectoryMode: 0o750},
			{Name: "operator", Path: "/var/run/unyolo/huggingface/operator/broker.sock", Owner: "root", Group: "hf-broker-operator", Mode: 0o660, DirectoryMode: 0o750},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := xml.Unmarshal([]byte(body), new(any)); err != nil {
		t.Fatalf("invalid plist XML: %v", err)
	}
	for _, want := range []string{"<string>io.unyolo.huggingface</string>", "<string>activation://agent</string>", "<key>agent</key>", "<integer>432</integer>", "<integer>5</integer>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("plist missing %q:\n%s", want, body)
		}
	}
}

func TestRenderLaunchdEscapesValues(t *testing.T) {
	body, err := RenderLaunchd(LaunchdUnit{
		Label: "io.unyolo.test", ProgramArguments: []string{"/usr/local/bin/test", "a&b"}, UserName: "broker", GroupName: "broker",
		Environment: map[string]string{"VALUE": "a<b"},
		Sockets:     []LaunchdSocket{{Name: "agent", Path: "/var/run/a&b.sock", Owner: "root", Group: "broker", Mode: 0o660, DirectoryMode: 0o750}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "a&amp;b") || !strings.Contains(body, "a&lt;b") {
		t.Fatalf("values were not escaped:\n%s", body)
	}
}

func TestRenderLaunchdRejectsUnsafeValues(t *testing.T) {
	base := LaunchdUnit{Label: "io.unyolo.test", ProgramArguments: []string{"/usr/local/bin/test"}, UserName: "broker", GroupName: "broker", Sockets: []LaunchdSocket{{Name: "agent", Path: "/var/run/test.sock", Owner: "root", Group: "broker", Mode: 0o660, DirectoryMode: 0o750}}}
	mutations := []func(*LaunchdUnit){
		func(unit *LaunchdUnit) { unit.Label = "test" },
		func(unit *LaunchdUnit) { unit.ProgramArguments = nil },
		func(unit *LaunchdUnit) { unit.ProgramArguments[0] = "relative" },
		func(unit *LaunchdUnit) { unit.ProgramArguments = append(unit.ProgramArguments, "bad\narg") },
		func(unit *LaunchdUnit) { unit.UserName = "bad/name" },
		func(unit *LaunchdUnit) { unit.Environment = map[string]string{"bad-name": "value"} },
		func(unit *LaunchdUnit) { unit.Sockets[0].Path = "relative" },
		func(unit *LaunchdUnit) { unit.Sockets[0].Mode = 0o666 },
		func(unit *LaunchdUnit) { unit.Sockets = append(unit.Sockets, unit.Sockets[0]) },
		func(unit *LaunchdUnit) { unit.ProcessType = "Daemon" },
	}
	for _, mutate := range mutations {
		unit := base
		unit.ProgramArguments = append([]string(nil), base.ProgramArguments...)
		unit.Sockets = append([]LaunchdSocket(nil), base.Sockets...)
		mutate(&unit)
		if _, err := RenderLaunchd(unit); err == nil {
			t.Fatalf("RenderLaunchd(%+v) error = nil", unit)
		}
	}
}
