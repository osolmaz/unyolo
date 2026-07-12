//go:build linux || darwin

package doctor

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestRunProbeCommand(t *testing.T) {
	result, ran, err := RunProbeCommand(context.Background(), ProbeCommand{
		HelperPath:    "/bin/sh",
		Args:          []string{"-c", `printf '%s' '{"token_file_readable":true}'`},
		Identity:      Identity{UID: os.Geteuid(), GID: os.Getegid()},
		PrimaryGIDSet: true,
	})
	if err != nil || !ran || !result.TokenFileReadable {
		t.Fatalf("RunProbeCommand() = %+v, %v, %v", result, ran, err)
	}
	if _, ran, err := RunProbeCommand(context.Background(), ProbeCommand{
		HelperPath: "/bin/sh", Args: []string{"-c", "exit 1"}, Identity: Identity{UID: os.Geteuid(), GID: os.Getegid()},
	}); err == nil || !ran {
		t.Fatalf("failed RunProbeCommand() ran=%v err=%v", ran, err)
	}
}

func TestProbeCommandScrubsEnvironmentAndBuildsCredentials(t *testing.T) {
	t.Setenv("HF_BROKER_HF_TOKEN", "hf_secret_value")
	command, ok := probeCommand(context.Background(), ProbeCommand{
		HelperPath: "/bin/echo", Identity: Identity{UID: os.Geteuid(), GID: os.Getegid()}, PrimaryGIDSet: true,
	})
	if !ok || len(command.Env) != 2 {
		t.Fatalf("probeCommand() ok=%v env=%v", ok, command.Env)
	}
	for _, item := range command.Env {
		if strings.Contains(item, "hf_secret_value") || strings.HasPrefix(item, "HF_BROKER_HF_TOKEN=") {
			t.Fatalf("probe environment leaked a secret: %q", item)
		}
	}
	fallback := probeCredential(ProbeCommand{Identity: Identity{UID: 42, GroupIDs: []int{9, 3}}})
	if fallback.Uid != 42 || fallback.Gid != 3 || firstProbeGroup(nil) != 0 {
		t.Fatalf("fallback credential = %+v", fallback)
	}
	primary := probeCredential(ProbeCommand{Identity: Identity{UID: 42, GID: 9, GroupIDs: []int{9, 3}}, PrimaryGIDSet: true})
	if primary.Gid != 9 {
		t.Fatalf("primary credential = %+v", primary)
	}
}
