//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestRewriteLaunchdFlags(t *testing.T) {
	got := rewriteLaunchdFlags([]string{"--launchd-dir=/tmp/launchd", "--launchd-dir", "/other"})
	if strings.Join(got, " ") != "--systemd-dir=/tmp/launchd --systemd-dir /other" {
		t.Fatalf("rewriteLaunchdFlags() = %v", got)
	}
}

func TestHFLaunchdEnvironment(t *testing.T) {
	plan := systemdSetupPlan(setupSystemdOptions{})
	values := hfLaunchdEnvironment(plan)
	if values["HF_BROKER_AGENT_ENDPOINT"] != "activation://agent" || values["HF_BROKER_OPERATOR_ENDPOINT"] != "activation://operator" {
		t.Fatalf("hfLaunchdEnvironment() = %+v", values)
	}
}
