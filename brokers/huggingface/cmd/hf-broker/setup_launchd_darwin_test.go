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
	plan := systemdSetupPlan(setupSystemdOptions{XetPython: "/opt/hf-broker/xet/bin/python"})
	values := hfLaunchdEnvironment(plan)
	if values["HF_BROKER_AGENT_ENDPOINT"] != "activation://agent" || values["HF_BROKER_OPERATOR_ENDPOINT"] != "activation://operator" ||
		values["HF_BROKER_XET_PYTHON"] != "/opt/hf-broker/xet/bin/python" {
		t.Fatalf("hfLaunchdEnvironment() = %+v", values)
	}
}
