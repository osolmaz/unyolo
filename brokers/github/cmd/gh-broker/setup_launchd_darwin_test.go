//go:build darwin

package main

import "testing"

func TestGHLaunchdEnvironment(t *testing.T) {
	plan := systemdSetupPlan(setupSystemdOptions{DevTokenFallback: true})
	values := ghLaunchdEnvironment(plan)
	if values["GH_BROKER_AGENT_ENDPOINT"] != "activation://agent" || values["GH_BROKER_GITHUB_TOKEN_FILE"] != plan.tokenPath {
		t.Fatalf("ghLaunchdEnvironment() = %+v", values)
	}
}
