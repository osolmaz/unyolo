package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/profile"
)

func TestDeploymentFlagParsing(t *testing.T) {
	root := t.TempDir()
	state := t.TempDir()
	args := []string{"--profile", root, "--root", root, "--state-dir", state, "--development", "--json"}
	values, err := parseDeploymentFlags("verify", args, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if values.profile != root || !values.development || !values.jsonOutput {
		t.Fatalf("values = %#v", values)
	}
	for _, invalid := range [][]string{
		{}, {"--profile", "relative"}, {"--profile", root, "extra"}, {"--profile", root, "--development"},
	} {
		if _, err := parseDeploymentFlags("verify", invalid, &bytes.Buffer{}); err == nil {
			t.Fatalf("arguments were accepted: %v", invalid)
		}
	}
}

func TestPlanAndApplyFlagParsing(t *testing.T) {
	root := t.TempDir()
	state := t.TempDir()
	common := []string{"--profile", root, "--root", root, "--state-dir", state, "--development"}
	values, output, err := parsePlanFlags(append(append([]string{}, common...), "--output", "/tmp/plan.json"), &bytes.Buffer{})
	if err != nil || output != "/tmp/plan.json" || values.profile != root {
		t.Fatalf("plan = %#v, %q, %v", values, output, err)
	}
	apply := append(append([]string{}, common...), "--expect-plan", "sha256:"+strings.Repeat("a", 64), "--secret-file", "token=/tmp/token")
	_, expected, secrets, err := parseApplyFlags(apply, &bytes.Buffer{})
	if err != nil || expected == "" || len(secrets) != 1 || secrets[0].Name != "token" {
		t.Fatalf("apply = %q, %#v, %v", expected, secrets, err)
	}
	for _, invalid := range [][]string{
		common,
		append(append([]string{}, common...), "--expect-plan", "value", "extra"),
		append(append([]string{}, common...), "--expect-plan", "value", "--secret-file", "invalid"),
		append(append([]string{}, common...), "--expect-plan", "value", "--secret-file", "token=/tmp/a", "--secret-file", "token=/tmp/b"),
	} {
		if _, _, _, err := parseApplyFlags(invalid, &bytes.Buffer{}); err == nil {
			t.Fatalf("apply arguments were accepted: %v", invalid)
		}
	}
}

func TestDeploymentFormattingHelpers(t *testing.T) {
	var output bytes.Buffer
	value := struct {
		Name string `json:"name"`
	}{Name: "host"}
	if err := writeDeploymentResult(&output, true, value, "ignored"); err != nil || !strings.Contains(output.String(), `"name": "host"`) {
		t.Fatalf("JSON output = %q, %v", output.String(), err)
	}
	output.Reset()
	if err := writeDeploymentResult(&output, false, value, "plain"); err != nil || output.String() != "plain" {
		t.Fatalf("text output = %q, %v", output.String(), err)
	}
	snapshot := profile.Snapshot{Deployment: profile.Deployment{Components: []profile.Component{{ID: "github"}, {ID: "sudo"}}}}
	if got := strings.Join(componentIDs(snapshot), ","); got != "github,sudo" {
		t.Fatalf("components = %q", got)
	}
}

func TestSecretFlags(t *testing.T) {
	var values secretFlags
	if values.String() != "" {
		t.Fatal("secret flags must not render values")
	}
	for _, invalid := range []string{"", "name", "=path", "name="} {
		if err := values.Set(invalid); err == nil {
			t.Fatalf("secret binding %q was accepted", invalid)
		}
	}
	if err := values.Set("name=/tmp/value"); err != nil {
		t.Fatal(err)
	}
}
