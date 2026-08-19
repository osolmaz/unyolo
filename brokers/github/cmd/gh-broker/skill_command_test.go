package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/schemaregistry"
)

func TestSkillCommandPrintsBundledDocument(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "skills", "gh-broker", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"skill"}, {"--skill"}} {
		var stdout, stderr bytes.Buffer
		if err := runWithArgs(t.Context(), args, &stdout, &stderr); err != nil {
			t.Fatalf("runWithArgs(%v) error = %v", args, err)
		}
		if !bytes.Equal(stdout.Bytes(), want) {
			t.Fatalf("runWithArgs(%v) output does not match skills/gh-broker/SKILL.md", args)
		}
	}
}

func TestSkillPullRequestCreateExampleMatchesRegistry(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", "skills", "gh-broker", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	section := markedSkillSection(t, string(document), "contract-example:pull_request.create")
	target := skillFlagJSON(t, section, "--target-json")
	arguments := skillFlagJSON(t, section, "--arguments-json")
	if err := schemaregistry.ValidateSubmission("pull_request.create", target, arguments); err != nil {
		t.Fatalf("documented pull request example is invalid: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(arguments, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded["input"] == nil {
		t.Fatalf("documented arguments must contain only input: %s", arguments)
	}
	if err := schemaregistry.ValidateSubmission(
		"pull_request.create",
		target,
		json.RawMessage(`{"title":"TITLE","head":"BRANCH","base":"main","body":"BODY"}`),
	); err == nil {
		t.Fatal("superseded flat pull request arguments were accepted")
	}
}

func markedSkillSection(t *testing.T, document, marker string) string {
	t.Helper()
	startMarker := "<!-- " + marker + ":start -->"
	endMarker := "<!-- " + marker + ":end -->"
	if strings.Count(document, startMarker) != 1 || strings.Count(document, endMarker) != 1 {
		t.Fatalf("skill marker %q must occur exactly once", marker)
	}
	start := strings.Index(document, startMarker) + len(startMarker)
	end := strings.Index(document[start:], endMarker)
	if end < 0 {
		t.Fatalf("skill marker %q is not closed", marker)
	}
	return document[start : start+end]
}

func skillFlagJSON(t *testing.T, section, flag string) json.RawMessage {
	t.Helper()
	prefix := flag + " '"
	if strings.Count(section, prefix) != 1 {
		t.Fatalf("skill flag %q must occur exactly once", flag)
	}
	start := strings.Index(section, prefix) + len(prefix)
	end := strings.Index(section[start:], "'")
	if end < 0 {
		t.Fatalf("skill flag %q has no closing quote", flag)
	}
	return json.RawMessage(section[start : start+end])
}
