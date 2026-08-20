package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkillExplainsTerminalOperationStates(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", "skills", "hf-broker", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"`pending`, `approved`",
		"`executing` are not completion",
		"Follow the printed `Next:` wait command",
		"Only `succeeded` means it completed",
		"`failed`, `denied`, `expired`",
		"`canceled` mean it did not complete",
	} {
		if !strings.Contains(string(document), expected) {
			t.Fatalf("skill does not contain %q", expected)
		}
	}
}

func TestSkillCommandPrintsBundledDocument(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "skills", "hf-broker", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	getenv := func(string) string { return "" }
	for _, args := range [][]string{{"skill"}, {"--skill"}} {
		var stdout, stderr bytes.Buffer
		if err := runWithArgs(context.Background(), getenv, &stdout, &stderr, args); err != nil {
			t.Fatalf("runWithArgs(%v) error = %v", args, err)
		}
		if !bytes.Equal(stdout.Bytes(), want) {
			t.Fatalf("runWithArgs(%v) output does not match skills/hf-broker/SKILL.md", args)
		}
	}
}
