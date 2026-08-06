package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
