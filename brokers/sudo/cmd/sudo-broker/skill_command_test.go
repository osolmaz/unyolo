package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSkillCommandPrintsBundledDocument(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "skills", "sudo-broker", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"skill"}, {"--skill"}} {
		var stdout, stderr bytes.Buffer
		if err := run(t.Context(), args, &stdout, &stderr); err != nil {
			t.Fatalf("run(%v) error = %v", args, err)
		}
		if !bytes.Equal(stdout.Bytes(), want) {
			t.Fatalf("run(%v) output does not match skills/sudo-broker/SKILL.md", args)
		}
	}
}
