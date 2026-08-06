package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

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
