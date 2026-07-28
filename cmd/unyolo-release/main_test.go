package main

import (
	"strings"
	"testing"
)

func TestExtraCommands(t *testing.T) {
	commands := extraCommands{}
	if err := commands.Set("helper=./cmd/helper"); err != nil {
		t.Fatal(err)
	}
	if got := commands.String(); got != "helper=./cmd/helper" {
		t.Fatalf("String() = %q", got)
	}
	if err := commands.Set("helper=./cmd/other"); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate Set() error = %v", err)
	}
	for _, value := range []string{"missing-separator", "=./cmd/helper", "helper="} {
		if err := (extraCommands{}).Set(value); err == nil {
			t.Fatalf("Set(%q) unexpectedly succeeded", value)
		}
	}
}
