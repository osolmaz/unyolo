package envfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndOverlayLookup(t *testing.T) {
	values, err := Parse([]byte("# generated\nBROKER_PATH=/etc/broker/config\nBROKER_PORT=8080\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	lookup := OverlayLookup(values, func(key string) string {
		if key == "BROKER_PORT" {
			return "9090"
		}
		return ""
	})
	if lookup("BROKER_PATH") != "/etc/broker/config" || lookup("BROKER_PORT") != "9090" || lookup("MISSING") != "" {
		t.Fatalf("overlay values = path %q port %q missing %q", lookup("BROKER_PATH"), lookup("BROKER_PORT"), lookup("MISSING"))
	}
}

func TestParseRejectsMalformedInputWithoutReturningValues(t *testing.T) {
	for _, data := range []string{
		"MISSING",
		"1BAD=value",
		"BAD-KEY=value",
		"DUP=one\nDUP=two",
		"VALUE=bad\x00value",
		"VALUE=bad\x1bvalue",
		"VALUE='quoted'",
		" VALUE=spaced",
	} {
		if values, err := Parse([]byte(data)); err == nil || values != nil {
			t.Fatalf("Parse(%q) = %v, %v", data, values, err)
		}
	}
}

func TestLoadBoundsInput(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "env")
	if err := os.WriteFile(valid, []byte("BROKER=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := Load(valid)
	if err != nil || values["BROKER"] != "value" {
		t.Fatalf("Load(valid) = %v, %v", values, err)
	}
	oversized := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversized, []byte("BROKER="+strings.Repeat("x", maxEnvironmentFileBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(oversized); err == nil {
		t.Fatal("Load(oversized) error = nil")
	}
}
