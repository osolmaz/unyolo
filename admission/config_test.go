package admission

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseConfigRequiresCompleteValidExactClients(t *testing.T) {
	raw := []byte(`{
  "requests_per_window": 30,
  "window_seconds": 60,
  "client_active": 20,
  "client_pending": 8,
  "global_active": 100,
  "global_executing": 12,
  "clients": {
    "agent-a": {"requests_per_window": 5, "window_seconds": 120, "active": 4, "pending": 2}
  }
}`)
	config, err := ParseConfig(raw, []string{"agent-a", "agent-b"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Default.RequestsPerWindow != 30 || config.Default.Window != time.Minute ||
		config.Clients["agent-a"].Window != 2*time.Minute {
		t.Fatalf("config = %+v", config)
	}
	for name, invalid := range map[string][]byte{
		"unknown client": []byte(`{"requests_per_window":30,"window_seconds":60,"client_active":20,"client_pending":8,"global_active":100,"global_executing":12,"clients":{"other":{"requests_per_window":5,"window_seconds":60,"active":4,"pending":2}}}`),
		"unknown field":  []byte(`{"requests_per_window":30,"window_seconds":60,"client_active":20,"client_pending":8,"global_active":100,"global_executing":12,"extra":true}`),
		"duplicate":      []byte(`{"requests_per_window":30,"requests_per_window":31}`),
		"incomplete":     []byte(`{"requests_per_window":30}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig(invalid, []string{"agent-a"}); err == nil {
				t.Fatal("invalid admission config was accepted")
			}
		})
	}
}

func TestLoadFileDefaultsAndBounds(t *testing.T) {
	config, err := LoadFile("", []string{"agent-a"})
	if err != nil || config.Default != DefaultLimits() {
		t.Fatalf("default config = %+v, %v", config, err)
	}
	if _, err := LoadFile("relative.json", []string{"agent-a"}); err == nil {
		t.Fatal("relative admission config was accepted")
	}
	path := filepath.Join(t.TempDir(), "large.json")
	if err := os.WriteFile(path, make([]byte, maxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path, []string{"agent-a"}); err == nil {
		t.Fatal("oversized admission config was accepted")
	}
}
