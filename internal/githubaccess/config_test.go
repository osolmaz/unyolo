package githubaccess

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileNormalizesManualConfig(t *testing.T) {
	t.Parallel()
	path := writeAccessFile(t, `{
		"owners": [" dutifuldev ", "dutifuldev", "osolmaz"],
		"repositories": [
			{"owner": "openclaw", "name": "openclaw"},
			{"owner": "openclaw", "name": "openclaw"}
		]
	}`)
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if len(cfg.Owners) != 2 || len(cfg.Repositories) != 1 {
		t.Fatalf("LoadFile() = %+v, want deduplicated config", cfg)
	}
	assertAccessRules(t, cfg)
}

func assertAccessRules(t *testing.T, cfg Config) {
	t.Helper()
	checks := map[string]bool{
		"owner-wide repo access": cfg.Allows("dutifuldev", "any-repo"),
		"explicit repo access":   cfg.Allows("openclaw", "openclaw"),
		"denied repo access":     !cfg.Allows("other", "repo"),
	}
	for name, passed := range checks {
		if !passed {
			t.Fatalf("%s check failed for %+v", name, cfg)
		}
	}
}

func TestLoadFileRejectsInvalidConfig(t *testing.T) {
	t.Parallel()
	cases := []string{
		`{}`,
		`{"owners":["bad/owner"]}`,
		`{"repositories":[{"owner":"bad/owner","name":"repo"}]}`,
		`{"repositories":[{"owner":"owner","name":"bad/repo"}]}`,
		`not json`,
	}
	for _, body := range cases {
		if _, err := LoadFile(writeAccessFile(t, body)); err == nil {
			t.Fatalf("LoadFile(%q) error = nil, want validation error", body)
		}
	}
}

func TestLoadFileMissingFile(t *testing.T) {
	t.Parallel()
	_, err := LoadFile(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("LoadFile() error = nil, want missing file error")
	}
}

func writeAccessFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "github-access.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
