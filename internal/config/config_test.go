package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadReadsEnvironment(t *testing.T) {
	t.Setenv("CBA_ENVIRONMENT", "test")
	t.Setenv("CBA_PORT", "9090")
	t.Setenv("CBA_SHARED_SECRET", strings.Repeat("a", minimumSharedSecretBytes))
	t.Setenv("CBA_GITHUB_ACCESS_FILE", "/tmp/github-access.json")
	t.Setenv("CBA_READ_TIMEOUT", "3")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Environment != "test" || cfg.Port != "9090" {
		t.Fatalf("Load() = %+v, want configured values", cfg)
	}
	if cfg.GitHubAccessFile != "/tmp/github-access.json" {
		t.Fatalf("GitHubAccessFile = %q, want configured path", cfg.GitHubAccessFile)
	}
	if cfg.ReadTimeout != 3*time.Second {
		t.Fatalf("ReadTimeout = %s, want 3s", cfg.ReadTimeout)
	}
}

func TestValidateRejectsWeakSharedSecret(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Port:             "8080",
		SharedSecret:     "short",
		GitHubAccessFile: "github-access.json",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want weak token error")
	}
}

func TestDurationEnvFallsBackForInvalidValue(t *testing.T) {
	t.Setenv("CBA_BAD_DURATION", "bad")
	if got := durationEnv("CBA_BAD_DURATION", 7*time.Second); got != 7*time.Second {
		t.Fatalf("durationEnv() = %s, want fallback", got)
	}
}
