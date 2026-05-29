package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadReadsEnvironment(t *testing.T) {
	t.Setenv("CBA_ENVIRONMENT", "test")
	t.Setenv("CBA_BIND_ADDR", "127.0.0.2")
	t.Setenv("CBA_PORT", "9090")
	t.Setenv("CBA_SHARED_SECRET", strings.Repeat("a", minimumSharedSecretBytes))
	t.Setenv("CBA_GITHUB_TOKEN", "github-token")
	t.Setenv("CBA_GITHUB_ACCESS_FILE", "/tmp/github-access.json")
	t.Setenv("CBA_GITHUB_HTTP_TIMEOUT", "11")
	t.Setenv("CBA_MAX_RECEIVE_PACK_BYTES", "12345")
	t.Setenv("CBA_READ_TIMEOUT", "3")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Environment != "test" || cfg.BindAddr != "127.0.0.2" || cfg.Port != "9090" {
		t.Fatalf("Load() = %+v, want configured values", cfg)
	}
	if cfg.GitHubAccessFile != "/tmp/github-access.json" {
		t.Fatalf("GitHubAccessFile = %q, want configured path", cfg.GitHubAccessFile)
	}
	if cfg.ReadTimeout != 3*time.Second {
		t.Fatalf("ReadTimeout = %s, want 3s", cfg.ReadTimeout)
	}
	if cfg.GitHubHTTPTimeout != 11*time.Second {
		t.Fatalf("GitHubHTTPTimeout = %s, want 11s", cfg.GitHubHTTPTimeout)
	}
	if cfg.MaxReceivePackBytes != 12345 {
		t.Fatalf("MaxReceivePackBytes = %d, want 12345", cfg.MaxReceivePackBytes)
	}
}

func TestValidateRejectsWeakSharedSecret(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Port:                "8080",
		BindAddr:            "127.0.0.1",
		SharedSecret:        "short",
		GitHubToken:         "github-token",
		GitHubAccessFile:    "github-access.json",
		GitHubHTTPTimeout:   time.Second,
		MaxReceivePackBytes: 1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want weak token error")
	}
}

func TestValidateRejectsMissingGitHubToken(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Port:                "8080",
		BindAddr:            "127.0.0.1",
		SharedSecret:        strings.Repeat("a", minimumSharedSecretBytes),
		GitHubAccessFile:    "github-access.json",
		GitHubHTTPTimeout:   time.Second,
		MaxReceivePackBytes: 1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want missing GitHub token error")
	}
}

func TestValidateRejectsBadDeploySafetyConfig(t *testing.T) {
	t.Parallel()
	cases := map[string]Config{
		"empty bind address": {
			Port:                "8080",
			SharedSecret:        strings.Repeat("a", minimumSharedSecretBytes),
			GitHubToken:         "github-token",
			GitHubAccessFile:    "github-access.json",
			GitHubHTTPTimeout:   time.Second,
			MaxReceivePackBytes: 1,
		},
		"bad github timeout": {
			Port:                "8080",
			BindAddr:            "127.0.0.1",
			SharedSecret:        strings.Repeat("a", minimumSharedSecretBytes),
			GitHubToken:         "github-token",
			GitHubAccessFile:    "github-access.json",
			MaxReceivePackBytes: 1,
		},
		"bad receive pack limit": {
			Port:              "8080",
			BindAddr:          "127.0.0.1",
			SharedSecret:      strings.Repeat("a", minimumSharedSecretBytes),
			GitHubToken:       "github-token",
			GitHubAccessFile:  "github-access.json",
			GitHubHTTPTimeout: time.Second,
		},
	}
	for name, cfg := range cases {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s Validate() error = nil, want validation error", name)
		}
	}
}

func TestDurationEnvFallsBackForInvalidValue(t *testing.T) {
	t.Setenv("CBA_BAD_DURATION", "bad")
	if got := durationEnv("CBA_BAD_DURATION", 7*time.Second); got != 7*time.Second {
		t.Fatalf("durationEnv() = %s, want fallback", got)
	}
}

func TestInt64EnvFallsBackForInvalidValue(t *testing.T) {
	t.Setenv("CBA_BAD_INT", "bad")
	if got := int64Env("CBA_BAD_INT", 42); got != 42 {
		t.Fatalf("int64Env() = %d, want fallback", got)
	}
}
