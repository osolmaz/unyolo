package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadReadsEnvironment(t *testing.T) {
	t.Setenv("GH_BROKER_ENVIRONMENT", "test")
	t.Setenv("GH_BROKER_BIND_ADDR", "127.0.0.2")
	t.Setenv("GH_BROKER_PORT", "9090")
	t.Setenv("GH_BROKER_CLIENT_ID", "bob")
	t.Setenv("GH_BROKER_SHARED_SECRET", strings.Repeat("a", minimumSharedSecretBytes))
	t.Setenv("GH_BROKER_GITHUB_TOKEN", "github-token")
	t.Setenv("GH_BROKER_SCOPE_FILE", "/tmp/scope.json")
	t.Setenv("GH_BROKER_GITHUB_HTTP_TIMEOUT", "11")
	t.Setenv("GH_BROKER_MAX_RECEIVE_PACK_BYTES", "12345")
	t.Setenv("GH_BROKER_READ_TIMEOUT", "3")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Environment != "test" || cfg.BindAddr != "127.0.0.2" || cfg.Port != "9090" {
		t.Fatalf("Load() = %+v, want configured values", cfg)
	}
	if cfg.ClientID != "bob" {
		t.Fatalf("ClientID = %q, want bob", cfg.ClientID)
	}
	if cfg.ScopeFile != "/tmp/scope.json" {
		t.Fatalf("ScopeFile = %q, want configured path", cfg.ScopeFile)
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

func TestLoadSupportsLegacyCBAEnvironmentFallback(t *testing.T) {
	t.Setenv("CBA_BIND_ADDR", "127.0.0.3")
	t.Setenv("CBA_PORT", "8081")
	t.Setenv("CBA_SHARED_SECRET", strings.Repeat("b", minimumSharedSecretBytes))
	t.Setenv("CBA_GITHUB_TOKEN", "github-token")
	t.Setenv("CBA_GITHUB_ACCESS_FILE", "/tmp/legacy-scope.json")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.BindAddr != "127.0.0.3" || cfg.ScopeFile != "/tmp/legacy-scope.json" || cfg.ClientID != "bob" {
		t.Fatalf("Load() = %+v, want legacy fallback values", cfg)
	}
}

func TestLoadReadsGitHubTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "github-token")
	if err := os.WriteFile(path, []byte(" token-from-file\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv("GH_BROKER_SHARED_SECRET", strings.Repeat("a", minimumSharedSecretBytes))
	t.Setenv("GH_BROKER_GITHUB_TOKEN_FILE", path)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.GitHubToken != "token-from-file" {
		t.Fatalf("GitHubToken = %q, want token-from-file", cfg.GitHubToken)
	}
}

func TestValidateRejectsWeakSharedSecret(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Port:                "8080",
		BindAddr:            "127.0.0.1",
		ClientID:            "bob",
		SharedSecret:        "short",
		GitHubToken:         "github-token",
		ScopeFile:           "scope.json",
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
		ClientID:            "bob",
		SharedSecret:        strings.Repeat("a", minimumSharedSecretBytes),
		ScopeFile:           "scope.json",
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
			ClientID:            "bob",
			SharedSecret:        strings.Repeat("a", minimumSharedSecretBytes),
			GitHubToken:         "github-token",
			ScopeFile:           "scope.json",
			GitHubHTTPTimeout:   time.Second,
			MaxReceivePackBytes: 1,
		},
		"empty client id": {
			Port:                "8080",
			BindAddr:            "127.0.0.1",
			SharedSecret:        strings.Repeat("a", minimumSharedSecretBytes),
			GitHubToken:         "github-token",
			ScopeFile:           "scope.json",
			GitHubHTTPTimeout:   time.Second,
			MaxReceivePackBytes: 1,
		},
		"bad github timeout": {
			Port:                "8080",
			BindAddr:            "127.0.0.1",
			ClientID:            "bob",
			SharedSecret:        strings.Repeat("a", minimumSharedSecretBytes),
			GitHubToken:         "github-token",
			ScopeFile:           "scope.json",
			MaxReceivePackBytes: 1,
		},
		"bad receive pack limit": {
			Port:              "8080",
			BindAddr:          "127.0.0.1",
			ClientID:          "bob",
			SharedSecret:      strings.Repeat("a", minimumSharedSecretBytes),
			GitHubToken:       "github-token",
			ScopeFile:         "scope.json",
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
	t.Setenv("GH_BROKER_BAD_DURATION", "bad")
	if got := durationEnv(7*time.Second, "GH_BROKER_BAD_DURATION"); got != 7*time.Second {
		t.Fatalf("durationEnv() = %s, want fallback", got)
	}
}

func TestInt64EnvFallsBackForInvalidValue(t *testing.T) {
	t.Setenv("GH_BROKER_BAD_INT", "bad")
	if got := int64Env(42, "GH_BROKER_BAD_INT"); got != 42 {
		t.Fatalf("int64Env() = %d, want fallback", got)
	}
}
