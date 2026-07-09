package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const minimumSharedSecretBytes = 32

type Config struct {
	Environment         string
	BindAddr            string
	Port                string
	ClientID            string
	SharedSecret        string
	GitHubToken         string
	GitHubTokenFile     string
	ScopeFile           string
	GitHubHTTPTimeout   time.Duration
	MaxReceivePackBytes int64
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Environment:         getEnv("local", "GH_BROKER_ENVIRONMENT", "CBA_ENVIRONMENT"),
		BindAddr:            getEnv("127.0.0.1", "GH_BROKER_BIND_ADDR", "CBA_BIND_ADDR"),
		Port:                getEnv("8080", "GH_BROKER_PORT", "CBA_PORT"),
		ClientID:            getEnv("bob", "GH_BROKER_CLIENT_ID", "CBA_CLIENT_ID"),
		SharedSecret:        getEnv("", "GH_BROKER_SHARED_SECRET", "CBA_SHARED_SECRET"),
		GitHubToken:         getEnv("", "GH_BROKER_GITHUB_TOKEN", "CBA_GITHUB_TOKEN"),
		GitHubTokenFile:     getEnv("", "GH_BROKER_GITHUB_TOKEN_FILE", "CBA_GITHUB_TOKEN_FILE"),
		ScopeFile:           getEnv("scope.json", "GH_BROKER_SCOPE_FILE", "CBA_GITHUB_ACCESS_FILE"),
		GitHubHTTPTimeout:   durationEnv(30*time.Second, "GH_BROKER_GITHUB_HTTP_TIMEOUT", "CBA_GITHUB_HTTP_TIMEOUT"),
		MaxReceivePackBytes: int64Env(25*1024*1024, "GH_BROKER_MAX_RECEIVE_PACK_BYTES", "CBA_MAX_RECEIVE_PACK_BYTES"),
		ReadHeaderTimeout:   durationEnv(5*time.Second, "GH_BROKER_READ_HEADER_TIMEOUT", "CBA_READ_HEADER_TIMEOUT"),
		ReadTimeout:         durationEnv(15*time.Second, "GH_BROKER_READ_TIMEOUT", "CBA_READ_TIMEOUT"),
		WriteTimeout:        durationEnv(15*time.Second, "GH_BROKER_WRITE_TIMEOUT", "CBA_WRITE_TIMEOUT"),
		IdleTimeout:         durationEnv(60*time.Second, "GH_BROKER_IDLE_TIMEOUT", "CBA_IDLE_TIMEOUT"),
	}
	if cfg.GitHubToken == "" && cfg.GitHubTokenFile != "" {
		token, err := readSecretFile(cfg.GitHubTokenFile)
		if err != nil {
			return Config{}, err
		}
		cfg.GitHubToken = token
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	return firstError(
		required(c.Port, "GH_BROKER_PORT is required"),
		required(c.BindAddr, "GH_BROKER_BIND_ADDR is required"),
		required(c.ClientID, "GH_BROKER_CLIENT_ID is required"),
		minimumBytes(c.SharedSecret, minimumSharedSecretBytes, "GH_BROKER_SHARED_SECRET"),
		required(c.GitHubToken, "GH_BROKER_GITHUB_TOKEN or GH_BROKER_GITHUB_TOKEN_FILE is required"),
		required(c.ScopeFile, "GH_BROKER_SCOPE_FILE is required"),
		positiveDuration(c.GitHubHTTPTimeout, "GH_BROKER_GITHUB_HTTP_TIMEOUT must be positive"),
		positiveInt64(c.MaxReceivePackBytes, "GH_BROKER_MAX_RECEIVE_PACK_BYTES must be positive"),
	)
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func required(value string, message string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New(message)
	}
	return nil
}

func minimumBytes(value string, minimum int, name string) error {
	if len([]byte(value)) < minimum {
		return fmt.Errorf("%s must be at least %d bytes", name, minimum)
	}
	return nil
}

func positiveDuration(value time.Duration, message string) error {
	if value <= 0 {
		return errors.New(message)
	}
	return nil
}

func positiveInt64(value int64, message string) error {
	if value <= 0 {
		return errors.New(message)
	}
	return nil
}

func getEnv(fallback string, keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return fallback
}

func durationEnv(fallback time.Duration, keys ...string) time.Duration {
	value := getEnv("", keys...)
	if value == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func int64Env(fallback int64, keys ...string) int64 {
	value := getEnv("", keys...)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 || parsed > math.MaxInt32 {
		return fallback
	}
	return parsed
}

func readSecretFile(path string) (string, error) {
	// #nosec G304 -- secret file path is operator-provided process configuration.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read github token file: %w", err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", errors.New("github token file is empty")
	}
	return secret, nil
}
