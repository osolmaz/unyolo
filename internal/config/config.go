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
	SharedSecret        string
	GitHubToken         string
	GitHubAccessFile    string
	GitHubHTTPTimeout   time.Duration
	MaxReceivePackBytes int64
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Environment:         getEnv("CBA_ENVIRONMENT", "local"),
		BindAddr:            getEnv("CBA_BIND_ADDR", "127.0.0.1"),
		Port:                getEnv("CBA_PORT", "8080"),
		SharedSecret:        os.Getenv("CBA_SHARED_SECRET"),
		GitHubToken:         os.Getenv("CBA_GITHUB_TOKEN"),
		GitHubAccessFile:    getEnv("CBA_GITHUB_ACCESS_FILE", "github-access.json"),
		GitHubHTTPTimeout:   durationEnv("CBA_GITHUB_HTTP_TIMEOUT", 30*time.Second),
		MaxReceivePackBytes: int64Env("CBA_MAX_RECEIVE_PACK_BYTES", 25*1024*1024),
		ReadHeaderTimeout:   durationEnv("CBA_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:         durationEnv("CBA_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:        durationEnv("CBA_WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:         durationEnv("CBA_IDLE_TIMEOUT", 60*time.Second),
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	return firstError(
		required(c.Port, "CBA_PORT is required"),
		required(c.BindAddr, "CBA_BIND_ADDR is required"),
		minimumBytes(c.SharedSecret, minimumSharedSecretBytes, "CBA_SHARED_SECRET"),
		required(c.GitHubToken, "CBA_GITHUB_TOKEN is required"),
		required(c.GitHubAccessFile, "CBA_GITHUB_ACCESS_FILE is required"),
		positiveDuration(c.GitHubHTTPTimeout, "CBA_GITHUB_HTTP_TIMEOUT must be positive"),
		positiveInt64(c.MaxReceivePackBytes, "CBA_MAX_RECEIVE_PACK_BYTES must be positive"),
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

func getEnv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func int64Env(key string, fallback int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 || parsed > math.MaxInt32 {
		return fallback
	}
	return parsed
}
