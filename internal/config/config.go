package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const minimumAdminTokenBytes = 32

type Config struct {
	Environment       string
	Port              string
	APIPrefix         string
	AdminToken        string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Environment:       getEnv("CBA_ENVIRONMENT", "local"),
		Port:              getEnv("CBA_PORT", "8080"),
		APIPrefix:         getEnv("CBA_API_PREFIX", "/v1"),
		AdminToken:        os.Getenv("CBA_ADMIN_TOKEN"),
		ReadHeaderTimeout: durationEnv("CBA_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       durationEnv("CBA_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      durationEnv("CBA_WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:       durationEnv("CBA_IDLE_TIMEOUT", 60*time.Second),
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Port) == "" {
		return errors.New("CBA_PORT is required")
	}
	if !strings.HasPrefix(c.APIPrefix, "/") {
		return errors.New("CBA_API_PREFIX must start with /")
	}
	if len([]byte(c.AdminToken)) < minimumAdminTokenBytes {
		return fmt.Errorf("CBA_ADMIN_TOKEN must be at least %d bytes", minimumAdminTokenBytes)
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
