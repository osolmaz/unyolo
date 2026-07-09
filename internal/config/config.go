package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/clientconfig"
)

const minimumSharedSecretBytes = 32

type Config struct {
	Environment             string
	BindAddr                string
	Port                    string
	ClientID                string
	SharedSecret            string
	SecretsFile             string
	GitHubToken             string
	GitHubTokenFile         string
	GitHubAppID             string
	GitHubAppIDFile         string
	GitHubAppPrivateKey     []byte
	GitHubAppPrivateKeyFile string
	GitHubWebhookSecret     string
	GitHubWebhookSecretFile string
	ScopeFile               string
	StateDir                string
	TelegramBotToken        string
	TelegramChatID          int64
	GitHubHTTPTimeout       time.Duration
	MaxReceivePackBytes     int64
	ReadHeaderTimeout       time.Duration
	ReadTimeout             time.Duration
	WriteTimeout            time.Duration
	IdleTimeout             time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Environment:             getEnv("local", "GH_BROKER_ENVIRONMENT", "CBA_ENVIRONMENT"),
		BindAddr:                getEnv("127.0.0.1", "GH_BROKER_BIND_ADDR", "CBA_BIND_ADDR"),
		Port:                    getEnv("8080", "GH_BROKER_PORT", "CBA_PORT"),
		ClientID:                getEnv("bob", "GH_BROKER_CLIENT_ID", "CBA_CLIENT_ID"),
		SharedSecret:            getEnv("", "GH_BROKER_SHARED_SECRET", "CBA_SHARED_SECRET"),
		SecretsFile:             getEnv("", "GH_BROKER_SECRETS_FILE"),
		GitHubToken:             getEnv("", "GH_BROKER_GITHUB_TOKEN", "CBA_GITHUB_TOKEN"),
		GitHubTokenFile:         getEnv("", "GH_BROKER_GITHUB_TOKEN_FILE", "CBA_GITHUB_TOKEN_FILE"),
		GitHubAppID:             getEnv("", "GH_BROKER_GITHUB_APP_ID"),
		GitHubAppIDFile:         getEnv("", "GH_BROKER_GITHUB_APP_ID_FILE"),
		GitHubAppPrivateKeyFile: getEnv("", "GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE"),
		GitHubWebhookSecret:     getEnv("", "GH_BROKER_GITHUB_WEBHOOK_SECRET"),
		GitHubWebhookSecretFile: getEnv("", "GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE"),
		ScopeFile:               getEnv("scope.json", "GH_BROKER_SCOPE_FILE", "CBA_GITHUB_ACCESS_FILE"),
		StateDir:                getEnv("./state", "GH_BROKER_STATE_DIR", "CBA_STATE_DIR"),
		TelegramBotToken:        getEnv("", "GH_BROKER_TELEGRAM_BOT_TOKEN"),
		TelegramChatID:          int64Env(0, "GH_BROKER_TELEGRAM_CHAT_ID"),
		GitHubHTTPTimeout:       durationEnv(30*time.Second, "GH_BROKER_GITHUB_HTTP_TIMEOUT", "CBA_GITHUB_HTTP_TIMEOUT"),
		MaxReceivePackBytes:     int64Env(25*1024*1024, "GH_BROKER_MAX_RECEIVE_PACK_BYTES", "CBA_MAX_RECEIVE_PACK_BYTES"),
		ReadHeaderTimeout:       durationEnv(5*time.Second, "GH_BROKER_READ_HEADER_TIMEOUT", "CBA_READ_HEADER_TIMEOUT"),
		ReadTimeout:             durationEnv(15*time.Second, "GH_BROKER_READ_TIMEOUT", "CBA_READ_TIMEOUT"),
		WriteTimeout:            durationEnv(15*time.Second, "GH_BROKER_WRITE_TIMEOUT", "CBA_WRITE_TIMEOUT"),
		IdleTimeout:             durationEnv(60*time.Second, "GH_BROKER_IDLE_TIMEOUT", "CBA_IDLE_TIMEOUT"),
	}
	if err := cfg.loadGitHubTokenFile(); err != nil {
		return Config{}, err
	}
	if err := cfg.loadGitHubAppFiles(); err != nil {
		return Config{}, err
	}
	if err := cfg.loadGitHubWebhookSecretFile(); err != nil {
		return Config{}, err
	}
	if err := cfg.loadBrokerSecretFile(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) loadGitHubTokenFile() error {
	return loadOptionalSecretFile(&c.GitHubToken, c.GitHubTokenFile, "github token file")
}

func (c *Config) loadGitHubAppFiles() error {
	if err := c.loadGitHubAppIDFile(); err != nil {
		return err
	}
	return c.loadGitHubAppPrivateKeyFile()
}

func (c *Config) loadGitHubAppIDFile() error {
	return loadOptionalSecretFile(&c.GitHubAppID, c.GitHubAppIDFile, "github app id file")
}

func loadOptionalSecretFile(target *string, path string, label string) error {
	if *target != "" || path == "" {
		return nil
	}
	value, err := readSecretFile(path, label)
	if err != nil {
		return err
	}
	*target = value
	return nil
}

func (c *Config) loadGitHubAppPrivateKeyFile() error {
	if len(c.GitHubAppPrivateKey) > 0 || c.GitHubAppPrivateKeyFile == "" {
		return nil
	}
	data, err := os.ReadFile(c.GitHubAppPrivateKeyFile) // #nosec G304 -- operator configured secret path.
	if err != nil {
		return fmt.Errorf("read github app private key file: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return errors.New("github app private key file is empty")
	}
	c.GitHubAppPrivateKey = data
	return nil
}

func (c *Config) loadGitHubWebhookSecretFile() error {
	return loadOptionalSecretFile(&c.GitHubWebhookSecret, c.GitHubWebhookSecretFile, "github webhook secret file")
}

func (c *Config) loadBrokerSecretFile() error {
	if c.SharedSecret != "" || c.SecretsFile == "" {
		return nil
	}
	secret, err := clientconfig.SecretFromFile(c.SecretsFile, c.ClientID)
	if err != nil {
		return fmt.Errorf("read broker secret file: %w", err)
	}
	c.SharedSecret = secret
	return nil
}

func (c Config) Validate() error {
	return firstError(
		required(c.Port, "GH_BROKER_PORT is required"),
		required(c.BindAddr, "GH_BROKER_BIND_ADDR is required"),
		required(c.ClientID, "GH_BROKER_CLIENT_ID is required"),
		minimumBytes(c.SharedSecret, minimumSharedSecretBytes, "GH_BROKER_SHARED_SECRET"),
		githubCredential(c),
		required(c.ScopeFile, "GH_BROKER_SCOPE_FILE is required"),
		required(c.StateDir, "GH_BROKER_STATE_DIR is required"),
		telegramPair(c.TelegramBotToken, c.TelegramChatID),
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

func githubCredential(c Config) error {
	if strings.TrimSpace(c.GitHubToken) != "" {
		return nil
	}
	if strings.TrimSpace(c.GitHubAppID) != "" && len(c.GitHubAppPrivateKey) > 0 {
		return nil
	}
	return errors.New("GH_BROKER_GITHUB_TOKEN_FILE or GitHub App credential files are required")
}

func telegramPair(token string, chatID int64) error {
	if token == "" && chatID == 0 {
		return nil
	}
	if token == "" || chatID == 0 {
		return errors.New("GH_BROKER_TELEGRAM_BOT_TOKEN and GH_BROKER_TELEGRAM_CHAT_ID must be set together")
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

func readSecretFile(path string, label string) (string, error) {
	// #nosec G304 -- secret file path is operator-provided process configuration.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("%s is empty", label)
	}
	return secret, nil
}
