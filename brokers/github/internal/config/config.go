package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/clientconfig"
)

const minimumSharedSecretBytes = 32

type Config struct {
	Environment               string
	BindAddr                  string
	Port                      string
	ClientID                  string
	SharedSecret              string
	SecretsFile               string
	OperatorID                string
	OperatorSecret            string
	OperatorSecretsFile       string
	OperatorBindAddr          string
	OperatorPort              string
	GitHubToken               string
	GitHubTokenFile           string
	GitHubAppID               string
	GitHubAppIDFile           string
	GitHubAppPrivateKey       []byte
	GitHubAppPrivateKeyFile   string
	GitHubAppClientID         string
	GitHubAppClientIDFile     string
	GitHubAppClientSecret     string
	GitHubAppClientSecretFile string
	GitHubWebhookSecret       string
	GitHubWebhookSecretFile   string
	GitHubAPIBaseURL          string
	GitHubWebBaseURL          string
	ScopeFile                 string
	StateDir                  string
	TelegramBotToken          string
	TelegramBotTokenFile      string
	TelegramChatID            int64
	GitHubHTTPTimeout         time.Duration
	MaxReceivePackBytes       int64
	ReadHeaderTimeout         time.Duration
	ReadTimeout               time.Duration
	WriteTimeout              time.Duration
	IdleTimeout               time.Duration
}

func Load() (Config, error) {
	return LoadFromLookup(os.Getenv)
}

// LoadFromLookup loads configuration from an injected environment lookup.
func LoadFromLookup(getenv func(string) string) (Config, error) {
	cfg := Config{
		Environment:               getEnvFrom(getenv, "local", "GH_BROKER_ENVIRONMENT"),
		BindAddr:                  getEnvFrom(getenv, "127.0.0.1", "GH_BROKER_BIND_ADDR"),
		Port:                      getEnvFrom(getenv, "8080", "GH_BROKER_PORT"),
		ClientID:                  getEnvFrom(getenv, "bob", "GH_BROKER_CLIENT_ID"),
		SharedSecret:              getEnvFrom(getenv, "", "GH_BROKER_SHARED_SECRET"),
		SecretsFile:               getEnvFrom(getenv, "", "GH_BROKER_SECRETS_FILE"),
		OperatorID:                getEnvFrom(getenv, "onur", "GH_BROKER_OPERATOR_ID"),
		OperatorSecret:            getEnvFrom(getenv, "", "GH_BROKER_OPERATOR_SHARED_SECRET"),
		OperatorSecretsFile:       getEnvFrom(getenv, "", "GH_BROKER_OPERATOR_SECRETS_FILE"),
		OperatorBindAddr:          getEnvFrom(getenv, "127.0.0.1", "GH_BROKER_OPERATOR_BIND_ADDR"),
		OperatorPort:              getEnvFrom(getenv, "8082", "GH_BROKER_OPERATOR_PORT"),
		GitHubToken:               getEnvFrom(getenv, "", "GH_BROKER_GITHUB_TOKEN"),
		GitHubTokenFile:           getEnvFrom(getenv, "", "GH_BROKER_GITHUB_TOKEN_FILE"),
		GitHubAppID:               getEnvFrom(getenv, "", "GH_BROKER_GITHUB_APP_ID"),
		GitHubAppIDFile:           getEnvFrom(getenv, "", "GH_BROKER_GITHUB_APP_ID_FILE"),
		GitHubAppPrivateKeyFile:   getEnvFrom(getenv, "", "GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE"),
		GitHubAppClientID:         getEnvFrom(getenv, "", "GH_BROKER_GITHUB_APP_CLIENT_ID"),
		GitHubAppClientIDFile:     getEnvFrom(getenv, "", "GH_BROKER_GITHUB_APP_CLIENT_ID_FILE"),
		GitHubAppClientSecret:     getEnvFrom(getenv, "", "GH_BROKER_GITHUB_APP_CLIENT_SECRET"),
		GitHubAppClientSecretFile: getEnvFrom(getenv, "", "GH_BROKER_GITHUB_APP_CLIENT_SECRET_FILE"),
		GitHubWebhookSecret:       getEnvFrom(getenv, "", "GH_BROKER_GITHUB_WEBHOOK_SECRET"),
		GitHubWebhookSecretFile:   getEnvFrom(getenv, "", "GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE"),
		GitHubAPIBaseURL:          getEnvFrom(getenv, "https://api.github.com/", "GH_BROKER_GITHUB_API_URL"),
		GitHubWebBaseURL:          getEnvFrom(getenv, "https://github.com/", "GH_BROKER_GITHUB_WEB_URL"),
		ScopeFile:                 getEnvFrom(getenv, "scope.json", "GH_BROKER_SCOPE_FILE"),
		StateDir:                  getEnvFrom(getenv, "./state", "GH_BROKER_STATE_DIR"),
		TelegramBotTokenFile:      getEnvFrom(getenv, "", "GH_BROKER_TELEGRAM_BOT_TOKEN_FILE"),
		TelegramChatID:            telegramChatIDEnvFrom(getenv, "GH_BROKER_TELEGRAM_CHAT_ID"),
		GitHubHTTPTimeout:         durationEnvFrom(getenv, 30*time.Second, "GH_BROKER_GITHUB_HTTP_TIMEOUT"),
		MaxReceivePackBytes:       int64EnvFrom(getenv, 25*1024*1024, "GH_BROKER_MAX_RECEIVE_PACK_BYTES"),
		ReadHeaderTimeout:         durationEnvFrom(getenv, 5*time.Second, "GH_BROKER_READ_HEADER_TIMEOUT"),
		ReadTimeout:               durationEnvFrom(getenv, 15*time.Second, "GH_BROKER_READ_TIMEOUT"),
		WriteTimeout:              durationEnvFrom(getenv, 15*time.Second, "GH_BROKER_WRITE_TIMEOUT"),
		IdleTimeout:               durationEnvFrom(getenv, 60*time.Second, "GH_BROKER_IDLE_TIMEOUT"),
	}
	if err := cfg.loadCredentialFiles(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) loadCredentialFiles() error {
	loaders := []func() error{
		c.loadGitHubTokenFile, c.loadGitHubAppFiles, c.loadGitHubAppClientFiles, c.loadGitHubWebhookSecretFile,
		c.loadBrokerSecretFile, c.loadOperatorSecretFile, c.loadTelegramBotTokenFile,
	}
	for _, load := range loaders {
		if err := load(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) loadGitHubAppClientFiles() error {
	if err := loadOptionalSecretFile(&c.GitHubAppClientID, c.GitHubAppClientIDFile, "github app client id file"); err != nil {
		return err
	}
	return loadOptionalSecretFile(&c.GitHubAppClientSecret, c.GitHubAppClientSecretFile, "github app client secret file")
}

func (c *Config) loadTelegramBotTokenFile() error {
	return loadOptionalSecretFile(&c.TelegramBotToken, c.TelegramBotTokenFile, "telegram bot token file")
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
	return loadNamedSecret(&c.SharedSecret, c.SecretsFile, c.ClientID, "broker")
}

func (c *Config) loadOperatorSecretFile() error {
	return loadNamedSecret(&c.OperatorSecret, c.OperatorSecretsFile, c.OperatorID, "operator")
}

func loadNamedSecret(target *string, path string, identity string, label string) error {
	if *target != "" || path == "" {
		return nil
	}
	secret, err := clientconfig.SecretFromFile(path, identity)
	if err != nil {
		return fmt.Errorf("read %s secret file: %w", label, err)
	}
	*target = secret
	return nil
}

func (c Config) Validate() error {
	return firstError(
		required(c.Port, "GH_BROKER_PORT is required"),
		required(c.BindAddr, "GH_BROKER_BIND_ADDR is required"),
		required(c.ClientID, "GH_BROKER_CLIENT_ID is required"),
		minimumBytes(c.SharedSecret, minimumSharedSecretBytes, "GH_BROKER_SHARED_SECRET"),
		operatorConfig(c),
		githubCredential(c),
		required(c.ScopeFile, "GH_BROKER_SCOPE_FILE is required"),
		required(c.StateDir, "GH_BROKER_STATE_DIR is required"),
		telegramPair(c.TelegramBotToken, c.TelegramChatID),
		positiveDuration(c.GitHubHTTPTimeout, "GH_BROKER_GITHUB_HTTP_TIMEOUT must be positive"),
		positiveInt64(c.MaxReceivePackBytes, "GH_BROKER_MAX_RECEIVE_PACK_BYTES must be positive"),
	)
}

func operatorConfig(c Config) error {
	if c.OperatorSecret == "" {
		return nil
	}
	return firstError(operatorCredentials(c), operatorListener(c))
}

func operatorCredentials(c Config) error {
	if err := clientconfig.ValidateClientName(c.OperatorID); err != nil {
		return fmt.Errorf("GH_BROKER_OPERATOR_ID: %w", err)
	}
	if err := minimumBytes(c.OperatorSecret, minimumSharedSecretBytes, "GH_BROKER_OPERATOR_SHARED_SECRET"); err != nil {
		return err
	}
	if c.OperatorSecret == c.SharedSecret {
		return errors.New("operator secret must differ from the client secret")
	}
	return nil
}

func operatorListener(c Config) error {
	return firstError(operatorBindAddress(c.OperatorBindAddr), operatorPorts(c.OperatorPort, c.Port))
}

func operatorBindAddress(address string) error {
	if net.ParseIP(address) == nil && address != "localhost" {
		return errors.New("GH_BROKER_OPERATOR_BIND_ADDR must be an IP address or localhost")
	}
	return nil
}

func operatorPorts(operatorPort string, agentPort string) error {
	port, err := parsePort(operatorPort, "GH_BROKER_OPERATOR_PORT")
	if err != nil {
		return err
	}
	agent, err := parsePort(agentPort, "GH_BROKER_PORT")
	if err != nil {
		return err
	}
	if port == agent {
		return errors.New("operator and agent listeners must use different ports")
	}
	return nil
}

func parsePort(value string, name string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s must be between 1 and 65535", name)
	}
	return port, nil
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
		return developmentCredential(c)
	}
	if strings.TrimSpace(c.GitHubAppID) != "" && len(c.GitHubAppPrivateKey) > 0 {
		return appCredential(c)
	}
	return errors.New("GH_BROKER_GITHUB_TOKEN_FILE or GitHub App credential files are required")
}

func developmentCredential(c Config) error {
	if strings.TrimSpace(c.GitHubTokenFile) == "" {
		return errors.New("development GitHub token must be loaded from GH_BROKER_GITHUB_TOKEN_FILE")
	}
	if strings.TrimSpace(c.GitHubAppID) != "" || len(c.GitHubAppPrivateKey) > 0 {
		return errors.New("development GitHub token and GitHub App credentials are mutually exclusive")
	}
	return nil
}

func appCredential(c Config) error {
	if strings.TrimSpace(c.GitHubWebhookSecret) == "" {
		return errors.New("GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE is required with GitHub App credentials")
	}
	if (strings.TrimSpace(c.GitHubAppClientID) == "") != (strings.TrimSpace(c.GitHubAppClientSecret) == "") {
		return errors.New("GitHub App client id and client secret must be configured together")
	}
	if c.GitHubAppClientSecret != "" && c.GitHubAppClientSecretFile == "" {
		return errors.New("GitHub App client secret must be loaded from GH_BROKER_GITHUB_APP_CLIENT_SECRET_FILE")
	}
	return firstError(required(c.GitHubAPIBaseURL, "GH_BROKER_GITHUB_API_URL is required"), required(c.GitHubWebBaseURL, "GH_BROKER_GITHUB_WEB_URL is required"))
}

func telegramPair(token string, chatID int64) error {
	if token == "" && chatID == 0 {
		return nil
	}
	if token == "" || chatID == 0 {
		return errors.New("a Telegram bot token and GH_BROKER_TELEGRAM_CHAT_ID must be set together")
	}
	return nil
}

func getEnvFrom(getenv func(string) string, fallback string, keys ...string) string {
	for _, key := range keys {
		if value := getenv(key); value != "" {
			return value
		}
	}
	return fallback
}

func durationEnv(fallback time.Duration, keys ...string) time.Duration {
	return durationEnvFrom(os.Getenv, fallback, keys...)
}

func durationEnvFrom(getenv func(string) string, fallback time.Duration, keys ...string) time.Duration {
	value := getEnvFrom(getenv, "", keys...)
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
	return int64EnvFrom(os.Getenv, fallback, keys...)
}

func int64EnvFrom(getenv func(string) string, fallback int64, keys ...string) int64 {
	value := getEnvFrom(getenv, "", keys...)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func telegramChatIDEnvFrom(getenv func(string) string, key string) int64 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(getenv(key)), 10, 64)
	if err != nil || parsed == 0 {
		return 0
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
