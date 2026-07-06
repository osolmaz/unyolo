// Package config loads broker configuration from the environment.
//
// Secrets come only from environment variables (or the secrets file they
// point at), never from files an agent could reach through the broker.
// Loading fails closed: any invalid value aborts startup with a specific
// error, and no secret value is ever included in an error message.
package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// MinSecretBytes is the minimum accepted client secret length.
const MinSecretBytes = 32

// Defaults for optional settings.
const (
	DefaultBindAddr     = "127.0.0.1"
	DefaultPort         = 8080
	DefaultScopeFile    = "scope.json"
	DefaultStateDir     = "./state"
	DefaultMaxPackBytes = 25 * 1024 * 1024
	DefaultHFTimeout    = 120 * time.Second

	canonicalEnvPrefix = "HF_BROKER_"
	legacyEnvPrefix    = "BROKER_"
)

// Client is one named broker client and its shared secret.
type Client struct {
	Name   string
	Secret string
}

// Config is the validated broker configuration.
type Config struct {
	HFToken          string
	Clients          []Client
	BindAddr         string
	Port             int
	ScopeFile        string
	StateDir         string
	MaxPackBytes     int64
	HFTimeout        time.Duration
	TelegramBotToken string
	TelegramChatID   int64
}

// Load reads and validates configuration from getenv (normally
// os.Getenv). It reads the secrets file, if configured, from disk.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		HFToken:   brokerEnv(getenv, "HF_TOKEN"),
		BindAddr:  stringOr(brokerEnv(getenv, "BIND_ADDR"), DefaultBindAddr),
		ScopeFile: stringOr(brokerEnv(getenv, "SCOPE_FILE"), DefaultScopeFile),
		StateDir:  stringOr(brokerEnv(getenv, "STATE_DIR"), DefaultStateDir),
	}
	if cfg.HFToken == "" {
		return Config{}, fmt.Errorf("%s is required", brokerEnvName("HF_TOKEN"))
	}
	var err error
	if cfg.Clients, err = loadClients(getenv); err != nil {
		return Config{}, err
	}
	if err := loadNumeric(getenv, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, loadTelegram(getenv, &cfg)
}

func loadNumeric(getenv func(string) string, cfg *Config) error {
	port, err := intOr(brokerEnv(getenv, "PORT"), DefaultPort)
	if err != nil {
		return fmt.Errorf("%s: %w", brokerEnvName("PORT"), err)
	}
	maxPack, err := intOr(brokerEnv(getenv, "MAX_PACK_BYTES"), DefaultMaxPackBytes)
	if err != nil {
		return fmt.Errorf("%s: %w", brokerEnvName("MAX_PACK_BYTES"), err)
	}
	timeoutSeconds, err := intOr(brokerEnv(getenv, "HF_TIMEOUT"), 0)
	if err != nil {
		return fmt.Errorf("%s: %w", brokerEnvName("HF_TIMEOUT"), err)
	}
	cfg.Port = port
	cfg.MaxPackBytes = int64(maxPack)
	cfg.HFTimeout = DefaultHFTimeout
	if timeoutSeconds > 0 {
		cfg.HFTimeout = time.Duration(timeoutSeconds) * time.Second
	}
	return nil
}

func loadTelegram(getenv func(string) string, cfg *Config) error {
	cfg.TelegramBotToken = brokerEnv(getenv, "TELEGRAM_BOT_TOKEN")
	rawChatID := brokerEnv(getenv, "TELEGRAM_CHAT_ID")
	if cfg.TelegramBotToken == "" && rawChatID == "" {
		return nil
	}
	if cfg.TelegramBotToken == "" || rawChatID == "" {
		return fmt.Errorf("%s and %s must be set together", brokerEnvName("TELEGRAM_BOT_TOKEN"), brokerEnvName("TELEGRAM_CHAT_ID"))
	}
	chatID, err := strconv.ParseInt(rawChatID, 10, 64)
	if err != nil || chatID == 0 {
		return fmt.Errorf("%s: expected a non-zero integer", brokerEnvName("TELEGRAM_CHAT_ID"))
	}
	cfg.TelegramChatID = chatID
	return nil
}

func loadClients(getenv func(string) string) ([]Client, error) {
	var clients []Client
	if shared := brokerEnv(getenv, "SHARED_SECRET"); shared != "" {
		clients = append(clients, Client{Name: "default", Secret: shared})
	}
	if path := brokerEnv(getenv, "SECRETS_FILE"); path != "" {
		fromFile, err := parseSecretsFile(path)
		if err != nil {
			return nil, err
		}
		clients = append(clients, fromFile...)
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("%s or %s is required", brokerEnvName("SHARED_SECRET"), brokerEnvName("SECRETS_FILE"))
	}
	return validateClients(clients)
}

func validateClients(clients []Client) ([]Client, error) {
	seen := make(map[string]bool, len(clients))
	seenSecrets := make(map[[32]byte]string, len(clients))
	for _, client := range clients {
		if seen[client.Name] {
			return nil, fmt.Errorf("duplicate client name %q", client.Name)
		}
		seen[client.Name] = true
		if len(client.Secret) < MinSecretBytes {
			return nil, fmt.Errorf("secret for client %q is shorter than %d bytes", client.Name, MinSecretBytes)
		}
		secretHash := sha256.Sum256([]byte(client.Secret))
		if previousName, ok := seenSecrets[secretHash]; ok {
			return nil, fmt.Errorf("duplicate client secret for %q and %q", previousName, client.Name)
		}
		seenSecrets[secretHash] = client.Name
	}
	return clients, nil
}

// parseSecretsFile reads `name = secret` lines. Blank lines and lines
// starting with # are ignored.
func parseSecretsFile(path string) ([]Client, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path from the environment.
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", brokerEnvName("SECRETS_FILE"), err)
	}
	var clients []Client
	for lineNumber, line := range strings.Split(string(data), "\n") {
		client, ok, err := parseSecretLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", brokerEnvName("SECRETS_FILE"), lineNumber+1, err)
		}
		if !ok {
			continue
		}
		clients = append(clients, client)
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("%s contains no clients", brokerEnvName("SECRETS_FILE"))
	}
	return clients, nil
}

func brokerEnv(getenv func(string) string, suffix string) string {
	if value := getenv(brokerEnvName(suffix)); value != "" {
		return value
	}
	return getenv(legacyEnvPrefix + suffix)
}

func brokerEnvName(suffix string) string {
	return canonicalEnvPrefix + suffix
}

func parseSecretLine(line string) (Client, bool, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return Client{}, false, nil
	}
	name, secret, found := strings.Cut(trimmed, "=")
	name = strings.TrimSpace(name)
	secret = strings.TrimSpace(secret)
	if !found || name == "" || secret == "" {
		return Client{}, false, errors.New("expected `name = secret`")
	}
	return Client{Name: name, Secret: secret}, true, nil
}

func stringOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func intOr(value string, fallback int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("expected a positive integer, got %q", value)
	}
	return parsed, nil
}
