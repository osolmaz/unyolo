// Package config loads broker configuration from the environment.
//
// Secrets come from environment variables or operator-configured files,
// never from files an agent could reach through the broker.
// Loading fails closed: any invalid value aborts startup with a specific
// error, and no secret value is ever included in an error message.
package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// MinSecretBytes is the minimum accepted client secret length.
const MinSecretBytes = 32

// Defaults for optional settings.
const (
	DefaultBindAddr          = "127.0.0.1"
	DefaultPort              = 8080
	DefaultOperatorBindAddr  = "127.0.0.1"
	DefaultOperatorPort      = 8081
	DefaultScopeFile         = "scope.json"
	DefaultStateDir          = "./state"
	DefaultMaxPackBytes      = 25 * 1024 * 1024
	DefaultHFTimeout         = 120 * time.Second
	DefaultUpstreamHubURL    = "https://huggingface.co"
	DefaultUpstreamRouterURL = "https://router.huggingface.co"
	maxSecretFileBytes       = 64 * 1024

	canonicalEnvPrefix = "HF_BROKER_"
)

var errSecretFileTooLarge = errors.New("secret file is too large")

// Client is one named broker client and its shared secret.
type Client struct {
	Name   string
	Secret string
}

// Config is the validated broker configuration.
type Config struct {
	HFToken           string
	Clients           []Client
	Operators         []Client
	BindAddr          string
	Port              int
	OperatorBindAddr  string
	OperatorPort      int
	ScopeFile         string
	StateDir          string
	MaxPackBytes      int64
	HFTimeout         time.Duration
	UpstreamHubURL    string
	UpstreamRouterURL string
	TelegramBotToken  string
	TelegramChatID    int64
}

// Load reads and validates configuration from getenv (normally
// os.Getenv). It reads the secrets file, if configured, from disk.
func Load(getenv func(string) string) (Config, error) {
	hfToken, err := loadHFToken(getenv)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		HFToken:           hfToken,
		BindAddr:          stringOr(brokerEnv(getenv, "BIND_ADDR"), DefaultBindAddr),
		OperatorBindAddr:  stringOr(brokerEnv(getenv, "OPERATOR_BIND_ADDR"), DefaultOperatorBindAddr),
		ScopeFile:         stringOr(brokerEnv(getenv, "SCOPE_FILE"), DefaultScopeFile),
		StateDir:          stringOr(brokerEnv(getenv, "STATE_DIR"), DefaultStateDir),
		UpstreamHubURL:    stringOr(brokerEnv(getenv, "UPSTREAM_HUB_URL"), DefaultUpstreamHubURL),
		UpstreamRouterURL: stringOr(brokerEnv(getenv, "UPSTREAM_ROUTER_URL"), DefaultUpstreamRouterURL),
	}
	if cfg.HFToken == "" {
		return Config{}, fmt.Errorf("%s or %s is required", brokerEnvName("HF_TOKEN"), brokerEnvName("HF_TOKEN_FILE"))
	}
	if cfg.Clients, err = loadClients(getenv); err != nil {
		return Config{}, err
	}
	if cfg.Operators, err = loadOperators(getenv, cfg.Clients); err != nil {
		return Config{}, err
	}
	if err := loadNumeric(getenv, &cfg); err != nil {
		return Config{}, err
	}
	if len(cfg.Operators) > 0 && cfg.Port == cfg.OperatorPort {
		return Config{}, errors.New("operator and agent listeners must use different ports")
	}
	return cfg, loadTelegram(getenv, &cfg)
}

func loadHFToken(getenv func(string) string) (string, error) {
	return loadSecretValue(getenv, "HF_TOKEN", "HF_TOKEN_FILE")
}

func secretPathReadFailure(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "file does not exist"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	case errors.Is(err, errSecretFileTooLarge):
		return fmt.Sprintf("file exceeds %d bytes", maxSecretFileBytes)
	default:
		return "failed"
	}
}

func loadNumeric(getenv func(string) string, cfg *Config) error {
	port, operatorPort, err := loadPorts(getenv)
	if err != nil {
		return err
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
	cfg.OperatorPort = operatorPort
	cfg.MaxPackBytes = int64(maxPack)
	cfg.HFTimeout = DefaultHFTimeout
	if timeoutSeconds > 0 {
		cfg.HFTimeout = time.Duration(timeoutSeconds) * time.Second
	}
	return nil
}

func loadPorts(getenv func(string) string) (int, int, error) {
	port, err := intOr(brokerEnv(getenv, "PORT"), DefaultPort)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", brokerEnvName("PORT"), err)
	}
	operatorPort, err := intOr(brokerEnv(getenv, "OPERATOR_PORT"), DefaultOperatorPort)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", brokerEnvName("OPERATOR_PORT"), err)
	}
	if port < 1 || port > 65535 {
		return 0, 0, fmt.Errorf("%s: expected a port between 1 and 65535", brokerEnvName("PORT"))
	}
	if operatorPort < 1 || operatorPort > 65535 {
		return 0, 0, fmt.Errorf("%s: expected a port between 1 and 65535", brokerEnvName("OPERATOR_PORT"))
	}
	return port, operatorPort, nil
}

func loadTelegram(getenv func(string) string, cfg *Config) error {
	token, err := loadTelegramToken(getenv)
	if err != nil {
		return err
	}
	cfg.TelegramBotToken = token
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

func loadTelegramToken(getenv func(string) string) (string, error) {
	return loadSecretValue(getenv, "TELEGRAM_BOT_TOKEN", "TELEGRAM_BOT_TOKEN_FILE")
}

func loadSecretValue(getenv func(string) string, valueSuffix, fileSuffix string) (string, error) {
	inlineValue := brokerEnv(getenv, valueSuffix)
	path := brokerEnv(getenv, fileSuffix)
	if inlineValue != "" && path != "" {
		return "", fmt.Errorf("%s and %s are mutually exclusive", brokerEnvName(valueSuffix), brokerEnvName(fileSuffix))
	}
	if inlineValue != "" || path == "" {
		return inlineValue, nil
	}
	data, err := readSecretFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %s", brokerEnvName(fileSuffix), secretPathReadFailure(err))
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s is empty", brokerEnvName(fileSuffix))
	}
	return value, nil
}

func readSecretFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-configured secret path.
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxSecretFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > maxSecretFileBytes {
		return nil, errSecretFileTooLarge
	}
	return data, nil
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

func loadOperators(getenv func(string) string, clients []Client) ([]Client, error) {
	operators, err := collectOperators(getenv)
	if err != nil || len(operators) == 0 {
		return operators, err
	}
	validated, err := validateClients(operators)
	if err != nil {
		return nil, fmt.Errorf("operator credentials: %w", err)
	}
	return validateOperatorSeparation(validated, clients)
}

func collectOperators(getenv func(string) string) ([]Client, error) {
	var operators []Client
	if shared := brokerEnv(getenv, "OPERATOR_SHARED_SECRET"); shared != "" {
		operators = append(operators, Client{Name: "default", Secret: shared})
	}
	if path := brokerEnv(getenv, "OPERATOR_SECRETS_FILE"); path != "" {
		fromFile, err := parseNamedSecretsFile(path, "OPERATOR_SECRETS_FILE")
		if err != nil {
			return nil, err
		}
		operators = append(operators, fromFile...)
	}
	return operators, nil
}

func validateOperatorSeparation(operators []Client, clients []Client) ([]Client, error) {
	clientHashes := make(map[[32]byte]struct{}, len(clients))
	for _, client := range clients {
		clientHashes[sha256.Sum256([]byte(client.Secret))] = struct{}{}
	}
	for _, operator := range operators {
		if _, reused := clientHashes[sha256.Sum256([]byte(operator.Secret))]; reused {
			return nil, fmt.Errorf("operator %q secret reuses a client secret", operator.Name)
		}
	}
	return operators, nil
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
	return parseNamedSecretsFile(path, "SECRETS_FILE")
}

func parseNamedSecretsFile(path string, envSuffix string) ([]Client, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path from the environment.
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", brokerEnvName(envSuffix), err)
	}
	var clients []Client
	for lineNumber, line := range strings.Split(string(data), "\n") {
		client, ok, err := parseSecretLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", brokerEnvName(envSuffix), lineNumber+1, err)
		}
		if !ok {
			continue
		}
		clients = append(clients, client)
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("%s contains no identities", brokerEnvName(envSuffix))
	}
	return clients, nil
}

func brokerEnv(getenv func(string) string, suffix string) string {
	return getenv(brokerEnvName(suffix))
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
