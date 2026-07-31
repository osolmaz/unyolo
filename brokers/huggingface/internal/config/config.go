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
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/auth"
	"github.com/osolmaz/unyolo/authorization/admission"
	"github.com/osolmaz/unyolo/internal/config/secretfile"
	"github.com/osolmaz/unyolo/transport/endpoint"
	clienthttp "github.com/osolmaz/unyolo/transport/http/client"
)

// MinSecretBytes is the minimum accepted client secret length.
const MinSecretBytes = auth.MinimumSecretBytes

// Defaults for optional settings.
const (
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
	HFToken            string
	HFTokenFile        string
	Clients            []Client
	Operators          []Client
	AgentEndpoint      endpoint.Endpoint
	GitEndpoint        *endpoint.Endpoint
	OperatorEndpoint   *endpoint.Endpoint
	TLSCertificateFile string
	TLSPrivateKeyFile  string
	Development        bool
	ScopeFile          string
	StateDir           string
	MaxPackBytes       int64
	HFTimeout          time.Duration
	UpstreamHubURL     string
	UpstreamRouterURL  string
	XetPython          string
	TelegramBotToken   string
	TelegramAPIBase    string
	TelegramChatID     int64
	Admission          admission.Config
}

// Load reads and validates configuration from getenv (normally
// os.Getenv). It reads the secrets file, if configured, from disk.
func Load(getenv func(string) string) (Config, error) {
	cfg, err := loadBaseConfig(getenv)
	if err != nil {
		return Config{}, err
	}
	if err := loadConfigSections(getenv, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func loadBaseConfig(getenv func(string) string) (Config, error) {
	hfToken, err := loadHFToken(getenv)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		HFToken:            hfToken,
		HFTokenFile:        strings.TrimSpace(brokerEnv(getenv, "HF_TOKEN_FILE")),
		ScopeFile:          brokerEnv(getenv, "SCOPE_FILE"),
		StateDir:           brokerEnv(getenv, "STATE_DIR"),
		UpstreamHubURL:     stringOr(brokerEnv(getenv, "UPSTREAM_HUB_URL"), DefaultUpstreamHubURL),
		UpstreamRouterURL:  stringOr(brokerEnv(getenv, "UPSTREAM_ROUTER_URL"), DefaultUpstreamRouterURL),
		XetPython:          stringOr(brokerEnv(getenv, "XET_PYTHON"), "python3"),
		TLSCertificateFile: strings.TrimSpace(brokerEnv(getenv, "TLS_CERT_FILE")),
		TLSPrivateKeyFile:  strings.TrimSpace(brokerEnv(getenv, "TLS_KEY_FILE")),
	}
	if cfg.HFToken == "" {
		return Config{}, fmt.Errorf("%s or %s is required", brokerEnvName("HF_TOKEN"), brokerEnvName("HF_TOKEN_FILE"))
	}
	return cfg, nil
}

func loadConfigSections(getenv func(string) string, cfg *Config) error {
	var err error
	if cfg.Clients, err = loadClients(getenv); err != nil {
		return err
	}
	if cfg.Operators, err = loadOperators(getenv, cfg.Clients); err != nil {
		return err
	}
	if cfg.Admission, err = admission.LoadFile(brokerEnv(getenv, "ADMISSION_CONFIG"), clientNames(cfg.Clients)); err != nil {
		return fmt.Errorf("%s: %w", brokerEnvName("ADMISSION_CONFIG"), err)
	}
	if err := loadRuntime(getenv, cfg); err != nil {
		return err
	}
	if err := loadNumeric(getenv, cfg); err != nil {
		return err
	}
	return loadTelegram(getenv, cfg)
}

func clientNames(clients []Client) []string {
	names := make([]string, 0, len(clients))
	for _, client := range clients {
		names = append(names, client.Name)
	}
	return names
}

func loadRuntime(getenv func(string) string, cfg *Config) error {
	development, err := parseDevelopment(brokerEnv(getenv, "DEVELOPMENT"))
	if err != nil {
		return err
	}
	cfg.Development = development
	allowNetwork, err := parseNetworkExposure(brokerEnv(getenv, "NETWORK_EXPOSURE"))
	if err != nil {
		return err
	}
	parseOptions := endpoint.ParseOptions{AllowEphemeralTCP: development, AllowNetworkTCP: allowNetwork, AllowNetworkTLS: allowNetwork}
	if err := loadRuntimeEndpoints(getenv, cfg, parseOptions); err != nil {
		return err
	}
	if err := validateRuntimePaths(cfg.ScopeFile, cfg.StateDir, development); err != nil {
		return err
	}
	if err := validateTLSFiles(cfg); err != nil {
		return err
	}
	return validateRuntimeOrigins(cfg.UpstreamHubURL, cfg.UpstreamRouterURL, development)
}

func loadRuntimeEndpoints(getenv func(string) string, cfg *Config, parseOptions endpoint.ParseOptions) error {
	var err error
	cfg.AgentEndpoint, err = parseEndpoint(brokerEnv(getenv, "AGENT_ENDPOINT"), "AGENT_ENDPOINT", parseOptions)
	if err != nil {
		return err
	}
	if len(cfg.Operators) > 0 {
		operatorEndpoint, parseErr := parseEndpoint(brokerEnv(getenv, "OPERATOR_ENDPOINT"), "OPERATOR_ENDPOINT", parseOptions)
		if parseErr != nil {
			return parseErr
		}
		if operatorEndpoint.String() == cfg.AgentEndpoint.String() {
			return errors.New("operator and agent endpoints must differ")
		}
		cfg.OperatorEndpoint = &operatorEndpoint
	}
	return loadGitEndpoint(getenv, cfg, parseOptions)
}

func loadGitEndpoint(getenv func(string) string, cfg *Config, parseOptions endpoint.ParseOptions) error {
	raw := brokerEnv(getenv, "GIT_ENDPOINT")
	if raw == "" {
		return nil
	}
	gitEndpoint, err := endpoint.Parse(raw, parseOptions)
	if err != nil {
		return fmt.Errorf("%s: %w", brokerEnvName("GIT_ENDPOINT"), err)
	}
	if gitEndpoint.Scheme() != endpoint.SchemeTCP && gitEndpoint.Scheme() != endpoint.SchemeTLS {
		return fmt.Errorf("%s must use tcp or tls", brokerEnvName("GIT_ENDPOINT"))
	}
	if gitEndpointConflicts(gitEndpoint, cfg) {
		return errors.New("git, agent, and operator endpoints must differ")
	}
	cfg.GitEndpoint = &gitEndpoint
	return nil
}

func gitEndpointConflicts(gitEndpoint endpoint.Endpoint, cfg *Config) bool {
	if gitEndpoint.Ephemeral() || gitEndpoint.String() == cfg.AgentEndpoint.String() {
		return !gitEndpoint.Ephemeral()
	}
	return cfg.OperatorEndpoint != nil && gitEndpoint.String() == cfg.OperatorEndpoint.String()
}

func validateTLSFiles(cfg *Config) error {
	needsTLS := configNeedsTLS(cfg)
	hasTLSFiles := cfg.TLSCertificateFile != "" && cfg.TLSPrivateKeyFile != ""
	if needsTLS != hasTLSFiles {
		return fmt.Errorf("%s and %s are required exactly for TLS listeners", brokerEnvName("TLS_CERT_FILE"), brokerEnvName("TLS_KEY_FILE"))
	}
	if !needsTLS {
		return nil
	}
	_, err := endpoint.ServerTLSConfig(cfg.TLSCertificateFile, cfg.TLSPrivateKeyFile)
	return err
}

func configNeedsTLS(cfg *Config) bool {
	if cfg.AgentEndpoint.Scheme() == endpoint.SchemeTLS {
		return true
	}
	if cfg.OperatorEndpoint != nil && cfg.OperatorEndpoint.Scheme() == endpoint.SchemeTLS {
		return true
	}
	return cfg.GitEndpoint != nil && cfg.GitEndpoint.Scheme() == endpoint.SchemeTLS
}

func validateRuntimeOrigins(upstreamHubURL, upstreamRouterURL string, development bool) error {
	if err := endpoint.ValidateHTTPOrigin(upstreamHubURL, development); err != nil {
		return fmt.Errorf("%s: %w", brokerEnvName("UPSTREAM_HUB_URL"), err)
	}
	if err := endpoint.ValidateHTTPOrigin(upstreamRouterURL, development); err != nil {
		return fmt.Errorf("%s: %w", brokerEnvName("UPSTREAM_ROUTER_URL"), err)
	}
	return nil
}

func parseNetworkExposure(raw string) (bool, error) {
	if raw == "" {
		return false, nil
	}
	if raw == "allow" {
		return true, nil
	}
	return false, fmt.Errorf("%s: expected allow when set", brokerEnvName("NETWORK_EXPOSURE"))
}

func parseDevelopment(raw string) (bool, error) {
	switch raw {
	case "":
		return false, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s: expected true or false", brokerEnvName("DEVELOPMENT"))
	}
}

func parseEndpoint(raw, suffix string, options endpoint.ParseOptions) (endpoint.Endpoint, error) {
	if raw == "" {
		return endpoint.Endpoint{}, fmt.Errorf("%s is required", brokerEnvName(suffix))
	}
	value, err := endpoint.Parse(raw, options)
	if err != nil {
		return endpoint.Endpoint{}, fmt.Errorf("%s: %w", brokerEnvName(suffix), err)
	}
	return value, nil
}

func validateRuntimePaths(scopeFile, stateDir string, development bool) error {
	if missingRuntimePath(scopeFile, stateDir) {
		return fmt.Errorf("%s and %s are required", brokerEnvName("SCOPE_FILE"), brokerEnvName("STATE_DIR"))
	}
	if productionRuntimePathIsRelative(scopeFile, stateDir, development) {
		return errors.New("production policy and state paths must be absolute")
	}
	return nil
}

func missingRuntimePath(scopeFile, stateDir string) bool {
	return scopeFile == "" || stateDir == ""
}

func productionRuntimePathIsRelative(scopeFile, stateDir string, development bool) bool {
	return !development && (!filepath.IsAbs(scopeFile) || !filepath.IsAbs(stateDir))
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
	maxPack, err := intOr(brokerEnv(getenv, "MAX_PACK_BYTES"), DefaultMaxPackBytes)
	if err != nil {
		return fmt.Errorf("%s: %w", brokerEnvName("MAX_PACK_BYTES"), err)
	}
	timeoutSeconds, err := intOr(brokerEnv(getenv, "HF_TIMEOUT"), 0)
	if err != nil {
		return fmt.Errorf("%s: %w", brokerEnvName("HF_TIMEOUT"), err)
	}
	cfg.MaxPackBytes = int64(maxPack)
	cfg.HFTimeout = DefaultHFTimeout
	if timeoutSeconds > 0 {
		cfg.HFTimeout = time.Duration(timeoutSeconds) * time.Second
	}
	return nil
}

func loadTelegram(getenv func(string) string, cfg *Config) error {
	token, err := loadTelegramToken(getenv)
	if err != nil {
		return err
	}
	cfg.TelegramBotToken = token
	cfg.TelegramAPIBase, err = loadTelegramAPIBase(brokerEnv(getenv, "TELEGRAM_API_BASE"))
	if err != nil {
		return err
	}
	cfg.TelegramChatID, err = loadTelegramChatID(
		cfg.TelegramBotToken,
		cfg.TelegramAPIBase,
		brokerEnv(getenv, "TELEGRAM_CHAT_ID"),
	)
	return err
}

func loadTelegramChatID(token, apiBase, raw string) (int64, error) {
	if token == "" && raw == "" && apiBase == "" {
		return 0, nil
	}
	if token == "" || raw == "" {
		return 0, fmt.Errorf("%s and %s must be set together", brokerEnvName("TELEGRAM_BOT_TOKEN"), brokerEnvName("TELEGRAM_CHAT_ID"))
	}
	chatID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || chatID == 0 {
		return 0, fmt.Errorf("%s: expected a non-zero integer", brokerEnvName("TELEGRAM_CHAT_ID"))
	}
	return chatID, nil
}

func loadTelegramAPIBase(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	parsed, err := clienthttp.ParseBaseURL(value)
	if err != nil {
		return "", fmt.Errorf("%s is invalid: %w", brokerEnvName("TELEGRAM_API_BASE"), err)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
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
	if len(clients) == 0 && brokerEnv(getenv, "SECRETS_FILE") == "" {
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
	return parseNamedSecretsFile(path, "SECRETS_FILE", true)
}

func parseNamedSecretsFile(path string, envSuffix string, allowEmpty ...bool) ([]Client, error) {
	options := secretfile.ParseOptions{AllowEmpty: len(allowEmpty) == 1 && allowEmpty[0]}
	secrets, err := secretfile.ParseWithOptions(path, options)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", brokerEnvName(envSuffix), err)
	}
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	slices.Sort(names)
	clients := make([]Client, 0, len(names))
	for _, name := range names {
		clients = append(clients, Client{Name: name, Secret: secrets[name]})
	}
	return clients, nil
}

func brokerEnv(getenv func(string) string, suffix string) string {
	return getenv(brokerEnvName(suffix))
}

func brokerEnvName(suffix string) string {
	return canonicalEnvPrefix + suffix
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
