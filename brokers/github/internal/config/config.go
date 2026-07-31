package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/auth"
	"github.com/osolmaz/unyolo/authorization/admission"
	"github.com/osolmaz/unyolo/internal/config/client"
	"github.com/osolmaz/unyolo/internal/config/secretfile"
	"github.com/osolmaz/unyolo/transport/endpoint"
)

const minimumSharedSecretBytes = auth.MinimumSecretBytes

type Config struct {
	Environment               string
	Development               bool
	AgentEndpoint             endpoint.Endpoint
	GitEndpoint               *endpoint.Endpoint
	ClientID                  string
	SharedSecret              string
	SecretsFile               string
	ClientSecrets             map[string]string
	OperatorID                string
	OperatorSecret            string
	OperatorSecretsFile       string
	OperatorSecrets           map[string]string
	OperatorEndpoint          *endpoint.Endpoint
	TLSCertificateFile        string
	TLSPrivateKeyFile         string
	GitHubToken               string
	GitHubTokenFile           string
	GitHubUserID              int64
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
	GitHubStreamTimeout       time.Duration
	MaxReceivePackBytes       int64
	Admission                 admission.Config
}

func Load() (Config, error) {
	return LoadFromLookup(os.LookupEnv)
}

// LoadFromLookup loads configuration from an injected environment lookup.
func LoadFromLookup(lookup func(string) (string, bool)) (Config, error) {
	env := environment{lookup: lookup}
	cfg, development, networkExposure, err := loadBaseConfig(env)
	if err != nil {
		return Config{}, err
	}
	if err := loadOperatorEndpoint(env, &cfg, development, networkExposure); err != nil {
		return Config{}, err
	}
	if err := loadGitEndpoint(env, &cfg, development, networkExposure); err != nil {
		return Config{}, err
	}
	if err := cfg.loadCredentialFiles(); err != nil {
		return Config{}, err
	}
	if err := cfg.loadIdentityStores(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	if err := loadAdmissionConfig(env, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func loadGitEndpoint(env environment, cfg *Config, development, networkExposure bool) error {
	value := env.value("GH_BROKER_GIT_ENDPOINT", "")
	if value == "" {
		return nil
	}
	parsed, err := endpoint.Parse(value, endpoint.ParseOptions{AllowEphemeralTCP: development, AllowNetworkTCP: networkExposure, AllowNetworkTLS: networkExposure})
	if err != nil {
		return fmt.Errorf("GH_BROKER_GIT_ENDPOINT: %w", err)
	}
	if parsed.Scheme() != endpoint.SchemeTCP && parsed.Scheme() != endpoint.SchemeTLS {
		return errors.New("GH_BROKER_GIT_ENDPOINT must use tcp or tls")
	}
	if !parsed.Ephemeral() && (parsed.String() == cfg.AgentEndpoint.String() || cfg.OperatorEndpoint != nil && parsed.String() == cfg.OperatorEndpoint.String()) {
		return errors.New("git, agent, and operator endpoints must differ")
	}
	cfg.GitEndpoint = &parsed
	return nil
}

func loadBaseConfig(env environment) (Config, bool, bool, error) {
	development, err := env.boolean("GH_BROKER_DEVELOPMENT", false)
	if err != nil {
		return Config{}, false, false, err
	}
	networkExposure, err := env.networkExposure("GH_BROKER_NETWORK_EXPOSURE")
	if err != nil {
		return Config{}, false, false, err
	}
	agentEndpoint, err := loadEndpoint(env, "GH_BROKER_AGENT_ENDPOINT", development, networkExposure)
	if err != nil {
		return Config{}, false, false, err
	}
	cfg := Config{
		Environment:               map[bool]string{false: "production", true: "development"}[development],
		Development:               development,
		AgentEndpoint:             agentEndpoint,
		ClientID:                  env.value("GH_BROKER_CLIENT_ID", ""),
		SharedSecret:              env.value("GH_BROKER_SHARED_SECRET", ""),
		SecretsFile:               env.value("GH_BROKER_SECRETS_FILE", ""),
		OperatorID:                env.value("GH_BROKER_OPERATOR_ID", ""),
		OperatorSecret:            env.value("GH_BROKER_OPERATOR_SHARED_SECRET", ""),
		OperatorSecretsFile:       env.value("GH_BROKER_OPERATOR_SECRETS_FILE", ""),
		GitHubToken:               env.value("GH_BROKER_GITHUB_TOKEN", ""),
		GitHubTokenFile:           env.value("GH_BROKER_GITHUB_TOKEN_FILE", ""),
		GitHubAppID:               env.value("GH_BROKER_GITHUB_APP_ID", ""),
		GitHubAppIDFile:           env.value("GH_BROKER_GITHUB_APP_ID_FILE", ""),
		GitHubAppPrivateKeyFile:   env.value("GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE", ""),
		GitHubAppClientID:         env.value("GH_BROKER_GITHUB_APP_CLIENT_ID", ""),
		GitHubAppClientIDFile:     env.value("GH_BROKER_GITHUB_APP_CLIENT_ID_FILE", ""),
		GitHubAppClientSecret:     env.value("GH_BROKER_GITHUB_APP_CLIENT_SECRET", ""),
		GitHubAppClientSecretFile: env.value("GH_BROKER_GITHUB_APP_CLIENT_SECRET_FILE", ""),
		GitHubWebhookSecret:       env.value("GH_BROKER_GITHUB_WEBHOOK_SECRET", ""),
		GitHubWebhookSecretFile:   env.value("GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE", ""),
		GitHubAPIBaseURL:          env.value("GH_BROKER_GITHUB_API_URL", "https://api.github.com/"),
		GitHubWebBaseURL:          env.value("GH_BROKER_GITHUB_WEB_URL", "https://github.com/"),
		ScopeFile:                 env.value("GH_BROKER_SCOPE_FILE", ""),
		StateDir:                  env.value("GH_BROKER_STATE_DIR", ""),
		TLSCertificateFile:        env.value("GH_BROKER_TLS_CERT_FILE", ""),
		TLSPrivateKeyFile:         env.value("GH_BROKER_TLS_KEY_FILE", ""),
		TelegramBotTokenFile:      env.value("GH_BROKER_TELEGRAM_BOT_TOKEN_FILE", ""),
	}
	if err := loadNumericEnvironment(env, &cfg); err != nil {
		return Config{}, false, false, err
	}
	return cfg, development, networkExposure, nil
}

func loadOperatorEndpoint(env environment, cfg *Config, development, networkExposure bool) error {
	if cfg.OperatorSecret != "" || cfg.OperatorSecretsFile != "" {
		operatorEndpoint, endpointErr := loadEndpoint(env, "GH_BROKER_OPERATOR_ENDPOINT", development, networkExposure)
		if endpointErr != nil {
			return endpointErr
		}
		cfg.OperatorEndpoint = &operatorEndpoint
	}
	return nil
}

func loadAdmissionConfig(env environment, cfg *Config) error {
	admissionPath := env.value("GH_BROKER_ADMISSION_CONFIG", "")
	clients := make([]string, 0, len(cfg.ClientSecrets))
	for identity := range cfg.ClientSecrets {
		clients = append(clients, identity)
	}
	loaded, err := admission.LoadFile(admissionPath, clients)
	if err != nil {
		return fmt.Errorf("GH_BROKER_ADMISSION_CONFIG: %w", err)
	}
	cfg.Admission = loaded
	return nil
}

type environment struct{ lookup func(string) (string, bool) }

func (e environment) value(name, fallback string) string {
	if value, ok := e.lookup(name); ok {
		return value
	}
	return fallback
}

func (e environment) boolean(name string, fallback bool) (bool, error) {
	value, ok := e.lookup(name)
	if !ok {
		return fallback, nil
	}
	if value == "true" {
		return true, nil
	}
	if value == "false" {
		return false, nil
	}
	return false, fmt.Errorf("%s must be true or false", name)
}

func (e environment) networkExposure(name string) (bool, error) {
	value, ok := e.lookup(name)
	if !ok || value == "" {
		return false, nil
	}
	if value == "allow" {
		return true, nil
	}
	return false, fmt.Errorf("%s must be allow when set", name)
}

func loadEndpoint(env environment, name string, development, network bool) (endpoint.Endpoint, error) {
	value := env.value(name, "")
	if value == "" {
		return endpoint.Endpoint{}, fmt.Errorf("%s is required", name)
	}
	parsed, err := endpoint.Parse(value, endpoint.ParseOptions{AllowEphemeralTCP: development, AllowNetworkTCP: network, AllowNetworkTLS: network})
	if err != nil {
		return endpoint.Endpoint{}, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func loadNumericEnvironment(env environment, cfg *Config) error {
	var err error
	if cfg.GitHubUserID, err = env.positiveInt("GH_BROKER_GITHUB_USER_ID", 0, true); err != nil {
		return err
	}
	if cfg.TelegramChatID, err = env.nonzeroInt("GH_BROKER_TELEGRAM_CHAT_ID", 0); err != nil {
		return err
	}
	if cfg.GitHubHTTPTimeout, err = env.duration("GH_BROKER_GITHUB_HTTP_TIMEOUT", 30*time.Second, false); err != nil {
		return err
	}
	if cfg.GitHubStreamTimeout, err = env.duration("GH_BROKER_GITHUB_STREAM_TIMEOUT", 10*time.Minute, true); err != nil {
		return err
	}
	cfg.MaxReceivePackBytes, err = env.positiveInt("GH_BROKER_MAX_RECEIVE_PACK_BYTES", 25*1024*1024, false)
	return err
}

func (e environment) positiveInt(name string, fallback int64, allowZero bool) (int64, error) {
	value, ok := e.lookup(name)
	if !ok {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 || parsed == 0 && !allowZero {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func (e environment) nonzeroInt(name string, fallback int64) (int64, error) {
	value, ok := e.lookup(name)
	if !ok {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%s must be a non-zero integer", name)
	}
	return parsed, nil
}

func (e environment) duration(name string, fallback time.Duration, allowZero bool) (time.Duration, error) {
	seconds, err := e.positiveInt(name, int64(fallback/time.Second), allowZero)
	if err != nil {
		return 0, err
	}
	return time.Duration(seconds) * time.Second, nil
}

func (c *Config) loadCredentialFiles() error {
	loaders := []func() error{
		c.loadGitHubTokenFile, c.loadGitHubAppFiles, c.loadGitHubAppClientFiles, c.loadGitHubWebhookSecretFile,
		c.loadTelegramBotTokenFile,
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

func (c *Config) loadIdentityStores() error {
	clients, err := collectIdentityStore(c.ClientID, c.SharedSecret, c.SecretsFile, true, "broker")
	if err != nil {
		return err
	}
	operators, err := collectIdentityStore(c.OperatorID, c.OperatorSecret, c.OperatorSecretsFile, false, "operator")
	if err != nil {
		return err
	}
	c.ClientSecrets, c.OperatorSecrets = clients, operators
	if c.SharedSecret == "" && c.ClientID != "" {
		c.SharedSecret = clients[c.ClientID]
	}
	if c.OperatorSecret == "" && c.OperatorID != "" {
		c.OperatorSecret = operators[c.OperatorID]
	}
	return nil
}

func collectIdentityStore(identity, inline, path string, allowEmpty bool, label string) (map[string]string, error) {
	values := map[string]string{}
	if inline != "" {
		if identity == "" {
			variable := map[string]string{"broker": "CLIENT", "operator": "OPERATOR"}[label]
			return nil, fmt.Errorf("GH_BROKER_%s_ID is required with an inline secret", variable)
		}
		values[identity] = inline
	}
	if path != "" {
		fromFile, err := secretfile.ParseWithOptions(path, secretfile.ParseOptions{AllowEmpty: allowEmpty})
		if err != nil {
			return nil, fmt.Errorf("read %s secret file: %w", label, err)
		}
		for name, secret := range fromFile {
			if _, exists := values[name]; exists {
				return nil, fmt.Errorf("duplicate %s identity %q", label, name)
			}
			values[name] = secret
		}
	}
	return values, nil
}

// EffectiveClientSecrets returns an isolated client credential map.
func (c Config) EffectiveClientSecrets() map[string]string {
	return effectiveIdentityStore(c.ClientSecrets, c.ClientID, c.SharedSecret)
}

// EffectiveOperatorSecrets returns an isolated approver credential map.
func (c Config) EffectiveOperatorSecrets() map[string]string {
	return effectiveIdentityStore(c.OperatorSecrets, c.OperatorID, c.OperatorSecret)
}

func effectiveIdentityStore(values map[string]string, identity, inline string) map[string]string {
	result := make(map[string]string, len(values)+1)
	for name, secret := range values {
		result[name] = secret
	}
	if identity != "" && inline != "" {
		result[identity] = inline
	}
	return result
}

func (c Config) Validate() error {
	return firstError(
		initializedEndpoint(c.AgentEndpoint, "GH_BROKER_AGENT_ENDPOINT is required"),
		identityStores(c),
		operatorConfig(c),
		githubCredential(c),
		required(c.ScopeFile, "GH_BROKER_SCOPE_FILE is required"),
		required(c.StateDir, "GH_BROKER_STATE_DIR is required"),
		productionPaths(c),
		tlsFiles(c),
		upstreamOrigins(c),
		telegramPair(c.TelegramBotToken, c.TelegramChatID),
		positiveDuration(c.GitHubHTTPTimeout, "GH_BROKER_GITHUB_HTTP_TIMEOUT must be positive"),
		optionalPositiveDuration(c.GitHubStreamTimeout, "GH_BROKER_GITHUB_STREAM_TIMEOUT must be positive"),
		positiveInt64(c.MaxReceivePackBytes, "GH_BROKER_MAX_RECEIVE_PACK_BYTES must be positive"),
	)
}

func upstreamOrigins(c Config) error {
	if err := endpoint.ValidateHTTPOrigin(c.GitHubAPIBaseURL, c.Development); err != nil {
		return fmt.Errorf("GH_BROKER_GITHUB_API_URL: %w", err)
	}
	if err := endpoint.ValidateHTTPOrigin(c.GitHubWebBaseURL, c.Development); err != nil {
		return fmt.Errorf("GH_BROKER_GITHUB_WEB_URL: %w", err)
	}
	return nil
}

func identityStores(c Config) error {
	if len(c.EffectiveClientSecrets()) == 0 && c.SecretsFile == "" {
		return errors.New("GH_BROKER_SECRETS_FILE is required when no clients are configured")
	}
	allSecrets := map[string]string{}
	for kind, values := range map[string]map[string]string{"client": c.EffectiveClientSecrets(), "operator": c.EffectiveOperatorSecrets()} {
		for identity, secret := range values {
			if err := clientconfig.ValidateClientName(identity); err != nil {
				return fmt.Errorf("%s identity %q: %w", kind, identity, err)
			}
			if err := minimumBytes(secret, minimumSharedSecretBytes, kind+" secret"); err != nil {
				return err
			}
			if previous, exists := allSecrets[secret]; exists {
				return fmt.Errorf("%s identity %q secret must differ from %s", kind, identity, previous)
			}
			allSecrets[secret] = kind + " " + identity
		}
	}
	return nil
}

func operatorConfig(c Config) error {
	if len(c.EffectiveOperatorSecrets()) == 0 {
		return nil
	}
	return operatorListener(c)
}

func operatorListener(c Config) error {
	if c.OperatorEndpoint == nil || c.OperatorEndpoint.String() == "" {
		return errors.New("GH_BROKER_OPERATOR_ENDPOINT is required with operator credentials")
	}
	if c.OperatorEndpoint.String() == c.AgentEndpoint.String() {
		return errors.New("operator and agent endpoints must differ")
	}
	return nil
}

func initializedEndpoint(value endpoint.Endpoint, message string) error {
	if value.String() == "" {
		return errors.New(message)
	}
	return nil
}

func tlsFiles(c Config) error {
	needsTLS := c.AgentEndpoint.Scheme() == endpoint.SchemeTLS || c.OperatorEndpoint != nil && c.OperatorEndpoint.Scheme() == endpoint.SchemeTLS ||
		c.GitEndpoint != nil && c.GitEndpoint.Scheme() == endpoint.SchemeTLS
	if needsTLS != (c.TLSCertificateFile != "" && c.TLSPrivateKeyFile != "") {
		return errors.New("GH_BROKER_TLS_CERT_FILE and GH_BROKER_TLS_KEY_FILE are required exactly for TLS listeners")
	}
	if needsTLS {
		if _, err := endpoint.ServerTLSConfig(c.TLSCertificateFile, c.TLSPrivateKeyFile); err != nil {
			return err
		}
	}
	return nil
}

func productionPaths(c Config) error {
	if c.Development {
		return nil
	}
	paths := map[string]string{"GH_BROKER_SCOPE_FILE": c.ScopeFile, "GH_BROKER_STATE_DIR": c.StateDir}
	if c.TLSCertificateFile != "" {
		paths["GH_BROKER_TLS_CERT_FILE"], paths["GH_BROKER_TLS_KEY_FILE"] = c.TLSCertificateFile, c.TLSPrivateKeyFile
	}
	for name, value := range paths {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be an absolute normalized production path", name)
		}
	}
	return nil
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

func optionalPositiveDuration(value time.Duration, message string) error {
	if value < 0 {
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
	return firstError(appWebhookCredential(c), appClientCredential(c), appUserSelector(c),
		required(c.GitHubAPIBaseURL, "GH_BROKER_GITHUB_API_URL is required"), required(c.GitHubWebBaseURL, "GH_BROKER_GITHUB_WEB_URL is required"))
}

func appWebhookCredential(c Config) error {
	if strings.TrimSpace(c.GitHubWebhookSecret) == "" {
		return errors.New("GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE is required with GitHub App credentials")
	}
	return nil
}

func appClientCredential(c Config) error {
	if (strings.TrimSpace(c.GitHubAppClientID) == "") != (strings.TrimSpace(c.GitHubAppClientSecret) == "") {
		return errors.New("GitHub App client id and client secret must be configured together")
	}
	if c.GitHubAppClientSecret != "" && c.GitHubAppClientSecretFile == "" {
		return errors.New("GitHub App client secret must be loaded from GH_BROKER_GITHUB_APP_CLIENT_SECRET_FILE")
	}
	return nil
}

func appUserSelector(c Config) error {
	if c.GitHubAppClientID != "" && c.GitHubUserID <= 0 {
		return errors.New("GH_BROKER_GITHUB_USER_ID is required with GitHub App user credentials")
	}
	if c.GitHubAppClientID == "" && c.GitHubUserID != 0 {
		return errors.New("GH_BROKER_GITHUB_USER_ID requires GitHub App user credentials")
	}
	return nil
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
