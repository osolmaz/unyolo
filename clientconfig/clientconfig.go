// Package clientconfig writes per-client broker environment files.
package clientconfig

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/osolmaz/brokerkit/store"
)

const clientEnvFileMode os.FileMode = 0o600

var chownPath = os.Chown

// Config describes one broker client environment file.
type Config struct {
	BrokerName string
	EnvPrefix  string
	URL        string
	Secret     string
	HomeDir    string
}

// SecretFromFile reads path and returns the configured secret for client.
func SecretFromFile(path string, client string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is operator supplied setup input.
	if err != nil {
		return "", fmt.Errorf("read client secret file: %w", err)
	}
	return SecretFromData(data, client)
}

// SecretsFromFile reads path and returns all configured client secrets.
func SecretsFromFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is operator supplied setup input.
	if err != nil {
		return nil, fmt.Errorf("read client secret file: %w", err)
	}
	return SecretsFromData(data)
}

// SecretFromData parses `name = secret` data and returns client's secret.
func SecretFromData(data []byte, client string) (string, error) {
	name := strings.TrimSpace(client)
	if name == "" {
		return "", errors.New("client name is required")
	}
	for lineNumber, line := range strings.Split(string(data), "\n") {
		foundName, secret, ok, err := parseSecretLine(line)
		if err != nil {
			return "", fmt.Errorf("client secret file line %d: %w", lineNumber+1, err)
		}
		if ok && foundName == name {
			return secret, nil
		}
	}
	return "", fmt.Errorf("client %q was not found in secret file", name)
}

// SecretsFromData parses `name = secret` data and returns all configured client secrets.
func SecretsFromData(data []byte) (map[string]string, error) {
	out := map[string]string{}
	for lineNumber, line := range strings.Split(string(data), "\n") {
		name, secret, ok, err := parseSecretLine(line)
		if err != nil {
			return nil, fmt.Errorf("client secret file line %d: %w", lineNumber+1, err)
		}
		if !ok {
			continue
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("client secret file line %d: duplicate client %q", lineNumber+1, name)
		}
		out[name] = secret
	}
	if len(out) == 0 {
		return nil, errors.New("client secret file has no clients")
	}
	return out, nil
}

// Path returns the default client.env path for cfg.
func Path(homeDir string, brokerName string) (string, error) {
	if err := validateBrokerName(brokerName); err != nil {
		return "", err
	}
	if strings.TrimSpace(homeDir) == "" {
		return "", errors.New("home directory is required")
	}
	return filepath.Join(homeDir, ".config", brokerName, "client.env"), nil
}

// Render returns shell-compatible environment assignments for cfg.
func Render(cfg Config) ([]byte, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	prefix := normalizeEnvPrefix(cfg.EnvPrefix)
	body := prefix + "_URL=" + shellQuote(cfg.URL) + "\n" +
		prefix + "_SHARED_SECRET=" + shellQuote(cfg.Secret) + "\n"
	return []byte(body), nil
}

// Write writes cfg to ~/.config/<broker>/client.env and returns the path.
func Write(cfg Config) (string, error) {
	path, err := Path(cfg.HomeDir, cfg.BrokerName)
	if err != nil {
		return "", err
	}
	body, err := Render(cfg)
	if err != nil {
		return "", err
	}
	if err := store.WriteFileAtomic(path, body, clientEnvFileMode); err != nil {
		return "", err
	}
	return path, nil
}

// WriteForHomeOwner writes cfg and, when running as root, makes the generated
// client config paths owned by the owner of cfg.HomeDir.
func WriteForHomeOwner(cfg Config) (string, error) {
	path, err := Write(cfg)
	if err != nil {
		return "", err
	}
	if os.Geteuid() != 0 {
		return path, nil
	}
	uid, gid, err := homeOwner(cfg.HomeDir)
	if err != nil {
		return "", err
	}
	return path, chownClientPaths(cfg.HomeDir, cfg.BrokerName, path, uid, gid)
}

func (cfg Config) validate() error {
	if err := validateBrokerName(cfg.BrokerName); err != nil {
		return err
	}
	if err := validateEnvPrefix(cfg.EnvPrefix); err != nil {
		return err
	}
	if err := validateURL(cfg.URL); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Secret) == "" {
		return errors.New("client secret is required")
	}
	return nil
}

func validateBrokerName(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("broker name is required")
	}
	for _, char := range value {
		if !isBrokerNameChar(char) {
			return fmt.Errorf("broker name %q must contain only lowercase letters, digits, and hyphens", value)
		}
	}
	return nil
}

func isBrokerNameChar(char rune) bool {
	return (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-'
}

func validateEnvPrefix(value string) error {
	prefix := normalizeEnvPrefix(value)
	if prefix == "" {
		return errors.New("environment prefix is required")
	}
	for _, char := range prefix {
		if !isEnvPrefixChar(char) {
			return fmt.Errorf("environment prefix %q must contain only uppercase letters, digits, and underscores", value)
		}
	}
	return nil
}

func isEnvPrefixChar(char rune) bool {
	return (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_'
}

func normalizeEnvPrefix(value string) string {
	return strings.Trim(strings.TrimSpace(value), "_")
}

func validateURL(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return errors.New("broker URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("broker URL is invalid: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("broker URL must use http or https")
	}
	if parsed.Host == "" {
		return errors.New("broker URL host is required")
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func homeOwner(homeDir string) (int, int, error) {
	info, err := os.Stat(homeDir)
	if err != nil {
		return 0, 0, fmt.Errorf("stat home directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("home directory owner is unavailable")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func chownClientPaths(homeDir string, brokerName string, envPath string, uid int, gid int) error {
	for _, path := range []string{
		filepath.Join(homeDir, ".config"),
		filepath.Join(homeDir, ".config", brokerName),
		envPath,
	} {
		if err := chownPath(path, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	}
	return nil
}

func parseSecretLine(line string) (string, string, bool, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false, nil
	}
	name, secret, ok := strings.Cut(trimmed, "=")
	if !ok {
		return "", "", false, errors.New("expected name = secret")
	}
	name = strings.TrimSpace(name)
	secret = strings.TrimSpace(secret)
	if name == "" {
		return "", "", false, errors.New("client name is empty")
	}
	if secret == "" {
		return "", "", false, fmt.Errorf("client %q secret is empty", name)
	}
	return name, secret, true, nil
}
