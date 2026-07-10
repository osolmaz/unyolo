// Package clientconfig writes per-client broker environment files.
package clientconfig

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/osolmaz/brokerkit/store"
)

const (
	clientEnvFileMode     os.FileMode = 0o600
	maxClientSecretsBytes             = 1024 * 1024
)

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
	data, err := readSecretsFile(path)
	if err != nil {
		return "", err
	}
	return SecretFromData(data, client)
}

// SecretsFromFile reads path and returns all configured client secrets.
func SecretsFromFile(path string) (map[string]string, error) {
	data, err := readSecretsFile(path)
	if err != nil {
		return nil, err
	}
	return SecretsFromData(data)
}

// SecretFromData parses `name = secret` data and returns client's secret.
func SecretFromData(data []byte, client string) (string, error) {
	name := strings.TrimSpace(client)
	if err := ValidateClientName(name); err != nil {
		return "", err
	}
	secrets, err := SecretsFromData(data)
	if err != nil {
		return "", err
	}
	if secret, exists := secrets[name]; exists {
		return secret, nil
	}
	return "", fmt.Errorf("client %q was not found in secret file", name)
}

func readSecretsFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- path is operator supplied setup input.
	if err != nil {
		return nil, fmt.Errorf("read client secret file: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxClientSecretsBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read client secret file: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close client secret file: %w", closeErr)
	}
	if len(data) > maxClientSecretsBytes {
		return nil, fmt.Errorf("client secret file exceeds %d bytes", maxClientSecretsBytes)
	}
	return data, nil
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
	if !filepath.IsAbs(homeDir) {
		return "", errors.New("home directory must be absolute")
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
	path, err := Path(cfg.HomeDir, cfg.BrokerName)
	if err != nil {
		return "", err
	}
	body, err := Render(cfg)
	if err != nil {
		return "", err
	}
	if err := writeClientConfigSafely(cfg.HomeDir, cfg.BrokerName, body); err != nil {
		return "", err
	}
	return path, nil
}

func writeClientConfigSafely(homeDir string, brokerName string, body []byte) error {
	root, err := openVerifiedHomeRoot(homeDir)
	if err != nil {
		return err
	}
	writeErr := writeClientConfigInRoot(root, brokerName, body)
	closeErr := root.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return fmt.Errorf("close home directory: %w", closeErr)
	}
	return nil
}

func openVerifiedHomeRoot(homeDir string) (*os.Root, error) {
	expected, err := inspectRealHomePath(homeDir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(homeDir)
	if err != nil {
		return nil, fmt.Errorf("open home directory: %w", err)
	}
	if err := verifyOpenedHomeRoot(root, expected); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func verifyOpenedHomeRoot(root *os.Root, expected os.FileInfo) error {
	actual, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("verify opened home directory: %w", err)
	}
	if !os.SameFile(expected, actual) {
		return errors.New("home directory changed while it was being opened")
	}
	return nil
}

func writeClientConfigInRoot(root *os.Root, brokerName string, body []byte) error {
	uid, gid, err := rootOwner(root)
	if err != nil {
		return err
	}
	configDir := ".config"
	brokerDir := filepath.Join(configDir, brokerName)
	if err := ensureClientDirectory(root, configDir, uid, gid); err != nil {
		return err
	}
	if err := ensureClientDirectory(root, brokerDir, uid, gid); err != nil {
		return err
	}
	return writeClientFile(root, filepath.Join(brokerDir, "client.env"), body, uid, gid)
}

func (cfg Config) validate() error {
	if err := validateBrokerName(cfg.BrokerName); err != nil {
		return err
	}
	if err := validateEnvPrefix(cfg.EnvPrefix); err != nil {
		return err
	}
	if err := ValidateURL(cfg.URL); err != nil {
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

// ValidateURL validates a broker client URL and rejects embedded credentials.
func ValidateURL(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return errors.New("broker URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("broker URL is invalid: %w", err)
	}
	return validateParsedURL(parsed)
}

func validateParsedURL(parsed *url.URL) error {
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("broker URL must use http or https")
	}
	if parsed.Host == "" {
		return errors.New("broker URL host is required")
	}
	if parsed.User != nil {
		return errors.New("broker URL must not contain user information")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("broker URL must not contain a query or fragment")
	}
	return nil
}

// ValidateClientName validates an identifier used as a client secret-file key.
func ValidateClientName(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return errors.New("client name is required")
	}
	if strings.ContainsAny(value, "\r\n=") || strings.HasPrefix(trimmed, "#") {
		return errors.New("client name is not safe for a client secret file")
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func rootOwner(root *os.Root) (int, int, error) {
	info, err := root.Stat(".")
	if err != nil {
		return 0, 0, fmt.Errorf("stat home directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("home directory owner is unavailable")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func inspectRealHomePath(path string) (os.FileInfo, error) {
	current := string(filepath.Separator)
	var final os.FileInfo
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), current), current) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("inspect home directory path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("home directory path must not contain symbolic links")
		}
		final = info
	}
	return final, nil
}

func ensureClientDirectory(root *os.Root, name string, uid int, gid int) error {
	if err := ensureRealClientDirectory(root, name); err != nil {
		return err
	}
	return chownClientDirectory(root, name, uid, gid)
}

func ensureRealClientDirectory(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(name, 0o700); err != nil {
			return fmt.Errorf("create client config directory: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect client config directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("client config path must contain only real directories")
	}
	return nil
}

func chownClientDirectory(root *os.Root, name string, uid int, gid int) error {
	handle, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("open client config directory: %w", err)
	}
	uid, gid = requestedOwner(uid, gid)
	chownErr := handle.Chown(uid, gid)
	closeErr := handle.Close()
	if chownErr != nil {
		return fmt.Errorf("chown client config directory: %w", chownErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close client config directory: %w", closeErr)
	}
	return nil
}

func writeClientFile(root *os.Root, name string, data []byte, uid int, gid int) error {
	temporary, err := temporaryClientName(name)
	if err != nil {
		return err
	}
	if err := writeClientTemporary(root, temporary, data, uid, gid); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return fmt.Errorf("replace client config file: %w", err)
	}
	return syncClientDirectory(root, filepath.Dir(name))
}

func writeClientTemporary(root *os.Root, name string, data []byte, uid int, gid int) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, clientEnvFileMode)
	if err != nil {
		return fmt.Errorf("create client config file: %w", err)
	}
	return populateClientTemporary(file, data, uid, gid)
}

func populateClientTemporary(file *os.File, data []byte, uid int, gid int) error {
	uid, gid = requestedOwner(uid, gid)
	if err := runClientFileSteps(file, data, uid, gid); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close client config file: %w", err)
	}
	return nil
}

func requestedOwner(uid int, gid int) (int, int) {
	if os.Geteuid() != 0 {
		return -1, -1
	}
	return uid, gid
}

func runClientFileSteps(file *os.File, data []byte, uid int, gid int) error {
	steps := []struct {
		name string
		run  func() error
	}{
		{name: "write", run: func() error { _, err := file.Write(data); return err }},
		{name: "chown", run: func() error { return file.Chown(uid, gid) }},
		{name: "sync", run: file.Sync},
	}
	for _, step := range steps {
		if err := step.run(); err != nil {
			return fmt.Errorf("%s client config file: %w", step.name, err)
		}
	}
	return nil
}

func temporaryClientName(name string) (string, error) {
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate client config temporary name: %w", err)
	}
	return name + "." + hex.EncodeToString(suffix[:]) + ".tmp", nil
}

func syncClientDirectory(root *os.Root, name string) error {
	handle, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("open client config directory for sync: %w", err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return fmt.Errorf("sync client config directory: %w", err)
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("close client config directory: %w", err)
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
	if err := ValidateClientName(name); err != nil {
		return "", "", false, err
	}
	if secret == "" {
		return "", "", false, fmt.Errorf("client %q secret is empty", name)
	}
	return name, secret, true, nil
}
