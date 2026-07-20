package clientconfig

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxClientEnvBytes = 64 * 1024

// Client is the non-shell representation of one generated client.env file.
type Client struct {
	AgentEndpoint string
	GitEndpoint   string
	SharedSecret  string
}

// Read loads a generated client.env without evaluating it as shell code.
func Read(homeDir, brokerName, envPrefix string) (Client, error) {
	path, err := Path(homeDir, brokerName)
	if err != nil {
		return Client{}, err
	}
	if err := validateClientFile(path, homeDir); err != nil {
		return Client{}, err
	}
	file, err := os.Open(path) // #nosec G304 -- path is constrained beneath the selected home.
	if err != nil {
		return Client{}, fmt.Errorf("open broker client configuration: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxClientEnvBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return Client{}, errors.New("read broker client configuration")
	}
	if len(data) > maxClientEnvBytes {
		return Client{}, errors.New("broker client configuration is too large")
	}
	return parseClientEnv(data, normalizeEnvPrefix(envPrefix))
}

func validateClientFile(path, homeDir string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect broker client configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != clientEnvFileMode {
		return errors.New("broker client configuration must be a regular owner-only file")
	}
	homeInfo, err := os.Stat(filepath.Clean(homeDir))
	if err != nil {
		return fmt.Errorf("inspect broker client home: %w", err)
	}
	fileStat, fileOK := info.Sys().(*syscall.Stat_t)
	homeStat, homeOK := homeInfo.Sys().(*syscall.Stat_t)
	if !fileOK || !homeOK || fileStat.Uid != homeStat.Uid {
		return errors.New("broker client configuration must be owned by the home owner")
	}
	return nil
}

func parseClientEnv(data []byte, prefix string) (Client, error) {
	wanted := map[string]*string{}
	var client Client
	wanted[prefix+"_AGENT_ENDPOINT"] = &client.AgentEndpoint
	wanted[prefix+"_GIT_ENDPOINT"] = &client.GitEndpoint
	wanted[prefix+"_SHARED_SECRET"] = &client.SharedSecret
	seen := map[string]bool{}
	for _, raw := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if err := parseClientAssignment(raw, wanted, seen); err != nil {
			return Client{}, err
		}
	}
	return validateParsedClient(client)
}

func parseClientAssignment(raw string, wanted map[string]*string, seen map[string]bool) error {
	name, value, ok := strings.Cut(raw, "=")
	name = strings.TrimPrefix(name, "export ")
	destination, expected := wanted[name]
	if !ok || !expected || seen[name] {
		return errors.New("broker client configuration has an unsupported assignment")
	}
	decoded, err := decodeShellQuoted(value)
	if err != nil {
		return errors.New("broker client configuration has an invalid quoted value")
	}
	*destination = decoded
	seen[name] = true
	return nil
}

func validateParsedClient(client Client) (Client, error) {
	if client.AgentEndpoint == "" || client.SharedSecret == "" {
		return Client{}, errors.New("broker client configuration is incomplete")
	}
	if err := ValidateEndpoint(client.AgentEndpoint); err != nil {
		return Client{}, errors.New("broker client configuration has an invalid agent endpoint")
	}
	if client.GitEndpoint != "" {
		if err := ValidateGitEndpoint(client.GitEndpoint); err != nil {
			return Client{}, errors.New("broker client configuration has an invalid git endpoint")
		}
	}
	return client, nil
}

func decodeShellQuoted(value string) (string, error) {
	if len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' {
		return "", errors.New("value is not single quoted")
	}
	inner := value[1 : len(value)-1]
	const escapedQuote = `'\''`
	inner = strings.ReplaceAll(inner, escapedQuote, "\x00")
	if strings.Contains(inner, "'") || strings.ContainsRune(inner, '\x00') && strings.Contains(value, "\x00") {
		return "", errors.New("value contains invalid quoting")
	}
	return strings.ReplaceAll(inner, "\x00", "'"), nil
}
