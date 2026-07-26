package clientconfig

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const maxClientConfigBytes = 64 * 1024

// Client is one loaded private client V1 document.
type Client struct {
	ClientID      string
	AgentEndpoint string
	GitEndpoint   string
	SharedSecret  string
}

// Read loads the default generated client.json without shell evaluation.
func Read(homeDir, brokerName, _ string) (Client, error) {
	path, err := Path(homeDir, brokerName)
	if err != nil {
		return Client{}, err
	}
	return ReadPath(path, homeDir)
}

// ReadPath loads one explicit private client V1 document.
func ReadPath(path, homeDir string) (Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Client{}, errors.New("broker client configuration path must be absolute and clean")
	}
	if err := validateClientFile(path, homeDir); err != nil {
		return Client{}, err
	}
	file, err := os.Open(path) // #nosec G304 -- explicit path is validated and owner checked.
	if err != nil {
		return Client{}, fmt.Errorf("open broker client configuration: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxClientConfigBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return Client{}, errors.New("read broker client configuration")
	}
	if len(data) > maxClientConfigBytes {
		return Client{}, errors.New("broker client configuration is too large")
	}
	var value document
	if err := strictjson.Decode(data, &value, true); err != nil {
		return Client{}, errors.New("broker client configuration is invalid")
	}
	return validateDocument(value)
}

// Resolve chooses exactly one configuration source. The private client file is
// the production default; complete environment configuration remains available
// for isolated development and tests.
func Resolve(homeDir, brokerName, envPrefix string, getenv func(string) string) (Client, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	path, err := Path(homeDir, brokerName)
	if err != nil {
		return Client{}, err
	}
	_, statErr := os.Lstat(path)
	fileExists := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return Client{}, fmt.Errorf("inspect broker client configuration: %w", statErr)
	}
	prefix := normalizeEnvPrefix(envPrefix)
	environment := Client{
		ClientID:      strings.TrimSpace(getenv(prefix + "_CLIENT_ID")),
		AgentEndpoint: strings.TrimSpace(getenv(prefix + "_AGENT_ENDPOINT")),
		GitEndpoint:   strings.TrimSpace(getenv(prefix + "_GIT_ENDPOINT")),
		SharedSecret:  strings.TrimSpace(getenv(prefix + "_SHARED_SECRET")),
	}
	secretFile := strings.TrimSpace(getenv(prefix + "_SHARED_SECRET_FILE"))
	if secretFile != "" {
		if environment.SharedSecret != "" {
			return Client{}, errors.New("broker client environment has conflicting credential sources")
		}
		data, readErr := os.ReadFile(secretFile) // #nosec G304 -- explicit development credential source.
		if readErr != nil || len(data) > maxClientConfigBytes {
			return Client{}, errors.New("broker client environment credential could not be read")
		}
		environment.SharedSecret = strings.TrimSpace(string(data))
	}
	hasEnvironment := environment.ClientID != "" || environment.AgentEndpoint != "" || environment.GitEndpoint != "" || environment.SharedSecret != "" || secretFile != ""
	if fileExists && hasEnvironment {
		return Client{}, errors.New("broker client file and environment configuration conflict")
	}
	if fileExists {
		return ReadPath(path, homeDir)
	}
	if !hasEnvironment {
		return Client{}, errors.New("broker client configuration is unavailable; run setup client")
	}
	if environment.ClientID == "" {
		environment.ClientID = "development"
	}
	return validateClient(environment)
}

func validateClientFile(path, homeDir string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect broker client configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != clientFileMode {
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

func validateDocument(value document) (Client, error) {
	if value.APIVersion != APIVersion {
		return Client{}, errors.New("broker client configuration has an unsupported API")
	}
	return validateClient(Client{
		ClientID: value.ClientID, AgentEndpoint: value.AgentEndpoint,
		GitEndpoint: value.GitEndpoint, SharedSecret: value.SharedSecret,
	})
}

func validateClient(client Client) (Client, error) {
	if err := ValidateClientName(client.ClientID); err != nil {
		return Client{}, errors.New("broker client configuration has an invalid client ID")
	}
	if client.AgentEndpoint == "" || client.SharedSecret == "" {
		return Client{}, errors.New("broker client endpoint or credential is incomplete")
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
