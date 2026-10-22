package clientconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/transport/endpoint"
)

// OperatorAPIVersion is the private operator client document contract.
const OperatorAPIVersion = "unyolo.io/operator-client/v1"

const operatorFileName = "operator.json"

// Operator is one operator client document. A provider writes it into the home
// of a managed approver, such as the Telegram owner, so that the approver can
// reach the provider's Operator V1 API with its own credential.
type Operator struct {
	Endpoint string
	Secret   string
}

type operatorDocument struct {
	APIVersion       string `json:"api_version"`
	OperatorEndpoint string `json:"operator_endpoint"`
	SharedSecret     string `json:"shared_secret"`
}

// OperatorPath returns <home>/.config/<broker>/operator.json.
func OperatorPath(homeDir, brokerName string) (string, error) {
	path, err := Path(homeDir, brokerName)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), operatorFileName), nil
}

// RenderOperator returns the closed operator client V1 JSON document.
func RenderOperator(value Operator) ([]byte, error) {
	if err := value.validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(operatorDocument{
		APIVersion: OperatorAPIVersion, OperatorEndpoint: value.Endpoint, SharedSecret: value.Secret,
	}, "", "  ")
	return append(data, '\n'), err
}

// WriteOperatorForHomeOwner writes the operator document into homeDir and,
// when running as root, gives it and its directories to the home owner.
func WriteOperatorForHomeOwner(homeDir, brokerName string, value Operator) (string, error) {
	path, err := OperatorPath(homeDir, brokerName)
	if err != nil {
		return "", err
	}
	body, err := RenderOperator(value)
	if err != nil {
		return "", err
	}
	defer clear(body)
	if err := writeHomeConfigSafely(homeDir, brokerName, operatorFileName, body); err != nil {
		return "", err
	}
	return path, nil
}

// ReadOperatorPath loads one operator document. The file must be a regular
// owner-only file that belongs to ownerUID.
func ReadOperatorPath(path string, ownerUID int) (Operator, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Operator{}, errors.New("operator client path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Operator{}, fmt.Errorf("inspect operator client: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != clientFileMode || !ok || int(stat.Uid) != ownerUID {
		return Operator{}, errors.New("operator client must be a regular owner-only file of its approver")
	}
	file, err := os.Open(path) // #nosec G304 -- explicit path is validated and owner checked.
	if err != nil {
		return Operator{}, fmt.Errorf("open operator client: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxClientConfigBytes+1))
	closeErr := file.Close()
	defer clear(data)
	if readErr != nil || closeErr != nil || len(data) > maxClientConfigBytes {
		return Operator{}, errors.New("read operator client")
	}
	var document operatorDocument
	if err := strictjson.Decode(data, &document, true); err != nil || document.APIVersion != OperatorAPIVersion {
		return Operator{}, errors.New("operator client is invalid")
	}
	value := Operator{Endpoint: document.OperatorEndpoint, Secret: document.SharedSecret}
	if err := value.validate(); err != nil {
		return Operator{}, err
	}
	return value, nil
}

func (value Operator) validate() error {
	parsed, err := endpoint.Parse(value.Endpoint, endpoint.ParseOptions{})
	if err != nil || parsed.Scheme() != endpoint.SchemeUnix && (parsed.Scheme() != endpoint.SchemeTCP || parsed.Exposure() != endpoint.ExposureLoopback) {
		return errors.New("operator endpoint must be a local socket or loopback TCP")
	}
	if value.Secret == "" || value.Secret != strings.TrimSpace(value.Secret) || strings.ContainsAny(value.Secret, "\x00\r\n") {
		return errors.New("operator credential is invalid")
	}
	return nil
}
