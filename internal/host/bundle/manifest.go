// Package bundle owns atomic BrokerKit host release activation.
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/protocol/contract"
)

const APIVersion = "brokerkit.io/runtime-bundle/v1"

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Manifest pins one complete platform-specific BrokerKit host release.
type Manifest struct {
	APIVersion             string      `json:"api_version"`
	BundleID               string      `json:"bundle_id"`
	SourceCommit           string      `json:"source_commit"`
	OperatingSystem        string      `json:"operating_system"`
	Architecture           string      `json:"architecture"`
	OperatorContractDigest string      `json:"operator_contract_digest"`
	AgentContractDigest    string      `json:"agent_contract_digest"`
	Components             []Component `json:"components"`
}

// Component is one separately released process or companion executable.
type Component struct {
	Name                   string   `json:"name"`
	Source                 string   `json:"source"`
	Destination            string   `json:"destination"`
	SHA256                 string   `json:"sha256"`
	BuildID                string   `json:"build_id"`
	Role                   Role     `json:"role"`
	Services               []string `json:"services"`
	OperatorEndpoint       string   `json:"operator_endpoint,omitempty"`
	OperatorTokenFile      string   `json:"operator_token_file,omitempty"`
	OperatorContractDigest string   `json:"operator_contract_digest,omitempty"`
	AgentContractDigest    string   `json:"agent_contract_digest,omitempty"`
	StateFormatDigest      string   `json:"state_format_digest"`
	StateDir               string   `json:"state_dir,omitempty"`
	ReplaceState           bool     `json:"replace_state,omitempty"`
	Required               bool     `json:"required"`
}

// Role controls safe service stop and start ordering.
type Role string

const (
	RoleProvider  Role = "provider"
	RoleConsumer  Role = "consumer"
	RoleCompanion Role = "companion"
)

// Load verifies and strictly decodes a detached-signed manifest.
func Load(path, signaturePath, publicKeyPath string, development bool) (Manifest, []byte, error) {
	data, err := readBounded(path, 2*1024*1024)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("read runtime bundle manifest: %w", err)
	}
	if !development {
		if err := verifySignature(data, signaturePath, publicKeyPath); err != nil {
			return Manifest{}, nil, err
		}
	}
	var manifest Manifest
	if err := strictjson.Decode(data, &manifest, true); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode runtime bundle manifest: %w", err)
	}
	if err := manifest.Validate(development); err != nil {
		return Manifest{}, nil, err
	}
	return manifest, data, nil
}

// Validate checks the closed manifest's platform, protocol, and path invariants.
func (m Manifest) Validate(development bool) error {
	if err := m.validateIdentity(); err != nil {
		return err
	}
	if err := m.validatePlatform(); err != nil {
		return err
	}
	if err := m.validateContracts(); err != nil {
		return err
	}
	return m.validateComponents(development)
}

func (m Manifest) validateIdentity() error {
	if m.APIVersion != APIVersion {
		return fmt.Errorf("unsupported runtime bundle API %q", m.APIVersion)
	}
	if !identifierPattern.MatchString(m.BundleID) || !commitPattern.MatchString(m.SourceCommit) {
		return errors.New("runtime bundle identity is invalid")
	}
	return nil
}

func (m Manifest) validatePlatform() error {
	if m.OperatingSystem != runtime.GOOS || m.Architecture != runtime.GOARCH {
		return fmt.Errorf("runtime bundle targets %s/%s, host is %s/%s", m.OperatingSystem, m.Architecture, runtime.GOOS, runtime.GOARCH)
	}
	return nil
}

func (m Manifest) validateContracts() error {
	if m.OperatorContractDigest != contract.OperatorV1Digest || m.AgentContractDigest != contract.AgentV1Digest {
		return errors.New("runtime bundle protocol contract does not match this host command")
	}
	return nil
}

func (m Manifest) validateComponents(development bool) error {
	if len(m.Components) == 0 || len(m.Components) > 32 {
		return errors.New("runtime bundle must contain 1 to 32 components")
	}
	seenNames, seenDestinations, seenServices := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, component := range m.Components {
		if err := component.validate(development, m, seenNames, seenDestinations, seenServices); err != nil {
			return fmt.Errorf("component %q: %w", component.Name, err)
		}
	}
	return nil
}

func (c Component) validate(development bool, manifest Manifest, names, destinations, services map[string]bool) error {
	checks := []func() error{
		func() error { return c.registerIdentity(names, destinations) },
		c.validateDigests,
		c.validateState,
		func() error { return c.validateBuild(development) },
		func() error { return c.registerServices(services) },
		func() error { return c.validateOperator(manifest) },
		func() error { return c.validateProcess(manifest) },
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (c Component) registerIdentity(names, destinations map[string]bool) error {
	if !identifierPattern.MatchString(c.Name) || names[c.Name] {
		return errors.New("name is invalid or duplicated")
	}
	names[c.Name] = true
	if !safeRelative(c.Source) || !safeRelative(c.Destination) || destinations[c.Destination] {
		return errors.New("source or destination is unsafe or duplicated")
	}
	destinations[c.Destination] = true
	return nil
}

func (c Component) validateDigests() error {
	if !digestPattern.MatchString(c.SHA256) || !digestPattern.MatchString(c.StateFormatDigest) {
		return errors.New("artifact or state-format digest is invalid")
	}
	return nil
}

func (c Component) validateState() error {
	if !optionalAbsolutePath(c.StateDir) {
		return errors.New("state directory is unsafe")
	}
	if !optionalAbsolutePath(c.OperatorTokenFile) {
		return errors.New("operator token file is unsafe")
	}
	if c.ReplaceState && c.StateDir == "" {
		return errors.New("state replacement requires a state directory")
	}
	return nil
}

func optionalAbsolutePath(path string) bool {
	return path == "" || (filepath.IsAbs(path) && filepath.Clean(path) == path)
}

func (c Component) validateBuild(development bool) error {
	if !identifierPattern.MatchString(c.BuildID) || (!development && strings.HasPrefix(c.BuildID, "dev")) {
		return errors.New("release build identity is invalid")
	}
	if !slices.Contains([]Role{RoleProvider, RoleConsumer, RoleCompanion}, c.Role) {
		return errors.New("role is invalid")
	}
	return nil
}

func (c Component) registerServices(services map[string]bool) error {
	for _, service := range c.Services {
		if !identifierPattern.MatchString(service) || services[service] {
			return errors.New("service identity is invalid or duplicated")
		}
		services[service] = true
	}
	return nil
}

func (c Component) validateOperator(manifest Manifest) error {
	if c.OperatorEndpoint != "" && c.OperatorContractDigest != manifest.OperatorContractDigest {
		return errors.New("operator contract digest does not match bundle")
	}
	if (c.OperatorEndpoint == "") != (c.OperatorTokenFile == "") {
		return errors.New("operator endpoint and token file must be configured together")
	}
	if c.Required && c.Role == RoleProvider && c.OperatorEndpoint == "" {
		return errors.New("required provider has no authenticated operator endpoint")
	}
	return nil
}

func (c Component) validateProcess(manifest Manifest) error {
	if c.AgentContractDigest != "" && c.AgentContractDigest != manifest.AgentContractDigest {
		return errors.New("agent contract digest does not match bundle")
	}
	if c.Required && c.Role != RoleCompanion && len(c.Services) == 0 {
		return errors.New("required process component has no service")
	}
	return nil
}

func safeRelative(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != "." && !strings.HasPrefix(path, ".."+string(filepath.Separator))
}

func verifySignature(data []byte, signaturePath, publicKeyPath string) error {
	if signaturePath == "" || publicKeyPath == "" {
		return errors.New("runtime bundle signature and public key are required")
	}
	signatureText, err := readBounded(signaturePath, 1024)
	if err != nil {
		return fmt.Errorf("read runtime bundle signature: %w", err)
	}
	publicText, err := readBounded(publicKeyPath, 1024)
	if err != nil {
		return fmt.Errorf("read runtime bundle public key: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureText)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("runtime bundle signature is invalid")
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicText)))
	if err != nil || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, data, signature) {
		return errors.New("runtime bundle signature verification failed")
	}
	return nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- explicit operator input.
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if int64(len(data)) > maximum {
		return nil, errors.New("file exceeds size limit")
	}
	return data, errors.Join(readErr, closeErr)
}

func digestFile(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is constrained beneath a trusted root.
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", digest), nil
}
