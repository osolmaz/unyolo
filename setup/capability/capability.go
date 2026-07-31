// Package capability intersects signed installer support with read-only host probes.
package capability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/internal/host/bundle"
)

const APIVersion = "unyolo.io/setup-capabilities/v1"

type Feature string

const (
	FeatureNativeService  Feature = "native_service"
	FeatureLocalAccounts  Feature = "local_accounts"
	FeatureLocalSocket    Feature = "local_socket"
	FeatureTLS            Feature = "tls"
	FeatureRemotePairing  Feature = "remote_pairing"
	FeatureDockerAgent    Feature = "docker_agent"
	FeatureDockerServices Feature = "docker_services"
)

var knownFeatures = []Feature{
	FeatureNativeService,
	FeatureLocalAccounts,
	FeatureLocalSocket,
	FeatureTLS,
	FeatureRemotePairing,
	FeatureDockerAgent,
	FeatureDockerServices,
}

// Probe performs read-only checks for one signed feature.
type Probe interface {
	Available(Feature, string) bool
}

// Snapshot is the exact capability set used by one setup session.
type Snapshot struct {
	APIVersion      string    `json:"api_version"`
	OperatingSystem string    `json:"operating_system"`
	Architecture    string    `json:"architecture"`
	ServiceBackend  string    `json:"service_backend,omitempty"`
	Features        []Feature `json:"features"`
	Integrations    []string  `json:"integrations"`
	Digest          string    `json:"digest"`
}

func Resolve(manifest bundle.Manifest, probe Probe) (Snapshot, error) {
	if manifest.OperatingSystem == "" || manifest.Architecture == "" || probe == nil {
		return Snapshot{}, errors.New("capability inputs are invalid")
	}
	declared := map[Feature]bool{}
	for _, raw := range manifest.SetupCapabilities.Features {
		feature := Feature(raw)
		if !slices.Contains(knownFeatures, feature) {
			return Snapshot{}, fmt.Errorf("release declares unknown setup capability %q", raw)
		}
		declared[feature] = true
	}
	features := make([]Feature, 0, len(declared))
	for _, feature := range knownFeatures {
		if declared[feature] && probe.Available(feature, manifest.SetupCapabilities.NativeServiceBackend) {
			features = append(features, feature)
		}
	}
	integrations := append([]string(nil), manifest.SetupCapabilities.Integrations...)
	slices.Sort(integrations)
	value := Snapshot{
		APIVersion: APIVersion, OperatingSystem: manifest.OperatingSystem, Architecture: manifest.Architecture,
		ServiceBackend: manifest.SetupCapabilities.NativeServiceBackend, Features: features, Integrations: integrations,
	}
	digest, err := value.calculateDigest()
	if err != nil {
		return Snapshot{}, err
	}
	value.Digest = digest
	return value, nil
}

func (value Snapshot) Has(feature Feature) bool { return slices.Contains(value.Features, feature) }

func (value Snapshot) Validate() error {
	if value.APIVersion != APIVersion || value.OperatingSystem == "" || value.Architecture == "" || value.Digest == "" {
		return errors.New("capability snapshot identity is invalid")
	}
	for _, feature := range value.Features {
		if !slices.Contains(knownFeatures, feature) {
			return errors.New("capability snapshot contains an unknown feature")
		}
	}
	digest, err := value.calculateDigest()
	if err != nil || digest != value.Digest {
		return errors.New("capability snapshot digest is invalid")
	}
	return nil
}

func (value Snapshot) calculateDigest() (string, error) {
	value.Digest = ""
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data)), nil
}

// HostProbe is the production read-only host probe.
type HostProbe struct{}

func (HostProbe) Available(feature Feature, serviceBackend string) bool {
	switch feature {
	case FeatureNativeService:
		return (runtime.GOOS == "linux" && serviceBackend == "systemd" && hasCommand("systemctl")) ||
			(runtime.GOOS == "darwin" && serviceBackend == "launchd" && hasCommand("launchctl"))
	case FeatureLocalAccounts:
		return (runtime.GOOS == "linux" && hasCommands("getent", "useradd", "userdel")) ||
			(runtime.GOOS == "darwin" && hasCommands("dscl", "dseditgroup"))
	case FeatureLocalSocket, FeatureTLS:
		return true
	case FeatureRemotePairing:
		return true
	case FeatureDockerAgent, FeatureDockerServices:
		return dockerComposeAvailable()
	default:
		return false
	}
}

func hasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func hasCommands(names ...string) bool {
	for _, name := range names {
		if !hasCommand(name) {
			return false
		}
	}
	return true
}

func dockerComposeAvailable() bool {
	if !hasCommand("docker") {
		return false
	}
	output, err := exec.CommandContext(context.Background(), "docker", "compose", "version", "--short").Output()
	return err == nil && strings.TrimSpace(string(output)) != ""
}
