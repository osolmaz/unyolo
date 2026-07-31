package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/protocol/contract"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: pack ROOT ADAPTER")
	}
	root, adapter := os.Args[1], os.Args[2]
	must(os.MkdirAll(filepath.Join(root, "runtime"), 0o700))
	must(os.MkdirAll(filepath.Join(root, "artifacts"), 0o700))
	must(os.MkdirAll(filepath.Join(root, "components"), 0o700))
	must(os.MkdirAll(filepath.Join(root, "files"), 0o700))
	adapterData, err := os.ReadFile(adapter)
	must(err)
	must(os.WriteFile(filepath.Join(root, "artifacts", "fake"), adapterData, 0o700))
	configData := []byte("{\"enabled\":true}\n")
	must(os.WriteFile(filepath.Join(root, "files", "config.json"), configData, 0o600))

	manifest := bundle.Manifest{
		APIVersion: bundle.APIVersion, BundleID: "e2e-bundle", SourceCommit: strings.Repeat("a", 40),
		OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH,
		OperatorContractDigest: contract.OperatorV1Digest, AgentContractDigest: contract.AgentV1Digest,
		Components: []bundle.Component{{
			Name: "fake", Source: "artifacts/fake", Destination: "bin/fake", SHA256: digest(adapterData),
			BuildID: "e2e", Role: bundle.RoleCompanion, Services: []string{}, StateFormatDigest: digest([]byte("state")), Required: false,
			Setup: &bundle.SetupAdapter{
				Protocol: "unyolo.io/setup-component/v1", Arguments: []string{"setup-component"},
				Ownership: bundle.OwnershipEnvelope{
					Paths: []string{"/etc/unyolo-e2e", "/var/lib/unyolo-e2e", "/proc/unyolo-e2e", "/var/lib/unyolo-agent/.config/fake-broker/client.json"}, Services: []string{},
					Accounts: []string{"unyolo-e2e"}, Groups: []string{"unyolo-e2e", "unyolo-e2e-agent"},
				},
			},
		}},
	}
	manifestData := marshal(manifest)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	must(os.WriteFile(filepath.Join(root, "runtime", "manifest.json"), manifestData, 0o600))
	must(os.WriteFile(filepath.Join(root, "runtime", "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestData))+"\n"), 0o600))
	must(os.WriteFile(filepath.Join(root, "runtime", "release.pub"), []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o600))
	activation := manifest
	activation.BundleID = manifest.BundleID + "-fake"
	must(os.WriteFile(filepath.Join(root, "runtime", "activation.json"), marshal(activation), 0o600))

	componentProfile := component.Profile{
		APIVersion: "unyolo.io/fake-deployment/v1",
		Accounts:   []component.Account{{Name: "unyolo-e2e", Group: "unyolo-e2e", Home: "/var/lib/unyolo-e2e", Shell: "/usr/sbin/nologin"}},
		Groups:     []component.Group{{Name: "unyolo-e2e"}, {Name: "unyolo-e2e-agent", Members: []string{"unyolo-agent"}}},
		Directories: []component.Directory{
			{ID: "config", Destination: "/etc/unyolo-e2e", Mode: 0o750, Owner: "root", Group: "unyolo-e2e"},
			{ID: "state", Destination: "/var/lib/unyolo-e2e", Mode: 0o700, Owner: "unyolo-e2e", Group: "unyolo-e2e"},
		},
		Files: []component.ManagedFile{{
			ID: "config-file", Source: component.Reference{Path: "files/config.json", SHA256: digest(configData)},
			Destination: "/etc/unyolo-e2e/config.json", Mode: 0o640, Owner: "root", Group: "unyolo-e2e",
		}},
		Credentials: []component.Credential{{
			Slot: "e2e-token", Destination: "/etc/unyolo-e2e/token", Mode: 0o640,
			Owner: "root", Group: "unyolo-e2e", Encoding: "raw",
		}},
		Clients: []component.Client{{
			AgentID: "agent", BrokerName: "fake-broker", EnvPrefix: "FAKE_BROKER",
			SecretSlot: "e2e-token", Endpoint: "unix:///tmp/fake-broker.sock",
		}},
		Services: []string{},
	}
	must(os.WriteFile(filepath.Join(root, "components", "fake.json"), marshal(componentProfile), 0o600))
	deployment := profile.Deployment{
		APIVersion: profile.APIVersion, Name: "e2e-host",
		Runtime: profile.Runtime{
			Manifest: profile.Reference{Path: "runtime/manifest.json", SHA256: zeroDigest()}, Signature: profile.Reference{Path: "runtime/manifest.sig", SHA256: zeroDigest()},
			PublicKey: profile.Reference{Path: "runtime/release.pub", SHA256: zeroDigest()}, Activation: profile.Reference{Path: "runtime/activation.json", SHA256: zeroDigest()},
		},
		Agents: []profile.Agent{{
			ID: "agent", ClientID: "agent", UnixUser: "unyolo-agent", AccountMode: "managed",
			Home: "/var/lib/unyolo-agent", Shell: "/usr/sbin/nologin", ComponentIDs: []string{"fake"},
		}},
		Operators:  []profile.Operator{{ID: "operator", UnixUser: "operator"}},
		Components: []profile.Component{{ID: "fake", Profile: profile.Reference{Path: "components/fake.json", SHA256: zeroDigest()}}},
	}
	must(os.WriteFile(filepath.Join(root, profile.EntryFilename), marshal(deployment), 0o600))
	must(profile.Lock(root, false))
}

func marshal(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	must(err)
	return append(data, '\n')
}

func digest(value []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(value)) }
func zeroDigest() string         { return "sha256:" + strings.Repeat("0", 64) }
func must(err error) {
	if err != nil {
		panic(err)
	}
}
