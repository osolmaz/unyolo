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

	"github.com/osolmaz/brokerkit/deployment/component"
	"github.com/osolmaz/brokerkit/deployment/profile"
	"github.com/osolmaz/brokerkit/internal/host/bundle"
	"github.com/osolmaz/brokerkit/protocol/contract"
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
				Protocol: "brokerkit.io/setup-component/v1", Arguments: []string{"setup-component"},
				Ownership: bundle.OwnershipEnvelope{
					Paths: []string{"/etc/brokerkit-e2e", "/var/lib/brokerkit-e2e", "/proc/brokerkit-e2e"}, Services: []string{},
					Accounts: []string{"brokerkit-e2e"}, Groups: []string{"brokerkit-e2e", "brokerkit-e2e-agent"},
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

	componentProfile := component.Profile{
		APIVersion: "brokerkit.io/fake-deployment/v1",
		Accounts:   []component.Account{{Name: "brokerkit-e2e", Group: "brokerkit-e2e", Home: "/var/lib/brokerkit-e2e", Shell: "/usr/sbin/nologin"}},
		Groups:     []component.Group{{Name: "brokerkit-e2e"}, {Name: "brokerkit-e2e-agent", Members: []string{"brokerkit-agent"}}},
		Directories: []component.Directory{
			{ID: "config", Destination: "/etc/brokerkit-e2e", Mode: 0o750, Owner: "root", Group: "brokerkit-e2e"},
			{ID: "state", Destination: "/var/lib/brokerkit-e2e", Mode: 0o700, Owner: "brokerkit-e2e", Group: "brokerkit-e2e"},
		},
		Files: []component.ManagedFile{{
			ID: "config-file", Source: component.Reference{Path: "files/config.json", SHA256: digest(configData)},
			Destination: "/etc/brokerkit-e2e/config.json", Mode: 0o640, Owner: "root", Group: "brokerkit-e2e",
		}},
		Credentials: []component.Credential{{
			Slot: "e2e-token", Destination: "/etc/brokerkit-e2e/token", Mode: 0o640,
			Owner: "root", Group: "brokerkit-e2e", Encoding: "raw",
		}},
		Services: []string{},
	}
	must(os.WriteFile(filepath.Join(root, "components", "fake.json"), marshal(componentProfile), 0o600))
	deployment := profile.Deployment{
		APIVersion: profile.APIVersion, Name: "e2e-host",
		Runtime: profile.Runtime{
			Manifest:  profile.Reference{Path: "runtime/manifest.json", SHA256: zeroDigest()},
			Signature: profile.Reference{Path: "runtime/manifest.sig", SHA256: zeroDigest()},
			PublicKey: profile.Reference{Path: "runtime/release.pub", SHA256: zeroDigest()},
		},
		Agents: []profile.Agent{{
			ID: "agent", ClientID: "agent", UnixUser: "brokerkit-agent", AccountMode: "managed",
			Home: "/var/lib/brokerkit-agent", Shell: "/usr/sbin/nologin", ComponentIDs: []string{"fake"},
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
