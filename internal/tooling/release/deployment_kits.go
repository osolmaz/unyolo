package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/protocol/contract"
)

const deploymentReleaseAPIVersion = "unyolo.io/deployment-release-component/v1"

type deploymentReleaseComponent struct {
	APIVersion             string                  `json:"api_version"`
	Provider               string                  `json:"provider"`
	Name                   string                  `json:"name"`
	Binary                 string                  `json:"binary"`
	Destination            string                  `json:"destination"`
	Role                   bundle.Role             `json:"role"`
	Services               []string                `json:"services"`
	OperatorEndpoint       string                  `json:"operator_endpoint,omitempty"`
	OperatorTokenFile      string                  `json:"operator_token_file,omitempty"`
	AgentContract          bool                    `json:"agent_contract"`
	StateFormatDigest      string                  `json:"state_format_digest"`
	StateDir               string                  `json:"state_dir,omitempty"`
	ReplaceState           bool                    `json:"replace_state,omitempty"`
	Required               bool                    `json:"required"`
	Setup                  *bundle.SetupAdapter    `json:"setup,omitempty"`
	Profile                string                  `json:"profile,omitempty"`
	AdditionalProfileFiles []deploymentReleaseFile `json:"additional_profile_files,omitempty"`
}

type deploymentReleaseFile struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type loadedDeploymentComponent struct {
	descriptor deploymentReleaseComponent
	directory  string
}

func generateDeploymentKits(work string, options Options, binaries map[string]string, goos, goarch string) (map[string]string, map[string]bool, error) {
	components, err := loadDeploymentComponents(options, binaries)
	if err != nil {
		return nil, nil, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	root := filepath.Join(work, "deployment-kits")
	runtimeBinaries, err := copyRuntimeArtifacts(root, components, binaries)
	if err != nil {
		return nil, nil, err
	}
	providers := selectableProviders(components)
	if err := validateProviderCatalogFiles(options.ExtraFiles, providers); err != nil {
		return nil, nil, err
	}
	publicData := []byte(base64.StdEncoding.EncodeToString(publicKey) + "\n")
	if err := generateAllDeploymentTemplates(root, options, components, binaries, providers, privateKey, publicData, goos, goarch); err != nil {
		return nil, nil, err
	}
	files, err := collectGeneratedFiles(root, "deployment-kits")
	return files, runtimeBinaries, err
}

func copyRuntimeArtifacts(root string, components []loadedDeploymentComponent, binaries map[string]string) (map[string]bool, error) {
	runtimeBinaries := map[string]bool{}
	for _, component := range components {
		name := component.descriptor.Binary
		if runtimeBinaries[name] {
			continue
		}
		runtimeBinaries[name] = true
		if err := copyReleaseData(binaries[name], filepath.Join(root, "artifacts", name), 0o700); err != nil {
			return nil, err
		}
	}
	return runtimeBinaries, nil
}

func generateAllDeploymentTemplates(root string, options Options, components []loadedDeploymentComponent, binaries map[string]string, providers []string, privateKey ed25519.PrivateKey, publicData []byte, goos, goarch string) error {
	for _, selected := range providerSelections(providers) {
		if err := generateDeploymentTemplate(root, options, components, binaries, selected, privateKey, publicData, goos, goarch); err != nil {
			return err
		}
	}
	return nil
}

func loadDeploymentComponents(options Options, binaries map[string]string) ([]loadedDeploymentComponent, error) {
	result := make([]loadedDeploymentComponent, 0, len(options.DeploymentComponents))
	seenNames := map[string]bool{}
	selectable := map[string]bool{}
	for _, configured := range options.DeploymentComponents {
		path := configured
		if !filepath.IsAbs(path) {
			path = filepath.Join(options.Directory, path)
		}
		path = filepath.Clean(path)
		data, err := os.ReadFile(path) // #nosec G304 -- explicit release descriptor input.
		if err != nil {
			return nil, err
		}
		var descriptor deploymentReleaseComponent
		if err := strictjson.Decode(data, &descriptor, true); err != nil {
			return nil, fmt.Errorf("decode deployment release component %q: %w", configured, err)
		}
		if err := validateDeploymentComponent(descriptor, binaries, seenNames, selectable); err != nil {
			return nil, fmt.Errorf("deployment release component %q: %w", configured, err)
		}
		result = append(result, loadedDeploymentComponent{descriptor: descriptor, directory: filepath.Dir(path)})
	}
	if len(selectable) == 0 || len(selectable) > 8 {
		return nil, errors.New("deployment release requires 1 to 8 selectable providers")
	}
	return result, nil
}

func validateDeploymentComponent(value deploymentReleaseComponent, binaries map[string]string, names, selectable map[string]bool) error {
	if err := validateComponentIdentity(value, names); err != nil {
		return err
	}
	if err := validateComponentRuntime(value, binaries); err != nil {
		return err
	}
	if err := validateComponentProfile(value, selectable); err != nil {
		return err
	}
	if err := validateAdditionalProfileFiles(value.AdditionalProfileFiles); err != nil {
		return err
	}
	names[value.Name] = true
	return nil
}

func validateComponentIdentity(value deploymentReleaseComponent, names map[string]bool) error {
	if value.APIVersion != deploymentReleaseAPIVersion || !brokerNamePattern.MatchString(value.Provider) ||
		!brokerNamePattern.MatchString(value.Name) || names[value.Name] {
		return errors.New("component API, provider, or name is invalid")
	}
	return nil
}

func validateComponentRuntime(value deploymentReleaseComponent, binaries map[string]string) error {
	if !brokerNamePattern.MatchString(value.Binary) || binaries[value.Binary] == "" ||
		value.Destination == "" || value.StateFormatDigest == "" {
		return errors.New("component binary, destination, or state digest is invalid")
	}
	if (value.OperatorEndpoint == "") != (value.OperatorTokenFile == "") {
		return errors.New("component operator endpoint and token file must be configured together")
	}
	return nil
}

func validateComponentProfile(value deploymentReleaseComponent, selectable map[string]bool) error {
	if value.Name != value.Provider {
		if value.Profile != "" {
			return errors.New("provider companion must not declare a deployment profile")
		}
		return nil
	}
	if !safeArchivePath(value.Profile) || selectable[value.Provider] {
		return errors.New("selectable provider requires one unique profile")
	}
	selectable[value.Provider] = true
	return nil
}

func validateAdditionalProfileFiles(files []deploymentReleaseFile) error {
	for _, file := range files {
		if !safeArchivePath(file.Source) || !safeArchivePath(file.Destination) || file.Destination == profile.EntryFilename {
			return errors.New("additional profile file is invalid")
		}
	}
	return nil
}

func validateProviderCatalogFiles(files map[string]string, providers []string) error {
	catalog := map[string]bool{}
	for path := range files {
		if strings.HasPrefix(path, "providers/") && strings.HasSuffix(path, ".json") {
			catalog[strings.TrimSuffix(strings.TrimPrefix(path, "providers/"), ".json")] = true
		}
	}
	if len(catalog) != len(providers) {
		return errors.New("provider catalog and deployment components differ")
	}
	for _, provider := range providers {
		if !catalog[provider] {
			return fmt.Errorf("deployment provider %q has no release catalog entry", provider)
		}
	}
	return nil
}

func selectableProviders(components []loadedDeploymentComponent) []string {
	var result []string
	for _, component := range components {
		if component.descriptor.Name == component.descriptor.Provider {
			result = append(result, component.descriptor.Provider)
		}
	}
	slices.Sort(result)
	return result
}

func providerSelections(providers []string) [][]string {
	result := make([][]string, 0, (1<<len(providers))-1)
	for mask := 1; mask < 1<<len(providers); mask++ {
		var selected []string
		for index, provider := range providers {
			if mask&(1<<index) != 0 {
				selected = append(selected, provider)
			}
		}
		result = append(result, selected)
	}
	return result
}

func generateDeploymentTemplate(root string, options Options, components []loadedDeploymentComponent, binaries map[string]string, selected []string, privateKey ed25519.PrivateKey, publicData []byte, goos, goarch string) error {
	key := strings.Join(selected, "+")
	template := filepath.Join(root, "templates", key)
	if err := prepareDeploymentTemplate(template); err != nil {
		return err
	}
	wanted := make(map[string]bool, len(selected))
	for _, provider := range selected {
		wanted[provider] = true
	}
	manifest := bundle.Manifest{
		APIVersion: bundle.APIVersion,
		BundleID:     fmt.Sprintf("unyolo-%s-%s-%s-%s", strings.TrimPrefix(options.Version, "v"), goos, goarch, key),
		SourceCommit: options.SourceCommit, OperatingSystem: goos, Architecture: goarch,
		OperatorContractDigest: contract.OperatorV1Digest, AgentContractDigest: contract.AgentV1Digest,
	}
	if goos == "linux" {
		manifest.SetupCapabilities = bundle.SetupCapabilities{
			NativeServiceBackend: "systemd",
			Features: []string{"native_service", "local_accounts", "local_socket"},
		}
	}
	deployment := profile.Deployment{
		APIVersion: profile.APIVersion, Name: "unyolo-template",
		Runtime: profile.Runtime{
			Manifest:  profile.Reference{Path: "runtime/manifest.json", SHA256: zeroReleaseDigest()},
			Signature: profile.Reference{Path: "runtime/manifest.sig", SHA256: zeroReleaseDigest()},
			PublicKey: profile.Reference{Path: "runtime/release.pub", SHA256: zeroReleaseDigest()},
		},
		Agents: []profile.Agent{{
			ID: "agent", ClientID: "agent",
			Target:       profile.AgentTarget{Kind: "local_account", Isolation: "separate", AccountMode: "managed", UnixUser: "unyolo-agent", Home: "/var/lib/unyolo-agent", Shell: "/usr/sbin/nologin"},
			ComponentIDs: append([]string(nil), selected...),
		}},
		Operators: []profile.Operator{{ID: "operator", UnixUser: "operator"}},
	}
	for _, loaded := range components {
		if err := appendDeploymentTemplateComponent(template, options.Version, loaded, binaries, wanted, &manifest, &deployment); err != nil {
			return err
		}
	}
	if err := writeRuntimeTrust(template, manifest, privateKey, publicData); err != nil {
		return err
	}
	if err := writeDeploymentEntry(template, deployment); err != nil {
		return err
	}
	return profile.Lock(template, false)
}

func prepareDeploymentTemplate(template string) error {
	for _, directory := range []string{"runtime", "components"} {
		if err := os.MkdirAll(filepath.Join(template, directory), 0o700); err != nil {
			return err
		}
	}
	return nil
}

func appendDeploymentTemplateComponent(template, version string, loaded loadedDeploymentComponent, binaries map[string]string, wanted map[string]bool, manifest *bundle.Manifest, deployment *profile.Deployment) error {
	value := loaded.descriptor
	if !wanted[value.Provider] {
		return nil
	}
	runtimeComponent, err := releaseRuntimeComponent(value, binaries[value.Binary], version)
	if err != nil {
		return err
	}
	manifest.Components = append(manifest.Components, runtimeComponent)
	if value.Name != value.Provider {
		return nil
	}
	return appendProviderProfile(template, loaded, deployment)
}

func releaseRuntimeComponent(value deploymentReleaseComponent, binary, version string) (bundle.Component, error) {
	artifactDigest, err := digestReleaseFile(binary)
	if err != nil {
		return bundle.Component{}, err
	}
	component := bundle.Component{
		Name: value.Name, Source: value.Binary, Destination: value.Destination, SHA256: artifactDigest,
		BuildID: version, Role: value.Role, Services: append([]string(nil), value.Services...),
		OperatorEndpoint: value.OperatorEndpoint, OperatorTokenFile: value.OperatorTokenFile,
		StateFormatDigest: value.StateFormatDigest, StateDir: value.StateDir, ReplaceState: value.ReplaceState,
		Required: value.Required, Setup: value.Setup,
	}
	if value.AgentContract {
		component.AgentContractDigest = contract.AgentV1Digest
	}
	if value.OperatorEndpoint != "" {
		component.OperatorContractDigest = contract.OperatorV1Digest
	}
	return component, nil
}

func appendProviderProfile(template string, loaded loadedDeploymentComponent, deployment *profile.Deployment) error {
	value := loaded.descriptor
	profileDestination := filepath.Join(template, "components", value.Provider+".json")
	if err := copyReleaseData(filepath.Join(loaded.directory, value.Profile), profileDestination, 0o600); err != nil {
		return err
	}
	for _, file := range value.AdditionalProfileFiles {
		source := filepath.Join(loaded.directory, file.Source)
		destination := filepath.Join(template, filepath.FromSlash(file.Destination))
		if err := copyReleaseData(source, destination, 0o600); err != nil {
			return err
		}
	}
	deployment.Components = append(deployment.Components, profile.Component{
		ID: value.Provider, Profile: profile.Reference{Path: "components/" + value.Provider + ".json", SHA256: zeroReleaseDigest()},
	})
	return nil
}

func writeRuntimeTrust(template string, manifest bundle.Manifest, privateKey ed25519.PrivateKey, publicData []byte) error {
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestData = append(manifestData, '\n')
	files := []struct {
		name string
		data []byte
	}{
		{"manifest.json", manifestData},
		{"manifest.sig", []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestData)) + "\n")},
		{"release.pub", publicData},
	}
	for _, file := range files {
		if err := writeReleaseData(filepath.Join(template, "runtime", file.name), file.data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeDeploymentEntry(template string, deployment profile.Deployment) error {
	data, err := json.MarshalIndent(deployment, "", "  ")
	if err != nil {
		return err
	}
	return writeReleaseData(filepath.Join(template, profile.EntryFilename), append(data, '\n'), 0o600)
}

func digestReleaseFile(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- generated native binary path.
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data)), nil
}

func zeroReleaseDigest() string { return "sha256:" + strings.Repeat("0", 64) }

func writeReleaseData(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// #nosec G703 -- path is derived from validated release descriptors beneath a private generator root.
	return os.WriteFile(path, data, mode)
}

func copyReleaseData(source, destination string, mode os.FileMode) error {
	data, err := os.ReadFile(source) // #nosec G304 -- provider-owned release descriptor source.
	if err != nil {
		return err
	}
	return writeReleaseData(destination, data, mode)
}

func collectGeneratedFiles(root, prefix string) (map[string]string, error) {
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("generated deployment kit contains a non-regular file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(prefix, relative))
		if !safeArchivePath(name) {
			return fmt.Errorf("generated deployment archive path %q is unsafe", name)
		}
		result[name] = path
		return nil
	})
	return result, err
}

func safeArchivePath(path string) bool {
	return path != "" && path != "." && filepath.ToSlash(filepath.Clean(path)) == path && !filepath.IsAbs(path) &&
		!strings.HasPrefix(path, "../") && !strings.Contains(path, "/../") && !strings.Contains(path, "/./") && archivePathPattern.MatchString(path)
}
