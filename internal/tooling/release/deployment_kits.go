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
	"sort"
	"strings"

	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/protocol/contract"
)

const (
	deploymentReleaseAPIVersion = "unyolo.io/deployment-release-component/v1"
	sourceProviderAPIVersion    = "unyolo.io/deployment-source-provider/v1"
)

type deploymentReleaseComponent struct {
	APIVersion             string                             `json:"api_version"`
	Provider               string                             `json:"provider"`
	Name                   string                             `json:"name"`
	Binary                 string                             `json:"binary"`
	Destination            string                             `json:"destination"`
	Role                   bundle.Role                        `json:"role"`
	Services               []string                           `json:"services"`
	OperatorEndpoint       string                             `json:"operator_endpoint,omitempty"`
	OperatorTokenFile      string                             `json:"operator_token_file,omitempty"`
	AgentContract          bool                               `json:"agent_contract"`
	StateFormatDigest      string                             `json:"state_format_digest"`
	StateDir               string                             `json:"state_dir,omitempty"`
	ReplaceState           bool                               `json:"replace_state,omitempty"`
	Required               bool                               `json:"required"`
	Setup                  *bundle.SetupAdapter               `json:"setup,omitempty"`
	Profile                string                             `json:"profile,omitempty"`
	AdditionalProfileFiles []deploymentReleaseFile            `json:"additional_profile_files,omitempty"`
	PlatformFiles          map[string][]deploymentReleaseFile `json:"platform_files,omitempty"`
}

type deploymentReleaseFile struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type loadedDeploymentComponent struct {
	descriptor deploymentReleaseComponent
	directory  string
}

// SourceProvider describes one canonical release provider inside the source set.
// It binds the provider identifier to its owned runtime components and its signed
// ownership envelope.
type SourceProvider struct {
	APIVersion      string                   `json:"api_version"`
	ID              string                   `json:"id"`
	Components      []string                 `json:"components"`
	Ownership       bundle.OwnershipEnvelope `json:"ownership"`
	Profile         string                   `json:"profile"`
	Files           []string                 `json:"files,omitempty"`
	RenderArguments []string                 `json:"render_arguments"`
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
	if err := generateSourceSet(root, options, components, binaries, providers, privateKey, publicData, goos, goarch); err != nil {
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

// generateSourceSet writes one canonical, verified release source set. It emits
// the signed runtime manifest with every declared component, one provider
// directory per selectable provider, and empty integration and platform
// directories so setup callers can rely on a single stable layout.
func generateSourceSet(root string, options Options, components []loadedDeploymentComponent, binaries map[string]string, providers []string, privateKey ed25519.PrivateKey, publicData []byte, goos, goarch string) error {
	if err := prepareSourceSetLayout(root, goos); err != nil {
		return err
	}
	manifest := bundle.Manifest{
		APIVersion:             bundle.APIVersion,
		BundleID:               fmt.Sprintf("unyolo-%s-%s-%s", strings.TrimPrefix(options.Version, "v"), goos, goarch),
		SourceCommit:           options.SourceCommit,
		OperatingSystem:        goos,
		Architecture:           goarch,
		OperatorContractDigest: contract.OperatorV1Digest,
		AgentContractDigest:    contract.AgentV1Digest,
		SetupCapabilities:      canonicalSetupCapabilities(goos, providers),
	}
	for _, loaded := range components {
		runtimeComponent, err := releaseRuntimeComponent(loaded.descriptor, binaries[loaded.descriptor.Binary], options.Version)
		if err != nil {
			return err
		}
		manifest.Components = append(manifest.Components, runtimeComponent)
	}
	if err := writeRuntimeTrust(root, manifest, privateKey, publicData); err != nil {
		return err
	}
	for _, provider := range providers {
		if err := writeSourceProvider(root, provider, components, goos); err != nil {
			return err
		}
	}
	return nil
}

func prepareSourceSetLayout(root, goos string) error {
	directories := []string{
		"runtime",
		"providers",
		"integrations",
		filepath.Join("platform", goos),
	}
	for _, directory := range directories {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			return err
		}
	}
	return nil
}

func canonicalSetupCapabilities(goos string, _ []string) bundle.SetupCapabilities {
	capabilities := bundle.SetupCapabilities{}
	switch goos {
	case "linux":
		capabilities.NativeServiceBackend = "systemd"
		capabilities.Features = []string{"native_service", "local_accounts", "local_socket"}
	case "darwin":
		capabilities.NativeServiceBackend = "launchd"
	}
	return capabilities
}

//nolint:cyclop // Source-provider assembly rejects every unsafe or duplicated release input.
func writeSourceProvider(root, provider string, components []loadedDeploymentComponent, goos string) error {
	providerRoot := filepath.Join(root, "providers", provider)
	if err := os.MkdirAll(providerRoot, 0o700); err != nil {
		return err
	}
	var (
		descriptor    SourceProvider
		primary       loadedDeploymentComponent
		primaryFound  bool
		componentIDs  []string
		trackedFiles  = map[string]bool{}
		providerFiles []string
	)
	descriptor.APIVersion = sourceProviderAPIVersion
	descriptor.ID = provider
	for _, loaded := range components {
		if loaded.descriptor.Provider != provider {
			continue
		}
		componentIDs = append(componentIDs, loaded.descriptor.Name)
		if loaded.descriptor.Name == provider {
			primary, primaryFound = loaded, true
		}
	}
	if !primaryFound {
		return fmt.Errorf("provider %q has no primary component", provider)
	}
	sort.Strings(componentIDs)
	descriptor.Components = componentIDs
	descriptor.Ownership = primary.descriptor.Setup.Ownership
	descriptor.Profile = "profile.json"
	descriptor.RenderArguments = []string{"setup-component-render"}
	if err := copyReleaseData(filepath.Join(primary.directory, primary.descriptor.Profile), filepath.Join(providerRoot, "profile.json"), 0o600); err != nil {
		return err
	}
	files := append([]deploymentReleaseFile(nil), primary.descriptor.AdditionalProfileFiles...)
	files = append(files, primary.descriptor.PlatformFiles[goos]...)
	for _, file := range files {
		if trackedFiles[file.Destination] {
			return fmt.Errorf("provider %q duplicates static file %q", provider, file.Destination)
		}
		trackedFiles[file.Destination] = true
		source := filepath.Join(primary.directory, file.Source)
		destination := filepath.Join(providerRoot, filepath.FromSlash(file.Destination))
		if err := copyReleaseData(source, destination, 0o600); err != nil {
			return err
		}
		providerFiles = append(providerFiles, file.Destination)
	}
	sort.Strings(providerFiles)
	descriptor.Files = providerFiles
	data, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		return err
	}
	return writeReleaseData(filepath.Join(providerRoot, "source.json"), append(data, '\n'), 0o600)
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
	if err := validatePlatformFiles(value.PlatformFiles); err != nil {
		return err
	}
	names[value.Name] = true
	return nil
}

func validatePlatformFiles(values map[string][]deploymentReleaseFile) error {
	supported := map[string]bool{"linux": true, "darwin": true}
	for goos, files := range values {
		if !supported[goos] {
			return fmt.Errorf("platform_files uses unsupported target %q", goos)
		}
		if err := validateAdditionalProfileFiles(files); err != nil {
			return err
		}
	}
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
		if !safeArchivePath(file.Source) || !safeArchivePath(file.Destination) {
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

func releaseRuntimeComponent(value deploymentReleaseComponent, binary, version string) (bundle.Component, error) {
	artifactDigest, err := digestReleaseFile(binary)
	if err != nil {
		return bundle.Component{}, err
	}
	component := bundle.Component{
		Name: value.Name, Source: filepath.ToSlash(filepath.Join("artifacts", value.Binary)), Destination: value.Destination, SHA256: artifactDigest,
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

func writeRuntimeTrust(root string, manifest bundle.Manifest, privateKey ed25519.PrivateKey, publicData []byte) error {
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
		if err := writeReleaseData(filepath.Join(root, "runtime", file.name), file.data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func digestReleaseFile(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- generated native binary path.
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data)), nil
}

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
