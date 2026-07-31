// Package profile loads immutable, digest-bound unYOLO deployment packs.
package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

const (
	APIVersion      = "unyolo.io/host-deployment/v1"
	EntryFilename   = "deployment.json"
	MaxEntryBytes   = 1024 * 1024
	MaxReferenced   = 16 * 1024 * 1024
	MaxReferences   = 256
	MaxAgents       = 32
	MaxOperators    = 32
	MaxComponents   = 32
	MaxIntegrations = 32
)

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Reference binds one relative regular file to its exact bytes.
type Reference struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Runtime references one signed runtime bundle.
type Runtime struct {
	Manifest   Reference `json:"manifest"`
	Signature  Reference `json:"signature"`
	PublicKey  Reference `json:"public_key"`
	Activation Reference `json:"activation"`
}

// Agent binds a unYOLO client identity to one local, container, or remote target.
type Agent struct {
	ID           string      `json:"id"`
	ClientID     string      `json:"client_id"`
	Target       AgentTarget `json:"target"`
	ComponentIDs []string    `json:"component_ids"`
}

// AgentTarget is the closed deployment target union.
type AgentTarget struct {
	Kind             string `json:"kind"`
	Isolation        string `json:"isolation"`
	AccountMode      string `json:"account_mode,omitempty"`
	UnixUser         string `json:"unix_user,omitempty"`
	Home             string `json:"home,omitempty"`
	Shell            string `json:"shell,omitempty"`
	ProjectDirectory string `json:"project_directory,omitempty"`
	Service          string `json:"service,omitempty"`
	RemoteName       string `json:"remote_name,omitempty"`
}

// Operator binds an existing trusted Unix account.
type Operator struct {
	ID       string `json:"id"`
	UnixUser string `json:"unix_user"`
}

// Component points to one provider-owned setup profile.
type Component struct {
	ID       string     `json:"id"`
	Profile  Reference  `json:"profile"`
	Metadata *Reference `json:"render_metadata,omitempty"`
}

// Integration points to one client integration profile.
type Integration struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	AgentID string    `json:"agent_id"`
	Profile Reference `json:"profile"`
}

// Deployment is the closed deployment.json document.
type Deployment struct {
	APIVersion         string        `json:"api_version"`
	Name               string        `json:"name"`
	InstallationDigest string        `json:"installation_digest,omitempty"`
	SourceSetDigest    string        `json:"source_set_digest,omitempty"`
	Runtime            Runtime       `json:"runtime"`
	Agents             []Agent       `json:"agents"`
	Operators          []Operator    `json:"operators"`
	Components         []Component   `json:"components"`
	Integrations       []Integration `json:"integrations,omitempty"`
}

// File is one immutable referenced file.
type File struct {
	Path   string
	SHA256 string
	Data   []byte
}

// Snapshot is a complete immutable deployment pack view.
type Snapshot struct {
	Root          string
	Deployment    Deployment
	Files         map[string]File
	Digest        string
	Manifest      bundle.Manifest
	TrustManifest bundle.Manifest
}

// Load validates and snapshots a deployment pack.
func Load(root string) (Snapshot, error) {
	return load(root, true)
}

// LoadUnlocked validates structure while allowing stale digests. It is used
// only by profile locking.
func LoadUnlocked(root string) (Snapshot, error) {
	return load(root, false)
}

//nolint:cyclop // Loading is one fail-closed chain from pack permissions through nested digest verification.
func load(root string, verifyDigests bool) (Snapshot, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return Snapshot{}, fmt.Errorf("resolve deployment pack: %w", err)
	}
	if err := inspectAbsolutePath(absolute); err != nil {
		return Snapshot{}, fmt.Errorf("inspect deployment pack: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return Snapshot{}, fmt.Errorf("inspect deployment pack: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return Snapshot{}, errors.New("deployment pack root must be a real directory")
	}
	packRoot, err := os.OpenRoot(absolute)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open deployment pack: %w", err)
	}
	defer func() { _ = packRoot.Close() }()

	entry, err := readFile(packRoot, EntryFilename, MaxEntryBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read %s: %w", EntryFilename, err)
	}
	var deployment Deployment
	if err := strictjson.Decode(entry, &deployment, true); err != nil {
		return Snapshot{}, fmt.Errorf("decode %s: %w", EntryFilename, err)
	}
	if err := deployment.Validate(); err != nil {
		return Snapshot{}, err
	}

	files := make(map[string]File)
	queue := append([]Reference(nil), deployment.references()...)
	for len(queue) > 0 {
		reference := queue[0]
		queue = queue[1:]
		if existing, exists := files[reference.Path]; exists {
			if verifyDigests && existing.SHA256 != reference.SHA256 {
				return Snapshot{}, fmt.Errorf("referenced file %q has conflicting digests", reference.Path)
			}
			continue
		}
		data, readErr := readFile(packRoot, reference.Path, MaxReferenced)
		if readErr != nil {
			return Snapshot{}, fmt.Errorf("read referenced file %q: %w", reference.Path, readErr)
		}
		actual := digest(data)
		if verifyDigests && actual != reference.SHA256 {
			return Snapshot{}, fmt.Errorf("referenced file %q digest mismatch", reference.Path)
		}
		files[reference.Path] = File{Path: reference.Path, SHA256: actual, Data: data}
		if isComponentProfile(deployment, reference.Path) {
			nested, nestedErr := nestedReferences(data)
			if nestedErr != nil {
				return Snapshot{}, fmt.Errorf("decode references in %q: %w", reference.Path, nestedErr)
			}
			queue = append(queue, nested...)
			if len(queue)+len(files) > MaxReferences {
				return Snapshot{}, errors.New("deployment contains too many file references")
			}
		}
	}
	manifestFile := files[deployment.Runtime.Manifest.Path]
	trustManifest, _, err := bundle.LoadBytes(
		manifestFile.Data,
		files[deployment.Runtime.Signature.Path].Data,
		files[deployment.Runtime.PublicKey.Path].Data,
		false,
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("validate deployment runtime trust: %w", err)
	}
	var manifest bundle.Manifest
	if err := strictjson.Decode(files[deployment.Runtime.Activation.Path].Data, &manifest, true); err != nil {
		return Snapshot{}, fmt.Errorf("decode deployment activation manifest: %w", err)
	}
	if err := validateActivationManifest(trustManifest, manifest); err != nil {
		return Snapshot{}, err
	}
	if err := deployment.validateRuntimeComponents(manifest); err != nil {
		return Snapshot{}, err
	}
	canonical, err := canonicalDeployment(deployment)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Root: absolute, Deployment: deployment, Files: files,
		Digest: snapshotDigest(canonical, files), Manifest: manifest, TrustManifest: trustManifest,
	}, nil
}

// Validate checks deployment-local invariants.
//
//nolint:cyclop // The closed deployment document is validated field by field.
func (d Deployment) Validate() error {
	if d.APIVersion != APIVersion {
		return fmt.Errorf("unsupported deployment API %q", d.APIVersion)
	}
	if !validName(d.Name) || d.InstallationDigest != "" && !digestPattern.MatchString(d.InstallationDigest) ||
		d.SourceSetDigest != "" && !digestPattern.MatchString(d.SourceSetDigest) {
		return errors.New("deployment name or source digest is invalid")
	}
	if len(d.Agents) > MaxAgents || len(d.Operators) == 0 || len(d.Operators) > MaxOperators {
		return errors.New("deployment must contain a bounded operator list and may contain bounded agents")
	}
	if len(d.Components) == 0 || len(d.Components) > MaxComponents || len(d.Integrations) > MaxIntegrations {
		return errors.New("deployment component or integration count is invalid")
	}
	if err := validateReferences(d.references()); err != nil {
		return err
	}
	if err := validateIdentities(d); err != nil {
		return err
	}
	return validateBindings(d)
}

//nolint:cyclop // Identity uniqueness and separation constraints are checked together to avoid partial validation.
func validateIdentities(d Deployment) error {
	agents, operators, components, integrations := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, agent := range d.Agents {
		if !registerName(agents, agent.ID) || !validName(agent.ClientID) || len(agent.ComponentIDs) == 0 || len(agent.ComponentIDs) > MaxComponents {
			return fmt.Errorf("agent %q has an invalid or duplicate identity", agent.ID)
		}
		if err := validateAgentTarget(agent.Target); err != nil {
			return fmt.Errorf("agent %q: %w", agent.ID, err)
		}
	}
	for _, operator := range d.Operators {
		if !registerName(operators, operator.ID) || !validUnixName(operator.UnixUser) {
			return fmt.Errorf("operator %q has an invalid or duplicate identity", operator.ID)
		}
	}
	for _, component := range d.Components {
		if !registerName(components, component.ID) {
			return fmt.Errorf("component %q has an invalid or duplicate identity", component.ID)
		}
	}
	for _, integration := range d.Integrations {
		if !registerName(integrations, integration.ID) || !validName(integration.Kind) || integration.ID != integration.Kind {
			return fmt.Errorf("integration %q has an invalid, duplicate, or noncanonical identity", integration.ID)
		}
	}
	return nil
}

func validateAgentTarget(target AgentTarget) error {
	if !slices.Contains([]string{"separate", "container", "remote", "reduced"}, target.Isolation) {
		return errors.New("target isolation is invalid")
	}
	switch target.Kind {
	case "local_account":
		if !slices.Contains([]string{"current", "existing", "managed"}, target.AccountMode) || !validUnixName(target.UnixUser) ||
			!cleanAbsolute(target.Home) || !cleanAbsolute(target.Shell) || target.ProjectDirectory != "" || target.Service != "" || target.RemoteName != "" {
			return errors.New("local account target is invalid")
		}
		if target.AccountMode == "managed" && (target.Home == "/" || target.Home == "/root" || !slices.Contains([]string{"nologin", "false"}, filepath.Base(target.Shell))) {
			return errors.New("managed account target must use a noninteractive account")
		}
	case "container":
		if target.Isolation != "container" || !cleanAbsolute(target.ProjectDirectory) || !validName(target.Service) || target.AccountMode != "" || target.UnixUser != "" || target.Home != "" || target.Shell != "" || target.RemoteName != "" {
			return errors.New("container target is invalid")
		}
	case "remote":
		if target.Isolation != "remote" || !validName(target.RemoteName) || target.AccountMode != "" || target.UnixUser != "" || target.Home != "" || target.Shell != "" || target.ProjectDirectory != "" || target.Service != "" {
			return errors.New("remote target is invalid")
		}
	default:
		return errors.New("target kind is invalid")
	}
	return nil
}

func validateBindings(d Deployment) error {
	componentIDs, agentIDs := map[string]bool{}, map[string]bool{}
	for _, component := range d.Components {
		componentIDs[component.ID] = true
	}
	for _, agent := range d.Agents {
		agentIDs[agent.ID] = true
		seen := map[string]bool{}
		for _, componentID := range agent.ComponentIDs {
			if !componentIDs[componentID] || seen[componentID] {
				return fmt.Errorf("agent %q references an unknown or duplicate component %q", agent.ID, componentID)
			}
			seen[componentID] = true
		}
	}
	for _, integration := range d.Integrations {
		if componentIDs[integration.Kind] {
			return fmt.Errorf("integration %q collides with component %q", integration.ID, integration.Kind)
		}
		if !agentIDs[integration.AgentID] {
			return fmt.Errorf("integration %q references unknown agent %q", integration.ID, integration.AgentID)
		}
	}
	return nil
}

func validateActivationManifest(trust, activation bundle.Manifest) error {
	if err := activation.Validate(false); err != nil {
		return fmt.Errorf("validate deployment activation manifest: %w", err)
	}
	if activation.BundleID == trust.BundleID || !strings.HasPrefix(activation.BundleID, trust.BundleID+"-") ||
		activation.APIVersion != trust.APIVersion || activation.SourceCommit != trust.SourceCommit ||
		activation.OperatingSystem != trust.OperatingSystem || activation.Architecture != trust.Architecture ||
		activation.OperatorContractDigest != trust.OperatorContractDigest || activation.AgentContractDigest != trust.AgentContractDigest ||
		!reflect.DeepEqual(activation.SetupCapabilities, trust.SetupCapabilities) {
		return errors.New("deployment activation manifest is not derived from signed runtime trust")
	}
	available := make(map[string]bundle.Component, len(trust.Components))
	for _, component := range trust.Components {
		available[component.Name] = component
	}
	for _, component := range activation.Components {
		trusted, exists := available[component.Name]
		if !exists || !reflect.DeepEqual(component, trusted) {
			return fmt.Errorf("activation component %q is not present unchanged in signed runtime trust", component.Name)
		}
	}
	return nil
}

func (d Deployment) validateRuntimeComponents(manifest bundle.Manifest) error {
	available := make(map[string]bundle.Component, len(manifest.Components))
	for _, component := range manifest.Components {
		available[component.Name] = component
	}
	for _, component := range d.Components {
		runtimeComponent, exists := available[component.ID]
		if !exists {
			return fmt.Errorf("component %q is absent from the signed runtime", component.ID)
		}
		if runtimeComponent.Setup == nil {
			return fmt.Errorf("component %q has no signed setup adapter", component.ID)
		}
	}
	for _, integration := range d.Integrations {
		runtimeComponent, exists := available[integration.Kind]
		if !exists || runtimeComponent.Setup == nil {
			return fmt.Errorf("integration %q has no signed runtime setup adapter", integration.ID)
		}
	}
	return nil
}

func (d Deployment) references() []Reference {
	result := []Reference{d.Runtime.Manifest, d.Runtime.Signature, d.Runtime.PublicKey, d.Runtime.Activation}
	for _, component := range d.Components {
		result = append(result, component.Profile)
		if component.Metadata != nil {
			result = append(result, *component.Metadata)
		}
	}
	for _, integration := range d.Integrations {
		result = append(result, integration.Profile)
	}
	return result
}

func isComponentProfile(deployment Deployment, path string) bool {
	for _, component := range deployment.Components {
		if component.Profile.Path == path {
			return true
		}
	}
	for _, integration := range deployment.Integrations {
		if integration.Profile.Path == path {
			return true
		}
	}
	return false
}

//nolint:cyclop // Each supported component profile resource contributes explicit nested references.
func nestedReferences(data []byte) ([]Reference, error) {
	if err := strictjson.RejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var result []Reference
	var walk func(any) error
	walk = func(current any) error {
		switch typed := current.(type) {
		case []any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		case map[string]any:
			path, pathOK := typed["path"].(string)
			digestValue, digestOK := typed["sha256"].(string)
			if pathOK && digestOK && len(typed) == 2 {
				reference := Reference{Path: path, SHA256: digestValue}
				if err := validateReference(reference); err != nil {
					return err
				}
				result = append(result, reference)
				return nil
			}
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return result, walk(value)
}

func validateReferences(references []Reference) error {
	if len(references) > MaxReferences {
		return errors.New("deployment contains too many file references")
	}
	seen := map[string]string{}
	for _, reference := range references {
		if err := validateReference(reference); err != nil {
			return err
		}
		if previous := seen[reference.Path]; previous != "" && previous != reference.SHA256 {
			return fmt.Errorf("file reference %q has conflicting digests", reference.Path)
		}
		seen[reference.Path] = reference.SHA256
	}
	return nil
}

func validateReference(reference Reference) error {
	if err := validateRelative(reference.Path); err != nil {
		return fmt.Errorf("invalid file reference %q: %w", reference.Path, err)
	}
	if !digestPattern.MatchString(reference.SHA256) {
		return fmt.Errorf("file reference %q has an invalid digest", reference.Path)
	}
	return nil
}

func inspectAbsolutePath(path string) error {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), current), current) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("deployment pack path must not contain symbolic links")
		}
	}
	return nil
}

//nolint:cyclop // Relative pack paths reject every platform escape form explicitly.
func validateRelative(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, `\`) || strings.ContainsRune(path, 0) {
		return errors.New("path must be a nonempty portable relative path")
	}
	if filepath.Clean(path) != path || path == "." {
		return errors.New("path must be clean")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("path contains an unsafe component")
		}
	}
	return nil
}

func readFile(root *os.Root, path string, maximum int64) ([]byte, error) {
	if err := validateRelative(path); err != nil {
		return nil, err
	}
	if err := inspectPath(root, path); err != nil {
		return nil, err
	}
	file, err := root.Open(path)
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

func inspectPath(root *os.Root, path string) error {
	parts := strings.Split(path, "/")
	current := ""
	for index, part := range parts {
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		info, err := root.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("file reference path must not contain symbolic links")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return errors.New("file reference parent must be a directory")
		}
		if index == len(parts)-1 {
			if !info.Mode().IsRegular() {
				return errors.New("file reference must be a regular file")
			}
			if info.Mode().Perm()&0o022 != 0 {
				return errors.New("file reference must not be writable by group or other users")
			}
		}
	}
	return nil
}

func canonicalDeployment(value Deployment) ([]byte, error) {
	slices.SortFunc(value.Agents, func(a, b Agent) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(value.Operators, func(a, b Operator) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(value.Components, func(a, b Component) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(value.Integrations, func(a, b Integration) int { return strings.Compare(a.ID, b.ID) })
	for index := range value.Agents {
		slices.Sort(value.Agents[index].ComponentIDs)
	}
	return json.Marshal(value)
}

func snapshotDigest(deployment []byte, files map[string]File) string {
	hash := sha256.New()
	_, _ = hash.Write(deployment)
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		_, _ = io.WriteString(hash, "\n"+path+"\x00"+files[path].SHA256)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

func registerName(seen map[string]bool, value string) bool {
	if !validName(value) || seen[value] {
		return false
	}
	seen[value] = true
	return true
}

func validName(value string) bool { return len(value) <= 64 && namePattern.MatchString(value) }

func validUnixName(value string) bool {
	return len(value) > 0 && len(value) <= 32 && namePattern.MatchString(value)
}

func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value
}
