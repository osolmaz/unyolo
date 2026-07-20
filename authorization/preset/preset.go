// Package policypreset owns provider-neutral managed policy artifact lifecycles.
// Providers retain operation classification and concrete policy rendering.
package policypreset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/internal/slicex"

	"github.com/osolmaz/brokerkit/operation/capability"
)

const (
	ProfileVersion  = 1
	ManifestVersion = 1
)

type Effect = capability.DefaultPolicyEffect

const (
	EffectAllow   = capability.DefaultEffectAllow
	EffectRequest = capability.DefaultEffectRequest
	EffectDeny    = capability.DefaultEffectDeny
)

// Profile is the operator-editable input to a provider-owned policy renderer.
type Profile struct {
	Version          int      `json:"version"`
	Preset           string   `json:"preset"`
	Clients          []string `json:"clients"`
	DeniedOperations []string `json:"denied_operations"`
}

// Operation is the provider-neutral authorization identity of one operation.
// AuthorizationDigest is computed by the provider from every field that can
// change authorization or grant behavior.
type Operation struct {
	Name                string `json:"name"`
	OperationRevision   int    `json:"operation_revision"`
	DefaultEffect       Effect `json:"default_effect"`
	AuthorizationDigest string `json:"authorization_digest"`
}

type EffectiveOperation struct {
	Operation
	Effect Effect `json:"effect"`
}

type OperationFingerprint = EffectiveOperation

type OperationCounts struct {
	Total   int `json:"total"`
	Allow   int `json:"allow"`
	Request int `json:"request"`
	Deny    int `json:"deny"`
}

// Manifest binds a generated policy to one provider, profile, and catalog.
type Manifest struct {
	Version         int                    `json:"version"`
	Provider        string                 `json:"provider"`
	Preset          string                 `json:"preset"`
	CatalogDigest   string                 `json:"catalog_digest"`
	ProfileDigest   string                 `json:"profile_digest"`
	PolicyDigest    string                 `json:"policy_digest"`
	OperationCounts OperationCounts        `json:"operation_counts"`
	Operations      []OperationFingerprint `json:"operations"`
}

type Artifacts struct {
	Profile      Profile
	Manifest     Manifest
	ProfileJSON  []byte
	PolicyJSON   []byte
	ManifestJSON []byte
}

type DriftStatus string

const (
	DriftCurrent  DriftStatus = "current"
	DriftStale    DriftStatus = "stale"
	DriftModified DriftStatus = "modified"
	DriftInvalid  DriftStatus = "invalid"
)

type DriftReport struct {
	Status            DriftStatus `json:"status"`
	Details           []string    `json:"details"`
	AddedOperations   []string    `json:"added_operations"`
	RemovedOperations []string    `json:"removed_operations"`
	ChangedOperations []string    `json:"changed_operations"`
}

// Renderer supplies provider-owned operation semantics and concrete policy.
type Renderer interface {
	ProviderID() string
	PresetName() string
	Operations() ([]Operation, error)
	RenderPolicy(Profile, []EffectiveOperation) ([]byte, error)
	ValidatePolicy([]byte) error
}

func NewProfile(renderer Renderer, clients, deniedOperations []string) Profile {
	return Profile{Version: ProfileVersion, Preset: renderer.PresetName(), Clients: clients, DeniedOperations: deniedOperations}
}

func ParseProfile(renderer Renderer, data []byte) (Profile, error) {
	profile, err := decodeStrict[Profile](data, "policy profile")
	if err != nil {
		return Profile{}, err
	}
	operations, err := loadOperations(renderer)
	if err != nil {
		return Profile{}, err
	}
	return normalizeProfile(renderer, profile, operationNames(operations), false)
}

func ParseInstalledProfile(renderer Renderer, data []byte) (Profile, error) {
	profile, err := decodeStrict[Profile](data, "policy profile")
	if err != nil {
		return Profile{}, err
	}
	operations, err := loadOperations(renderer)
	if err != nil {
		return Profile{}, err
	}
	return normalizeProfile(renderer, profile, operationNames(operations), true)
}

func ParseManifest(renderer Renderer, data []byte) (Manifest, error) {
	manifest, err := decodeStrict[Manifest](data, "policy manifest")
	if err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(renderer, manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Render(renderer Renderer, input Profile) (Artifacts, error) {
	operations, err := loadOperations(renderer)
	if err != nil {
		return Artifacts{}, err
	}
	profile, err := normalizeProfile(renderer, input, operationNames(operations), false)
	if err != nil {
		return Artifacts{}, err
	}
	effective, counts := applyDeniedOperations(operations, profile.DeniedOperations)
	policyJSON, err := renderer.RenderPolicy(profile, effective)
	if err != nil {
		return Artifacts{}, fmt.Errorf("render %s policy: %w", renderer.ProviderID(), err)
	}
	if err := renderer.ValidatePolicy(policyJSON); err != nil {
		return Artifacts{}, fmt.Errorf("validate rendered policy: %w", err)
	}
	manifest, profileJSON, manifestJSON, err := renderManifest(renderer, profile, operations, effective, counts, policyJSON)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{Profile: profile, Manifest: manifest, ProfileJSON: profileJSON, PolicyJSON: policyJSON, ManifestJSON: manifestJSON}, nil
}

func renderManifest(renderer Renderer, profile Profile, operations []Operation, effective []EffectiveOperation, counts OperationCounts, policyJSON []byte) (Manifest, []byte, []byte, error) {
	profileJSON, err := MarshalCanonical(profile)
	if err != nil {
		return Manifest{}, nil, nil, err
	}
	catalogJSON, err := MarshalCanonical(operations)
	if err != nil {
		return Manifest{}, nil, nil, err
	}
	manifest := Manifest{
		Version: ManifestVersion, Provider: renderer.ProviderID(), Preset: renderer.PresetName(),
		CatalogDigest: Digest(catalogJSON), ProfileDigest: Digest(profileJSON), PolicyDigest: Digest(policyJSON),
		OperationCounts: counts, Operations: effective,
	}
	manifestJSON, err := MarshalCanonical(manifest)
	if err != nil {
		return Manifest{}, nil, nil, err
	}
	return manifest, profileJSON, manifestJSON, nil
}

func Check(renderer Renderer, profileData, manifestData, policyData []byte) DriftReport {
	input, err := loadCheckInput(renderer, profileData, manifestData)
	if err != nil {
		return invalidReport(err)
	}
	current, err := Render(renderer, input.profile)
	if err != nil {
		return invalidReport(err)
	}
	report := newDriftReport()
	compareArtifactDigests(&report, input.manifest, profileData, policyData)
	compareOperationState(&report, input.manifest, current.Manifest)
	catalogCurrent := input.manifest.CatalogDigest == current.Manifest.CatalogDigest
	if err := compareCurrentPolicy(renderer, &report, catalogCurrent, current.PolicyJSON, policyData); err != nil {
		return invalidReport(err)
	}
	if report.Status == DriftCurrent {
		report.Details = append(report.Details, "profile, policy, manifest, and operation catalog match")
	}
	return report
}

type checkInput struct {
	profile  Profile
	manifest Manifest
}

func loadCheckInput(renderer Renderer, profileData, manifestData []byte) (checkInput, error) {
	manifest, err := ParseManifest(renderer, manifestData)
	if err != nil {
		return checkInput{}, err
	}
	profile, err := decodeStrict[Profile](profileData, "policy profile")
	if err != nil {
		return checkInput{}, err
	}
	operations, err := loadOperations(renderer)
	if err != nil {
		return checkInput{}, err
	}
	profile, err = normalizeInstalledForManifest(renderer, profile, operations, manifest)
	if err != nil {
		return checkInput{}, err
	}
	return checkInput{profile: profile, manifest: manifest}, nil
}

func newDriftReport() DriftReport {
	return DriftReport{Status: DriftCurrent, Details: []string{}, AddedOperations: []string{}, RemovedOperations: []string{}, ChangedOperations: []string{}}
}

func compareArtifactDigests(report *DriftReport, manifest Manifest, profileData, policyData []byte) {
	if manifest.ProfileDigest != Digest(profileData) {
		markDrift(report, DriftModified, "profile digest does not match the manifest")
	}
	if manifest.PolicyDigest != Digest(policyData) {
		markDrift(report, DriftModified, "policy digest does not match the manifest")
	}
}

func compareOperationState(report *DriftReport, manifest, current Manifest) {
	if manifest.CatalogDigest != current.CatalogDigest {
		markDrift(report, DriftStale, "operation catalog changed since this policy was rendered")
	}
	report.AddedOperations, report.RemovedOperations, report.ChangedOperations = compareOperations(manifest.Operations, current.Operations)
	if manifest.OperationCounts != current.OperationCounts || hasOperationDrift(*report) {
		markDrift(report, DriftModified, "manifest operation summary does not match the rendered profile and current catalog")
	}
}

func compareCurrentPolicy(renderer Renderer, report *DriftReport, catalogCurrent bool, currentPolicy, policyData []byte) error {
	if !catalogCurrent || report == nil {
		return nil
	}
	if err := renderer.ValidatePolicy(policyData); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	if !bytes.Equal(policyData, currentPolicy) {
		markDrift(report, DriftModified, "policy does not match the deterministic render of its profile")
	}
	return nil
}

// AuthorizationDigest canonicalizes provider-owned authorization metadata.
func AuthorizationDigest(value any) (string, error) {
	data, err := MarshalCanonical(value)
	if err != nil {
		return "", err
	}
	return Digest(data), nil
}

func MarshalCanonical(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode policy artifact: %w", err)
	}
	return append(data, '\n'), nil
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func loadOperations(renderer Renderer) ([]Operation, error) {
	if err := validateRendererIdentity(renderer); err != nil {
		return nil, err
	}
	operations, err := renderer.Operations()
	if err != nil {
		return nil, fmt.Errorf("load %s policy operations: %w", renderer.ProviderID(), err)
	}
	if err := validateOperationCatalog(operations); err != nil {
		return nil, err
	}
	return slices.Clone(operations), nil
}

func validateRendererIdentity(renderer Renderer) error {
	if renderer == nil || strings.TrimSpace(renderer.ProviderID()) == "" || strings.TrimSpace(renderer.PresetName()) == "" {
		return errors.New("policy preset renderer identity is incomplete")
	}
	return nil
}

func validateOperationCatalog(operations []Operation) error {
	if len(operations) == 0 {
		return errors.New("policy preset operation catalog is empty")
	}
	previous := ""
	for _, operation := range operations {
		if invalidCatalogOperation(operation, previous) {
			return fmt.Errorf("policy preset operation %q is invalid or out of order", operation.Name)
		}
		previous = operation.Name
	}
	return nil
}

func invalidCatalogOperation(operation Operation, previous string) bool {
	return operation.Name == "" || previous >= operation.Name || operation.OperationRevision < 1 ||
		!validEffect(operation.DefaultEffect) || !validDigest(operation.AuthorizationDigest)
}

func normalizeProfile(renderer Renderer, profile Profile, known map[string]bool, dropUnknown bool) (Profile, error) {
	if profile.Version != ProfileVersion {
		return Profile{}, fmt.Errorf("policy profile version must be %d", ProfileVersion)
	}
	if profile.Preset != renderer.PresetName() {
		return Profile{}, fmt.Errorf("unknown %s policy preset %q", renderer.ProviderID(), profile.Preset)
	}
	clients, err := normalizeExactValues("clients", profile.Clients, false)
	if err != nil {
		return Profile{}, err
	}
	denied, err := normalizeExactValues("denied_operations", profile.DeniedOperations, true)
	if err != nil {
		return Profile{}, err
	}
	kept := denied[:0]
	for _, operation := range denied {
		if known[operation] {
			kept = append(kept, operation)
		} else if !dropUnknown {
			return Profile{}, fmt.Errorf("denied_operations contains unknown operation %q", operation)
		}
	}
	profile.Clients, profile.DeniedOperations = clients, slicex.NonNil(kept)
	return profile, nil
}

func normalizeInstalledForManifest(renderer Renderer, profile Profile, operations []Operation, manifest Manifest) (Profile, error) {
	known := operationNames(operations)
	manifestNames := map[string]bool{}
	for _, operation := range manifest.Operations {
		manifestNames[operation.Name] = true
	}
	profile, err := normalizeProfileFields(renderer, profile)
	if err != nil {
		return Profile{}, err
	}
	kept := profile.DeniedOperations[:0]
	for _, operation := range profile.DeniedOperations {
		if known[operation] {
			kept = append(kept, operation)
		} else if !manifestNames[operation] {
			return Profile{}, fmt.Errorf("denied_operations contains operation %q absent from the policy manifest", operation)
		}
	}
	profile.DeniedOperations = slicex.NonNil(kept)
	return profile, nil
}

func normalizeProfileFields(renderer Renderer, profile Profile) (Profile, error) {
	if profile.Version != ProfileVersion || profile.Preset != renderer.PresetName() {
		return Profile{}, errors.New("policy profile version or preset is invalid")
	}
	clients, err := normalizeExactValues("clients", profile.Clients, false)
	if err != nil {
		return Profile{}, err
	}
	denied, err := normalizeExactValues("denied_operations", profile.DeniedOperations, true)
	if err != nil {
		return Profile{}, err
	}
	profile.Clients, profile.DeniedOperations = clients, slicex.NonNil(denied)
	return profile, nil
}

func normalizeExactValues(field string, values []string, allowEmpty bool) ([]string, error) {
	if len(values) == 0 {
		if allowEmpty {
			return []string{}, nil
		}
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	normalized := slices.Clone(values)
	for _, value := range normalized {
		if value == "" || strings.TrimSpace(value) != value {
			return nil, fmt.Errorf("%s contains an empty or whitespace-padded value", field)
		}
	}
	slices.Sort(normalized)
	for index := 1; index < len(normalized); index++ {
		if normalized[index] == normalized[index-1] {
			return nil, fmt.Errorf("%s contains duplicate values", field)
		}
	}
	return normalized, nil
}

func applyDeniedOperations(operations []Operation, denied []string) ([]EffectiveOperation, OperationCounts) {
	overrides := operationNamesFromSlice(denied)
	effective := make([]EffectiveOperation, 0, len(operations))
	counts := OperationCounts{Total: len(operations)}
	for _, operation := range operations {
		effect := operation.DefaultEffect
		if overrides[operation.Name] {
			effect = EffectDeny
		}
		effective = append(effective, EffectiveOperation{Operation: operation, Effect: effect})
		counts.add(effect)
	}
	return effective, counts
}

func validateManifest(renderer Renderer, manifest Manifest) error {
	if manifest.Version != ManifestVersion || manifest.Provider != renderer.ProviderID() || manifest.Preset != renderer.PresetName() {
		return errors.New("policy manifest provider, version, or preset is invalid")
	}
	if err := validateManifestDigests(manifest); err != nil {
		return err
	}
	counts, err := validateManifestOperations(manifest.Operations)
	if err != nil {
		return err
	}
	if counts != manifest.OperationCounts {
		return errors.New("policy manifest operation count is inconsistent")
	}
	return nil
}

func validateManifestDigests(manifest Manifest) error {
	for name, value := range map[string]string{"catalog": manifest.CatalogDigest, "profile": manifest.ProfileDigest, "policy": manifest.PolicyDigest} {
		if !validDigest(value) {
			return fmt.Errorf("policy manifest %s digest is invalid", name)
		}
	}
	return nil
}

func validateManifestOperations(operations []OperationFingerprint) (OperationCounts, error) {
	counts := OperationCounts{Total: len(operations)}
	previous := ""
	for _, operation := range operations {
		if invalidManifestOperation(operation, previous) {
			return OperationCounts{}, fmt.Errorf("policy manifest operation %q is invalid or out of order", operation.Name)
		}
		previous = operation.Name
		counts.add(operation.Effect)
	}
	return counts, nil
}

func invalidManifestOperation(operation OperationFingerprint, previous string) bool {
	return operation.Name == "" || previous >= operation.Name || operation.OperationRevision < 1 ||
		!validEffect(operation.DefaultEffect) || !validEffect(operation.Effect) ||
		!validDigest(operation.AuthorizationDigest) ||
		(operation.Effect != operation.DefaultEffect && operation.Effect != EffectDeny)
}

func compareOperations(installed, current []OperationFingerprint) (added, removed, changed []string) {
	old := make(map[string]OperationFingerprint, len(installed))
	for _, operation := range installed {
		old[operation.Name] = operation
	}
	seen := make(map[string]bool, len(current))
	for _, operation := range current {
		seen[operation.Name] = true
		previous, found := old[operation.Name]
		if !found {
			added = append(added, operation.Name)
		} else if previous != operation {
			changed = append(changed, operation.Name)
		}
	}
	for _, operation := range installed {
		if !seen[operation.Name] {
			removed = append(removed, operation.Name)
		}
	}
	return added, removed, changed
}

func decodeStrict[T any](data []byte, name string) (T, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("parse %s: %w", name, err)
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return value, fmt.Errorf("parse %s: trailing content", name)
	}
	return value, nil
}

func operationNames(operations []Operation) map[string]bool {
	result := make(map[string]bool, len(operations))
	for _, operation := range operations {
		result[operation.Name] = true
	}
	return result
}

func operationNamesFromSlice(operations []string) map[string]bool {
	result := make(map[string]bool, len(operations))
	for _, operation := range operations {
		result[operation] = true
	}
	return result
}

func validEffect(effect Effect) bool {
	return effect == EffectAllow || effect == EffectRequest || effect == EffectDeny
}

func validDigest(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || !strings.HasPrefix(value, prefix) {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func (counts *OperationCounts) add(effect Effect) {
	switch effect {
	case EffectAllow:
		counts.Allow++
	case EffectRequest:
		counts.Request++
	case EffectDeny:
		counts.Deny++
	}
}

func markDrift(report *DriftReport, status DriftStatus, detail string) {
	if report.Status == DriftCurrent {
		report.Status = status
	}
	report.Details = append(report.Details, detail)
}

func hasOperationDrift(report DriftReport) bool {
	return len(report.AddedOperations) > 0 || len(report.RemovedOperations) > 0 || len(report.ChangedOperations) > 0
}

func invalidReport(err error) DriftReport {
	return DriftReport{Status: DriftInvalid, Details: []string{err.Error()}, AddedOperations: []string{}, RemovedOperations: []string{}, ChangedOperations: []string{}}
}
