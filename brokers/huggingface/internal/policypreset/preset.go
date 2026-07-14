// Package policypreset renders provider-owned Hugging Face policy presets.
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

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

const (
	RequestAllAgentOperations = "request-all-agent-operations"
	ProfileVersion            = 1
	ManifestVersion           = 1
)

// Profile is the small, operator-editable input used to render a concrete
// broker policy. DeniedOperations is an exact override list.
type Profile struct {
	Version          int      `json:"version"`
	Preset           string   `json:"preset"`
	Clients          []string `json:"clients"`
	DeniedOperations []string `json:"denied_operations"`
}

// Manifest binds one generated policy to its profile and operation catalog.
type Manifest struct {
	Version         int                    `json:"version"`
	Preset          string                 `json:"preset"`
	CatalogDigest   string                 `json:"catalog_digest"`
	ProfileDigest   string                 `json:"profile_digest"`
	PolicyDigest    string                 `json:"policy_digest"`
	OperationCounts OperationCounts        `json:"operation_counts"`
	Operations      []OperationFingerprint `json:"operations"`
}

type OperationCounts struct {
	Total   int `json:"total"`
	Allow   int `json:"allow"`
	Request int `json:"request"`
	Deny    int `json:"deny"`
}

type OperationFingerprint struct {
	Name               string                        `json:"name"`
	OperationRevision  int                           `json:"operation_revision"`
	DefaultEffect      opcatalog.DefaultPolicyEffect `json:"default_effect"`
	Effect             opcatalog.DefaultPolicyEffect `json:"effect"`
	Risk               opcatalog.Risk                `json:"risk"`
	AuthorizationMode  opcatalog.AuthorizationMode   `json:"authorization_mode"`
	MaxUses            int                           `json:"max_uses"`
	RequestTTLSeconds  int                           `json:"request_ttl_seconds"`
	ApprovalTTLSeconds int                           `json:"approval_ttl_seconds"`
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

// DriftReport explains whether policy artifacts still match one another and
// the catalog embedded in the running binary.
type DriftReport struct {
	Status            DriftStatus `json:"status"`
	Details           []string    `json:"details"`
	AddedOperations   []string    `json:"added_operations"`
	RemovedOperations []string    `json:"removed_operations"`
	ChangedOperations []string    `json:"changed_operations"`
}

type policyDocument struct {
	Rules []policyRule `json:"rules"`
}

type policyRule struct {
	ID          string           `json:"id"`
	Effect      string           `json:"effect"`
	Clients     []string         `json:"clients"`
	Operations  []string         `json:"operations"`
	Targets     []map[string]any `json:"targets"`
	GrantPolicy *ruleGrantPolicy `json:"grant_policy,omitempty"`
	Description string           `json:"description"`
}

type ruleGrantPolicy struct {
	Mode              string `json:"mode"`
	DefaultMinutes    int    `json:"default_minutes"`
	MaxMinutes        int    `json:"max_minutes"`
	RequestTTLMinutes int    `json:"request_ttl_minutes"`
	DefaultMaxUses    int    `json:"default_max_uses"`
	MaxUses           int    `json:"max_uses"`
}

// NewProfile creates the default profile for one or more broker clients.
func NewProfile(clients, deniedOperations []string) Profile {
	return Profile{
		Version: ProfileVersion, Preset: RequestAllAgentOperations,
		Clients: clients, DeniedOperations: deniedOperations,
	}
}

// ParseProfile strictly decodes and normalizes one profile.
func ParseProfile(data []byte) (Profile, error) {
	profile, err := decodeProfile(data)
	if err != nil {
		return Profile{}, err
	}
	return normalizeProfile(profile)
}

// ParseManifest strictly decodes and validates one generated manifest.
func ParseManifest(data []byte) (Manifest, error) {
	return parseManifest(data)
}

// ParseInstalledProfile decodes an installed profile for a safe catalog
// upgrade. Deny overrides for operations retired from the current catalog are
// dropped because they can no longer appear in a newly rendered policy.
func ParseInstalledProfile(data []byte) (Profile, error) {
	profile, err := decodeProfile(data)
	if err != nil {
		return Profile{}, err
	}
	profile, err = normalizeProfileFields(profile)
	if err != nil {
		return Profile{}, err
	}
	current := profile.DeniedOperations[:0]
	for _, operation := range profile.DeniedOperations {
		if _, found := opcatalog.ByName(operation); found {
			current = append(current, operation)
		}
	}
	profile.DeniedOperations = current
	return profile, nil
}

func decodeProfile(data []byte) (Profile, error) {
	return decodeStrictArtifact[Profile](data, "policy profile")
}

// Check reports drift without changing any operator-owned files.
func Check(profileData, manifestData, policyData []byte) DriftReport {
	manifest, current, err := checkInputs(profileData, manifestData)
	if err != nil {
		return invalidReport(err)
	}
	report := DriftReport{Status: DriftCurrent, Details: []string{}}
	checkArtifactDigests(&report, profileData, policyData, manifest)
	checkCatalogDrift(&report, manifest, current.Manifest)
	if manifest.CatalogDigest == current.Manifest.CatalogDigest {
		if _, err := policy.Parse(policyData); err != nil {
			return invalidReport(fmt.Errorf("parse policy: %w", err))
		}
		checkDeterministicPolicy(&report, policyData, current.PolicyJSON)
	}
	if report.Status == DriftCurrent {
		report.Details = append(report.Details, "profile, policy, manifest, and operation catalog match")
	}
	return report
}

func checkInputs(profileData, manifestData []byte) (Manifest, Artifacts, error) {
	manifest, err := parseManifest(manifestData)
	if err != nil {
		return Manifest{}, Artifacts{}, err
	}
	profile, err := decodeProfile(profileData)
	if err != nil {
		return Manifest{}, Artifacts{}, err
	}
	profile, err = normalizeProfileFields(profile)
	if err != nil {
		return Manifest{}, Artifacts{}, err
	}
	currentProfile, err := currentCatalogProfile(profile, manifest)
	if err != nil {
		return Manifest{}, Artifacts{}, err
	}
	current, err := Render(currentProfile)
	if err != nil {
		return Manifest{}, Artifacts{}, err
	}
	return manifest, current, nil
}

func checkDeterministicPolicy(report *DriftReport, policyData, renderedPolicy []byte) {
	if bytes.Equal(policyData, renderedPolicy) {
		return
	}
	report.Status = DriftModified
	report.Details = append(report.Details, "policy does not match the deterministic render of its profile")
}

func checkArtifactDigests(report *DriftReport, profileData, policyData []byte, manifest Manifest) {
	if manifest.ProfileDigest != digest(profileData) {
		report.Status = DriftModified
		report.Details = append(report.Details, "profile digest does not match the manifest")
	}
	if manifest.PolicyDigest != digest(policyData) {
		report.Status = DriftModified
		report.Details = append(report.Details, "policy digest does not match the manifest")
	}
}

func checkCatalogDrift(report *DriftReport, manifest, current Manifest) {
	if manifest.CatalogDigest != current.CatalogDigest {
		markDrift(report, DriftStale, "operation catalog changed since this policy was rendered")
	}
	report.AddedOperations, report.RemovedOperations, report.ChangedOperations = compareOperations(manifest.Operations, current.Operations)
	if manifest.OperationCounts != current.OperationCounts || reportHasOperationDrift(*report) {
		markDrift(report, DriftModified, "manifest operation summary does not match the rendered profile and current catalog")
	}
}

func markDrift(report *DriftReport, status DriftStatus, detail string) {
	if report.Status == DriftCurrent {
		report.Status = status
	}
	report.Details = append(report.Details, detail)
}

func reportHasOperationDrift(report DriftReport) bool {
	return len(report.AddedOperations) > 0 || len(report.RemovedOperations) > 0 || len(report.ChangedOperations) > 0
}

// Render materializes a validated profile into deterministic policy artifacts.
func Render(input Profile) (Artifacts, error) {
	profile, err := normalizeProfile(input)
	if err != nil {
		return Artifacts{}, err
	}
	descriptors := opcatalog.MustAll()
	document, manifest := renderCatalog(profile, descriptors)
	profileJSON, err := marshalCanonical(profile)
	if err != nil {
		return Artifacts{}, err
	}
	policyJSON, err := marshalCanonical(document)
	if err != nil {
		return Artifacts{}, err
	}
	if _, err := policy.Parse(policyJSON); err != nil {
		return Artifacts{}, fmt.Errorf("validate rendered policy: %w", err)
	}
	catalogJSON, err := json.Marshal(descriptors)
	if err != nil {
		return Artifacts{}, fmt.Errorf("encode catalog digest input: %w", err)
	}
	manifest.CatalogDigest = digest(catalogJSON)
	manifest.ProfileDigest = digest(profileJSON)
	manifest.PolicyDigest = digest(policyJSON)
	manifestJSON, err := marshalCanonical(manifest)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{
		Profile: profile, Manifest: manifest, ProfileJSON: profileJSON,
		PolicyJSON: policyJSON, ManifestJSON: manifestJSON,
	}, nil
}

func renderCatalog(profile Profile, descriptors []opcatalog.Descriptor) (policyDocument, Manifest) {
	denied := deniedOperationSet(profile.DeniedOperations)
	document := policyDocument{Rules: make([]policyRule, 0, len(descriptors))}
	manifest := Manifest{Version: ManifestVersion, Preset: profile.Preset, Operations: make([]OperationFingerprint, 0, len(descriptors))}
	for _, descriptor := range descriptors {
		effect := descriptor.DefaultPolicyEffect
		if _, isDenied := denied[descriptor.Name]; isDenied {
			effect = opcatalog.DefaultEffectDeny
		}
		document.Rules = append(document.Rules, renderRule(profile.Clients, descriptor, effect))
		manifest.Operations = append(manifest.Operations, fingerprint(descriptor, effect))
		manifest.OperationCounts.add(effect)
	}
	manifest.OperationCounts.Total = len(descriptors)
	return document, manifest
}

func deniedOperationSet(operations []string) map[string]struct{} {
	denied := make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		denied[operation] = struct{}{}
	}
	return denied
}

func normalizeProfile(profile Profile) (Profile, error) {
	profile, err := normalizeProfileFields(profile)
	if err != nil {
		return Profile{}, err
	}
	for _, operation := range profile.DeniedOperations {
		if _, found := opcatalog.ByName(operation); !found {
			return Profile{}, fmt.Errorf("denied_operations contains unknown operation %q", operation)
		}
	}
	return profile, nil
}

func normalizeProfileFields(profile Profile) (Profile, error) {
	if profile.Version != ProfileVersion {
		return Profile{}, fmt.Errorf("policy profile version must be %d", ProfileVersion)
	}
	if profile.Preset != RequestAllAgentOperations {
		return Profile{}, fmt.Errorf("unknown Hugging Face policy preset %q", profile.Preset)
	}
	clients, err := normalizeExactValues("clients", profile.Clients)
	if err != nil {
		return Profile{}, err
	}
	denied, err := normalizeExactValues("denied_operations", profile.DeniedOperations)
	if err != nil && len(profile.DeniedOperations) > 0 {
		return Profile{}, err
	}
	profile.Clients = clients
	profile.DeniedOperations = nonNil(denied)
	return profile, nil
}

func currentCatalogProfile(profile Profile, manifest Manifest) (Profile, error) {
	manifestOperations := make(map[string]bool, len(manifest.Operations))
	for _, operation := range manifest.Operations {
		manifestOperations[operation.Name] = true
	}
	currentDenied := make([]string, 0, len(profile.DeniedOperations))
	for _, operation := range profile.DeniedOperations {
		if _, found := opcatalog.ByName(operation); found {
			currentDenied = append(currentDenied, operation)
			continue
		}
		if !manifestOperations[operation] {
			return Profile{}, fmt.Errorf("denied_operations contains operation %q absent from the policy manifest", operation)
		}
	}
	profile.DeniedOperations = currentDenied
	return profile, nil
}

func normalizeExactValues(field string, values []string) ([]string, error) {
	if len(values) == 0 {
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

func renderRule(clients []string, descriptor opcatalog.Descriptor, effect opcatalog.DefaultPolicyEffect) policyRule {
	target := map[string]any{"kind": descriptor.TargetKind, "owner": "*", "name": "*"}
	if descriptor.TargetKind == string(policy.KindRepo) {
		target["type"] = "*"
	}
	rule := policyRule{
		ID:     "preset-" + strings.ReplaceAll(descriptor.Name, ".", "-"),
		Effect: string(effect), Clients: clients, Operations: []string{descriptor.Name},
		Targets:     []map[string]any{target},
		Description: "Generated by Hugging Face policy preset " + RequestAllAgentOperations + ".",
	}
	if effect == opcatalog.DefaultEffectRequest {
		rule.GrantPolicy = grantPolicy(descriptor)
	}
	return rule
}

func grantPolicy(descriptor opcatalog.Descriptor) *ruleGrantPolicy {
	mode := string(policy.GrantModeWindow)
	if descriptor.AuthorizationMode == opcatalog.ModeExecution {
		mode = string(policy.GrantModeExecution)
	}
	maxMinutes := descriptor.ApprovalTTLSeconds / 60
	defaultMinutes := min(policy.DefaultGrantMinutes, maxMinutes)
	maxUses := descriptor.MaxUses
	if descriptor.AuthorizationMode == opcatalog.ModeExecution {
		maxUses = 1
	}
	return &ruleGrantPolicy{
		Mode: mode, DefaultMinutes: defaultMinutes, MaxMinutes: maxMinutes,
		RequestTTLMinutes: descriptor.RequestTTLSeconds / 60,
		DefaultMaxUses:    1, MaxUses: maxUses,
	}
}

func fingerprint(descriptor opcatalog.Descriptor, effect opcatalog.DefaultPolicyEffect) OperationFingerprint {
	return OperationFingerprint{
		Name: descriptor.Name, OperationRevision: descriptor.OperationRevision,
		DefaultEffect: descriptor.DefaultPolicyEffect, Effect: effect,
		Risk: descriptor.Risk, AuthorizationMode: descriptor.AuthorizationMode,
		MaxUses: descriptor.MaxUses, RequestTTLSeconds: descriptor.RequestTTLSeconds,
		ApprovalTTLSeconds: descriptor.ApprovalTTLSeconds,
	}
}

func (counts *OperationCounts) add(effect opcatalog.DefaultPolicyEffect) {
	switch effect {
	case opcatalog.DefaultEffectAllow:
		counts.Allow++
	case opcatalog.DefaultEffectRequest:
		counts.Request++
	case opcatalog.DefaultEffectDeny:
		counts.Deny++
	}
}

func marshalCanonical(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode policy artifact: %w", err)
	}
	return append(data, '\n'), nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func parseManifest(data []byte) (Manifest, error) {
	manifest, err := decodeManifest(data)
	if err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func decodeManifest(data []byte) (Manifest, error) {
	return decodeStrictArtifact[Manifest](data, "policy manifest")
}

func decodeStrictArtifact[T any](data []byte, name string) (T, error) {
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

func validateManifest(manifest Manifest) error {
	if manifest.Version != ManifestVersion || manifest.Preset != RequestAllAgentOperations {
		return errors.New("policy manifest version or preset is invalid")
	}
	for name, value := range map[string]string{
		"catalog": manifest.CatalogDigest,
		"profile": manifest.ProfileDigest,
		"policy":  manifest.PolicyDigest,
	} {
		if !validDigest(value) {
			return fmt.Errorf("policy manifest %s digest is invalid", name)
		}
	}
	counts, err := countManifestOperations(manifest.Operations)
	if err != nil {
		return err
	}
	if manifest.OperationCounts != counts {
		return errors.New("policy manifest operation count is inconsistent")
	}
	return nil
}

func validDigest(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || !strings.HasPrefix(value, prefix) {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func countManifestOperations(operations []OperationFingerprint) (OperationCounts, error) {
	counts := OperationCounts{Total: len(operations)}
	names := make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		if operation.Name == "" {
			return OperationCounts{}, errors.New("policy manifest contains an operation with an empty name")
		}
		if _, exists := names[operation.Name]; exists {
			return OperationCounts{}, fmt.Errorf("policy manifest contains duplicate operation %q", operation.Name)
		}
		names[operation.Name] = struct{}{}
		if !validPolicyEffect(operation.DefaultEffect) {
			return OperationCounts{}, fmt.Errorf("policy manifest operation %q has invalid default effect %q", operation.Name, operation.DefaultEffect)
		}
		if !validPolicyEffect(operation.Effect) {
			return OperationCounts{}, fmt.Errorf("policy manifest operation %q has invalid effect %q", operation.Name, operation.Effect)
		}
		if operation.Effect != operation.DefaultEffect && operation.Effect != opcatalog.DefaultEffectDeny {
			return OperationCounts{}, fmt.Errorf("policy manifest operation %q has impossible effect override", operation.Name)
		}
		counts.add(operation.Effect)
	}
	return counts, nil
}

func validPolicyEffect(effect opcatalog.DefaultPolicyEffect) bool {
	return effect == opcatalog.DefaultEffectAllow || effect == opcatalog.DefaultEffectRequest || effect == opcatalog.DefaultEffectDeny
}

func invalidReport(err error) DriftReport {
	return DriftReport{Status: DriftInvalid, Details: []string{err.Error()}, AddedOperations: []string{}, RemovedOperations: []string{}, ChangedOperations: []string{}}
}

func compareOperations(previous, current []OperationFingerprint) (added, removed, changed []string) {
	previousByName := make(map[string]OperationFingerprint, len(previous))
	currentByName := make(map[string]OperationFingerprint, len(current))
	for _, operation := range previous {
		previousByName[operation.Name] = operation
	}
	for _, operation := range current {
		currentByName[operation.Name] = operation
		old, found := previousByName[operation.Name]
		if !found {
			added = append(added, operation.Name)
		} else if old != operation {
			changed = append(changed, operation.Name)
		}
	}
	for _, operation := range previous {
		if _, found := currentByName[operation.Name]; !found {
			removed = append(removed, operation.Name)
		}
	}
	return nonNil(added), nonNil(removed), nonNil(changed)
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
