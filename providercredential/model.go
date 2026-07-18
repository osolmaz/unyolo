// Package providercredential defines provider-neutral credential capabilities
// and the immutable snapshots used by broker discovery and execution.
package providercredential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

const (
	SchemaVersion   = 1
	maxCapabilities = 4096
)

// VerificationState separates rejected credentials from transient provider failures.
type VerificationState string

const (
	VerificationValid        VerificationState = "valid"
	VerificationInvalid      VerificationState = "invalid"
	VerificationUnavailable  VerificationState = "unavailable"
	VerificationInconclusive VerificationState = "inconclusive"
	VerificationExpired      VerificationState = "expired"
)

// AccessLevel is ordered from metadata-only access through provider mutation.
type AccessLevel string

const (
	AccessNone  AccessLevel = "none"
	AccessRead  AccessLevel = "read"
	AccessWrite AccessLevel = "write"
)

// ResourceSelector is a structured provider resource ceiling.
// Empty fields mean the capability is not restricted by that dimension.
type ResourceSelector struct {
	Kind string `json:"kind,omitempty"`
	Name string `json:"name,omitempty"`
}

// Capability is one normalized authority exposed by a provider credential.
type Capability struct {
	Domain      string           `json:"domain"`
	Permission  string           `json:"permission"`
	AccessLevel AccessLevel      `json:"access_level"`
	Resource    ResourceSelector `json:"resource,omitempty"`
}

// Need is one acceptable capability in a requirement clause.
type Need struct {
	Domain             string      `json:"domain,omitempty"`
	Permission         string      `json:"permission"`
	MinimumAccessLevel AccessLevel `json:"minimum_access_level"`
	TargetBinding      string      `json:"target_binding,omitempty"`
}

// AnyOf requires at least one of its alternatives.
type AnyOf struct {
	Alternatives []Need `json:"any_of"`
}

// Requirement requires every clause and at least one alternative per clause.
type Requirement struct {
	AllOf []AnyOf `json:"all_of"`
}

// Snapshot is the secret-free, immutable credential authority used at runtime.
type Snapshot struct {
	SchemaVersion     int               `json:"schema_version"`
	Provider          string            `json:"provider"`
	CredentialKind    string            `json:"credential_kind"`
	Subject           string            `json:"subject"`
	FingerprintSHA256 string            `json:"fingerprint_sha256"`
	Generation        uint64            `json:"generation"`
	VerifiedAt        time.Time         `json:"verified_at"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
	VerificationState VerificationState `json:"verification_state"`
	Capabilities      []Capability      `json:"capabilities"`
	CapabilityDigest  string            `json:"capability_digest"`
}

// Target contains canonical provider target fields after schema validation.
type Target map[string]string

// TargetFromJSON projects scalar canonical target fields and a conventional
// owner/name resource key for provider capability matching.
func TargetFromJSON(data json.RawMessage) (Target, error) {
	if len(data) == 0 || len(data) > 64*1024 {
		return nil, errors.New("provider credential target is invalid")
	}
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil || raw == nil {
		return nil, errors.New("provider credential target is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("provider credential target is invalid")
	}
	target := Target{}
	for name, value := range raw {
		var text string
		if json.Unmarshal(value, &text) == nil && strings.TrimSpace(text) == text && text != "" {
			target[name] = text
		}
	}
	owner := target["owner"]
	if owner == "" {
		owner = target["namespace"]
	}
	name := target["name"]
	if name == "" {
		name = target["repo"]
	}
	if owner != "" && name != "" {
		target["resource"] = owner + "/" + name
	}
	return target, nil
}

// Binding is persisted in immutable operation plans.
type Binding struct {
	Generation       uint64 `json:"generation"`
	CapabilityDigest string `json:"capability_digest"`
}

// Evaluation is a bounded, secret-free requirement result.
type Evaluation struct {
	Allowed bool     `json:"allowed"`
	Missing []string `json:"missing,omitempty"`
}

// Normalize validates, sorts, deduplicates, and digests a snapshot.
func Normalize(snapshot Snapshot) (Snapshot, error) {
	if snapshot.SchemaVersion == 0 {
		snapshot.SchemaVersion = SchemaVersion
	}
	if err := validateSnapshotIdentity(snapshot); err != nil {
		return Snapshot{}, err
	}
	capabilities := slices.Clone(snapshot.Capabilities)
	for _, capability := range capabilities {
		if err := validateCapability(capability); err != nil {
			return Snapshot{}, err
		}
	}
	slices.SortFunc(capabilities, compareCapability)
	capabilities = slices.CompactFunc(capabilities, func(a, b Capability) bool { return compareCapability(a, b) == 0 })
	if len(capabilities) > maxCapabilities {
		return Snapshot{}, errors.New("provider credential has too many capabilities")
	}
	snapshot.Capabilities = capabilities
	digest, err := capabilityDigest(capabilities)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.CapabilityDigest = digest
	snapshot.VerifiedAt = snapshot.VerifiedAt.UTC()
	if snapshot.ExpiresAt != nil {
		expires := snapshot.ExpiresAt.UTC()
		snapshot.ExpiresAt = &expires
	}
	return snapshot, nil
}

func validateSnapshotIdentity(snapshot Snapshot) error {
	if snapshot.SchemaVersion != SchemaVersion || snapshot.Generation == 0 {
		return errors.New("provider credential snapshot version or generation is invalid")
	}
	if !validName(snapshot.Provider) || !validName(snapshot.CredentialKind) || strings.TrimSpace(snapshot.Subject) == "" {
		return errors.New("provider credential snapshot identity is invalid")
	}
	if len(snapshot.FingerprintSHA256) != sha256.Size*2 {
		return errors.New("provider credential fingerprint is invalid")
	}
	if _, err := hex.DecodeString(snapshot.FingerprintSHA256); err != nil {
		return errors.New("provider credential fingerprint is invalid")
	}
	if snapshot.VerifiedAt.IsZero() || !validVerificationState(snapshot.VerificationState) {
		return errors.New("provider credential verification metadata is invalid")
	}
	if snapshot.ExpiresAt != nil && !snapshot.ExpiresAt.After(snapshot.VerifiedAt) {
		return errors.New("provider credential expiry is invalid")
	}
	return nil
}

func validateCapability(value Capability) error {
	if !validName(value.Domain) || !validPermission(value.Permission) || accessRank(value.AccessLevel) < 0 {
		return errors.New("provider credential capability is invalid")
	}
	if strings.TrimSpace(value.Resource.Kind) != value.Resource.Kind || strings.TrimSpace(value.Resource.Name) != value.Resource.Name {
		return errors.New("provider credential resource selector is invalid")
	}
	return nil
}

func validVerificationState(value VerificationState) bool {
	return slices.Contains([]VerificationState{VerificationValid, VerificationInvalid, VerificationUnavailable, VerificationInconclusive, VerificationExpired}, value)
}

func validName(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\t ")
}

func validPermission(value string) bool { return validName(value) && len(value) <= 160 }

func compareCapability(a, b Capability) int {
	return strings.Compare(capabilityKey(a), capabilityKey(b))
}

func capabilityKey(value Capability) string {
	return strings.Join([]string{value.Domain, value.Permission, string(value.AccessLevel), value.Resource.Kind, value.Resource.Name}, "\x00")
}

func capabilityDigest(capabilities []Capability) (string, error) {
	encoded, err := json.Marshal(capabilities)
	if err != nil {
		return "", errors.New("encode provider credential capabilities")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Evaluate checks one exact canonical target against a requirement.
func Evaluate(snapshot Snapshot, requirement Requirement, target Target) Evaluation {
	return EvaluateAt(snapshot, requirement, target, time.Now().UTC())
}

// EvaluateAt checks one exact target at a caller-supplied time.
func EvaluateAt(snapshot Snapshot, requirement Requirement, target Target, now time.Time) Evaluation {
	if snapshot.VerificationState != VerificationValid || snapshot.ExpiresAt != nil && !snapshot.ExpiresAt.After(now.UTC()) {
		return Evaluation{Allowed: false, Missing: []string{"credential.valid"}}
	}
	missing := make([]string, 0, len(requirement.AllOf))
	for _, clause := range requirement.AllOf {
		if clauseSatisfied(snapshot.Capabilities, clause, target) {
			continue
		}
		missing = append(missing, clauseLabel(clause))
	}
	slices.Sort(missing)
	return Evaluation{Allowed: len(missing) == 0, Missing: slices.Compact(missing)}
}

// CanSatisfy reports whether the credential can satisfy a requirement for at
// least one target. Exact resource matching remains mandatory at submission.
func CanSatisfy(snapshot Snapshot, requirement Requirement, now time.Time) bool {
	if snapshot.VerificationState != VerificationValid || snapshot.ExpiresAt != nil && !snapshot.ExpiresAt.After(now.UTC()) {
		return false
	}
	for _, clause := range requirement.AllOf {
		matched := false
		for _, need := range clause.Alternatives {
			for _, capability := range snapshot.Capabilities {
				if capability.Permission == need.Permission && (need.Domain == "" || capability.Domain == need.Domain) &&
					accessRank(capability.AccessLevel) >= accessRank(need.MinimumAccessLevel) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func clauseSatisfied(capabilities []Capability, clause AnyOf, target Target) bool {
	if len(clause.Alternatives) == 0 {
		return false
	}
	for _, need := range clause.Alternatives {
		if needSatisfied(capabilities, need, target) {
			return true
		}
	}
	return false
}

func needSatisfied(capabilities []Capability, need Need, target Target) bool {
	if !validPermission(need.Permission) || accessRank(need.MinimumAccessLevel) < 0 {
		return false
	}
	for _, capability := range capabilities {
		if capability.Permission != need.Permission || need.Domain != "" && capability.Domain != need.Domain || accessRank(capability.AccessLevel) < accessRank(need.MinimumAccessLevel) {
			continue
		}
		if capability.Resource.Name == "" || need.TargetBinding != "" && strings.EqualFold(capability.Resource.Name, target[need.TargetBinding]) {
			return true
		}
	}
	return false
}

func clauseLabel(clause AnyOf) string {
	values := make([]string, 0, len(clause.Alternatives))
	for _, need := range clause.Alternatives {
		values = append(values, need.Permission)
	}
	slices.Sort(values)
	return strings.Join(slices.Compact(values), "|")
}

func accessRank(value AccessLevel) int {
	switch value {
	case AccessNone:
		return 0
	case AccessRead:
		return 1
	case AccessWrite:
		return 2
	default:
		return -1
	}
}

// Bind returns the immutable generation and digest for an operation plan.
func Bind(snapshot Snapshot) Binding {
	return Binding{Generation: snapshot.Generation, CapabilityDigest: snapshot.CapabilityDigest}
}

// ValidateBinding rejects plans approved under another effective credential ceiling.
func ValidateBinding(snapshot Snapshot, binding Binding) error {
	if snapshot.Generation != binding.Generation || snapshot.CapabilityDigest != binding.CapabilityDigest {
		return fmt.Errorf("provider credential binding is stale")
	}
	return nil
}
