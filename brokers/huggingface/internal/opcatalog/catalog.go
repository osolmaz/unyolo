// Package opcatalog owns the complete Hugging Face capability vocabulary.
package opcatalog

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

const ExpectedCount = 258

type AuthorizationMode string

const (
	ModeWindow    AuthorizationMode = "window"
	ModeExecution AuthorizationMode = "execution"
)

type ImplementationStatus string

const (
	StatusImplemented     ImplementationStatus = "implemented"
	StatusProtocol        ImplementationStatus = "protocol"
	StatusInternal        ImplementationStatus = "internal"
	StatusOperatorOnly    ImplementationStatus = "operator-only"
	StatusLocal           ImplementationStatus = "local"
	StatusBlockedUpstream ImplementationStatus = "blocked-upstream"
)

type Risk string

const (
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// DefaultPolicyEffect is the provider-owned baseline for a generated policy.
// It is stored explicitly in the catalog so policy generation never infers
// authorization from names, risk labels, or implementation details.
type DefaultPolicyEffect string

const (
	DefaultEffectAllow   DefaultPolicyEffect = "allow"
	DefaultEffectRequest DefaultPolicyEffect = "request"
	DefaultEffectDeny    DefaultPolicyEffect = "deny"
)

// Descriptor is the provider-owned registration record consumed by every HF
// broker surface. It contains no credentials or requester-controlled values.
type Descriptor struct {
	Name                 string               `json:"name"`
	OperationRevision    int                  `json:"operation_revision"`
	Disposition          string               `json:"disposition"`
	AuthorizationMode    AuthorizationMode    `json:"authorization_mode"`
	ExplicitOnly         bool                 `json:"explicit_only"`
	Sealed               bool                 `json:"sealed"`
	CredentialOutputKind *string              `json:"credential_output_kind,omitempty"`
	Internal             bool                 `json:"internal"`
	Implementation       ImplementationStatus `json:"implementation_status"`
	Risk                 Risk                 `json:"risk"`
	DefaultPolicyEffect  DefaultPolicyEffect  `json:"default_policy_effect"`
	TargetKind           string               `json:"target_kind"`
	MaxUses              int                  `json:"max_uses"`
	RequestTTLSeconds    int                  `json:"request_ttl_seconds"`
	ApprovalTTLSeconds   int                  `json:"approval_ttl_seconds"`
	FamilyGlobAllowed    bool                 `json:"family_glob_allowed"`
	AgentFacing          bool                 `json:"agent_facing"`
	MCPTool              *string              `json:"mcp_tool"`
	CLICommand           *string              `json:"cli_command"`
}

//go:embed catalog.json
var catalogJSON []byte

var (
	loadOnce sync.Once
	loaded   []Descriptor
	loadErr  error
)

var (
	operationPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`)
	targetPattern         = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	toolPattern           = regexp.MustCompile(`^hf_[a-z][a-z0-9_]*$`)
	credentialKindPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// All returns the validated, name-sorted capability catalog.
func All() ([]Descriptor, error) {
	loadOnce.Do(func() {
		if err := json.Unmarshal(catalogJSON, &loaded); err != nil {
			loadErr = fmt.Errorf("decode HF operation catalog: %w", err)
			return
		}
		loadErr = Validate(loaded)
	})
	return slices.Clone(loaded), loadErr
}

// MustAll returns the catalog or panics during broker startup.
func MustAll() []Descriptor {
	values, err := All()
	if err != nil {
		panic(err)
	}
	return values
}

// ByName returns one immutable descriptor.
func ByName(name string) (Descriptor, bool) {
	values, err := All()
	if err != nil {
		return Descriptor{}, false
	}
	index, found := slices.BinarySearchFunc(values, name, func(value Descriptor, target string) int {
		return strings.Compare(value.Name, target)
	})
	if !found {
		return Descriptor{}, false
	}
	return values[index], true
}

// Validate rejects catalog drift that could weaken policy or expose an unsafe
// operation through broad families.
func Validate(values []Descriptor) error {
	if len(values) != ExpectedCount {
		return fmt.Errorf("HF operation catalog has %d entries, want %d", len(values), ExpectedCount)
	}
	seenNames := make(map[string]bool, len(values))
	seenTools := make(map[string]bool, len(values))
	seenCommands := make(map[string]bool, len(values))
	previous := ""
	for index, value := range values {
		if err := validateDescriptor(value); err != nil {
			return fmt.Errorf("catalog entry %d: %w", index, err)
		}
		if seenNames[value.Name] || previous >= value.Name {
			return fmt.Errorf("operation %q is duplicated or out of order", value.Name)
		}
		seenNames[value.Name] = true
		previous = value.Name
		if value.MCPTool != nil {
			if seenTools[*value.MCPTool] {
				return fmt.Errorf("MCP tool %q is duplicated", *value.MCPTool)
			}
			seenTools[*value.MCPTool] = true
		}
		if value.CLICommand != nil {
			if seenCommands[*value.CLICommand] {
				return fmt.Errorf("CLI command %q is duplicated", *value.CLICommand)
			}
			seenCommands[*value.CLICommand] = true
		}
	}
	return nil
}

//nolint:cyclop // Catalog invariants are explicit and tracked by the exact HF CRAP baseline.
func validateDescriptor(value Descriptor) error {
	if !operationPattern.MatchString(value.Name) || value.OperationRevision != 1 || !targetPattern.MatchString(value.TargetKind) {
		return errors.New("operation identity is invalid")
	}
	if !validStatus(value.Implementation) || !validRisk(value.Risk) || value.RequestTTLSeconds <= 0 || value.ApprovalTTLSeconds <= 0 {
		return fmt.Errorf("operation %q has invalid lifecycle metadata", value.Name)
	}
	if err := validateDefaultPolicyEffect(value); err != nil {
		return err
	}
	if value.AuthorizationMode == ModeExecution {
		if value.MaxUses != 1 || !strings.Contains(value.Disposition, "E") {
			return fmt.Errorf("execution operation %q must be one-use E", value.Name)
		}
	} else if value.AuthorizationMode != ModeWindow || value.MaxUses < 1 || !strings.Contains(value.Disposition, "W") {
		return fmt.Errorf("window operation %q has invalid use semantics", value.Name)
	}
	if value.ExplicitOnly != strings.Contains(value.Disposition, "X") || value.Sealed != strings.Contains(value.Disposition, "S") || value.Internal != strings.Contains(value.Disposition, "I") {
		return fmt.Errorf("operation %q disposition flags drifted", value.Name)
	}
	if value.ExplicitOnly && value.FamilyGlobAllowed {
		return fmt.Errorf("explicit operation %q allows family globs", value.Name)
	}
	if value.Sealed && value.AuthorizationMode != ModeExecution {
		return fmt.Errorf("sealed operation %q is not execution-scoped", value.Name)
	}
	if value.CredentialOutputKind != nil && (!value.Sealed || !value.ExplicitOnly || !credentialKindPattern.MatchString(*value.CredentialOutputKind)) {
		return fmt.Errorf("credential output operation %q is invalid", value.Name)
	}
	if value.Internal && (value.AgentFacing || value.MCPTool != nil || value.CLICommand != nil || value.Implementation != StatusInternal) {
		return fmt.Errorf("internal operation %q is agent-facing", value.Name)
	}
	if value.AgentFacing {
		if value.MCPTool == nil || value.CLICommand == nil || !toolPattern.MatchString(*value.MCPTool) || strings.TrimSpace(*value.CLICommand) == "" {
			return fmt.Errorf("agent-facing operation %q has invalid UX metadata", value.Name)
		}
	}
	return nil
}

func validateDefaultPolicyEffect(value Descriptor) error {
	if !slices.Contains([]DefaultPolicyEffect{DefaultEffectAllow, DefaultEffectRequest, DefaultEffectDeny}, value.DefaultPolicyEffect) {
		return fmt.Errorf("operation %q has invalid default policy effect", value.Name)
	}
	requiresDeny := value.Internal || !value.AgentFacing || value.CredentialOutputKind != nil
	if requiresDeny && value.DefaultPolicyEffect != DefaultEffectDeny {
		return fmt.Errorf("operation %q must be denied by default", value.Name)
	}
	if value.DefaultPolicyEffect == DefaultEffectAllow && (value.Risk == RiskHigh || value.Risk == RiskCritical || value.AuthorizationMode == ModeExecution || value.ExplicitOnly || value.Sealed) {
		return fmt.Errorf("dangerous operation %q cannot be allowed by default", value.Name)
	}
	return nil
}

func validStatus(value ImplementationStatus) bool {
	return slices.Contains([]ImplementationStatus{StatusImplemented, StatusProtocol, StatusInternal, StatusOperatorOnly, StatusLocal, StatusBlockedUpstream}, value)
}

func validRisk(value Risk) bool {
	return slices.Contains([]Risk{RiskLow, RiskMedium, RiskHigh, RiskCritical}, value)
}
