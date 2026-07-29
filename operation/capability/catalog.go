// Package capability defines provider-neutral operation catalog metadata and
// structural validation. Providers own the catalog values and their semantics.
package capability

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/authorization/budget"
)

type AuthorizationMode string

const (
	ModeWindow    AuthorizationMode = "window"
	ModeExecution AuthorizationMode = "execution"
)

type ImplementationStatus string

const (
	StatusImplemented       ImplementationStatus = "implemented"
	StatusProtocol          ImplementationStatus = "protocol"
	StatusGraphQL           ImplementationStatus = "graphql"
	StatusInternal          ImplementationStatus = "internal"
	StatusOperatorOnly      ImplementationStatus = "operator-only"
	StatusLocal             ImplementationStatus = "local"
	StatusDuplicate         ImplementationStatus = "duplicate"
	StatusBlockedCredential ImplementationStatus = "blocked-credential"
	StatusBlockedUpstream   ImplementationStatus = "blocked-upstream"
	// StatusCataloged means the typed operation is frozen and generated, but its
	// credential provider and upstream executor have not been enabled yet.
	StatusCataloged ImplementationStatus = "cataloged"
)

type Risk string

const (
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// DefaultPolicyEffect is the provider-owned baseline for generated policy.
type DefaultPolicyEffect string

const (
	DefaultEffectAllow   DefaultPolicyEffect = "allow"
	DefaultEffectRequest DefaultPolicyEffect = "request"
	DefaultEffectDeny    DefaultPolicyEffect = "deny"
)

// Descriptor is provider-owned registration metadata. It contains no
// credentials or requester-controlled values.
type Descriptor struct {
	Name                     string               `json:"name"`
	OperationRevision        int                  `json:"operation_revision"`
	Summary                  string               `json:"summary,omitempty"`
	Disposition              string               `json:"disposition"`
	DefaultAuthorizationMode AuthorizationMode    `json:"default_authorization_mode"`
	AuthorizationModes       []AuthorizationMode  `json:"authorization_modes"`
	ExplicitOnly             bool                 `json:"explicit_only"`
	Sealed                   bool                 `json:"sealed"`
	CredentialOutputKind     *string              `json:"credential_output_kind,omitempty"`
	Internal                 bool                 `json:"internal"`
	Implementation           ImplementationStatus `json:"implementation_status"`
	Risk                     Risk                 `json:"risk"`
	DefaultPolicyEffect      DefaultPolicyEffect  `json:"default_policy_effect,omitempty"`
	TargetKind               string               `json:"target_kind"`
	MaxUses                  int                  `json:"max_uses"`
	RequestTTLSeconds        int                  `json:"request_ttl_seconds"`
	ApprovalTTLSeconds       int                  `json:"approval_ttl_seconds"`
	FamilyGlobAllowed        bool                 `json:"family_glob_allowed"`
	AgentFacing              bool                 `json:"agent_facing"`
	MCPTool                  *string              `json:"mcp_tool"`
	CLICommand               *string              `json:"cli_command"`
	TargetSchema             string               `json:"target_schema,omitempty"`
	ArgumentSchema           string               `json:"argument_schema,omitempty"`
	ResultSchema             string               `json:"result_schema,omitempty"`
	CredentialKind           string               `json:"credential_kind,omitempty"`
	SealedInputPaths         []string             `json:"sealed_input_paths,omitempty"`
	UpstreamBindingIDs       []string             `json:"upstream_binding_ids,omitempty"`
	ExecutorKind             string               `json:"executor_kind,omitempty"`
	ReconcilerKind           string               `json:"reconciler_kind,omitempty"`
}

// ValidationOptions contains provider registration constraints without
// embedding provider vocabulary in the shared package.
type ValidationOptions struct {
	Provider                   string
	ExpectedCount              int
	MCPToolPrefix              string
	RequireDefaultPolicyEffect bool
}

var (
	operationPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`)
	targetPattern         = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	toolPattern           = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	credentialKindPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// Validate rejects catalog drift that could weaken policy or expose an unsafe
// operation through broad families.
func Validate(values []Descriptor, options ValidationOptions) error {
	if err := validateOptions(options); err != nil {
		return err
	}
	if len(values) != options.ExpectedCount {
		return fmt.Errorf("%s operation catalog has %d entries, want %d", options.Provider, len(values), options.ExpectedCount)
	}
	registry := newCatalogIndex(len(values))
	for index, value := range values {
		if err := registry.add(index, value, options); err != nil {
			return err
		}
	}
	return nil
}

type catalogIndex struct {
	names, tools, commands map[string]bool
	previous               string
}

func newCatalogIndex(size int) *catalogIndex {
	return &catalogIndex{names: make(map[string]bool, size), tools: make(map[string]bool, size), commands: make(map[string]bool, size)}
}

func (c *catalogIndex) add(position int, value Descriptor, options ValidationOptions) error {
	if err := validateDescriptor(value, options); err != nil {
		return fmt.Errorf("catalog entry %d: %w", position, err)
	}
	if c.names[value.Name] || c.previous >= value.Name {
		return fmt.Errorf("operation %q is duplicated or out of order", value.Name)
	}
	c.names[value.Name], c.previous = true, value.Name
	if err := registerOptional("MCP tool", value.MCPTool, c.tools); err != nil {
		return err
	}
	return registerOptional("CLI command", value.CLICommand, c.commands)
}

func validateOptions(options ValidationOptions) error {
	if strings.TrimSpace(options.Provider) == "" || options.ExpectedCount <= 0 {
		return errors.New("capability validation options are incomplete")
	}
	if options.MCPToolPrefix == "" || !toolPattern.MatchString(options.MCPToolPrefix+"operation") {
		return errors.New("MCP tool prefix is invalid")
	}
	return nil
}

func registerOptional(kind string, value *string, seen map[string]bool) error {
	if value == nil {
		return nil
	}
	if seen[*value] {
		return fmt.Errorf("%s %q is duplicated", kind, *value)
	}
	seen[*value] = true
	return nil
}

func validateDescriptor(value Descriptor, options ValidationOptions) error {
	if !validIdentity(value) {
		return errors.New("operation identity is invalid")
	}
	if !validLifecycle(value) {
		return fmt.Errorf("operation %q has invalid lifecycle metadata", value.Name)
	}
	if options.RequireDefaultPolicyEffect {
		if err := validateDefaultPolicyEffect(value); err != nil {
			return err
		}
	}
	if err := validateAuthorization(value); err != nil {
		return err
	}
	if err := validateDisposition(value); err != nil {
		return err
	}
	return validateSurface(value, options.MCPToolPrefix)
}

func validIdentity(value Descriptor) bool {
	return !slices.Contains([]bool{operationPattern.MatchString(value.Name), value.OperationRevision == 1, targetPattern.MatchString(value.TargetKind)}, false)
}

func validLifecycle(value Descriptor) bool {
	return !slices.Contains([]bool{validStatus(value.Implementation), validRisk(value.Risk), value.RequestTTLSeconds > 0, value.ApprovalTTLSeconds > 0}, false)
}

func validateAuthorization(value Descriptor) error {
	if value.DefaultAuthorizationMode != ModeWindow {
		return fmt.Errorf("operation %q must default to window authorization", value.Name)
	}
	if !slices.Equal(value.AuthorizationModes, []AuthorizationMode{ModeWindow, ModeExecution}) {
		return fmt.Errorf("operation %q must support window and execution authorization", value.Name)
	}
	if value.MaxUses < 2 || value.MaxUses > int(usebudget.MaxFiniteUses) {
		return fmt.Errorf("operation %q has invalid reusable window use semantics", value.Name)
	}
	return nil
}

// AllowsAuthorizationMode reports whether the capability supports mode.
func (value Descriptor) AllowsAuthorizationMode(mode AuthorizationMode) bool {
	return slices.Contains(value.AuthorizationModes, mode)
}

// HasExecutionDisposition reports whether the provider operation performs a
// bounded external action. Grant mode is independent of this property.
func (value Descriptor) HasExecutionDisposition() bool {
	return strings.Contains(value.Disposition, "E")
}

func validateDisposition(value Descriptor) error {
	if value.ExplicitOnly != strings.Contains(value.Disposition, "X") || value.Sealed != strings.Contains(value.Disposition, "S") || value.Internal != strings.Contains(value.Disposition, "I") {
		return fmt.Errorf("operation %q disposition flags drifted", value.Name)
	}
	return validateSecretDisposition(value)
}

func validateSecretDisposition(value Descriptor) error {
	if value.ExplicitOnly && value.FamilyGlobAllowed {
		return fmt.Errorf("explicit operation %q allows family globs", value.Name)
	}
	if invalidCredentialOutput(value) {
		return fmt.Errorf("credential output operation %q is invalid", value.Name)
	}
	return nil
}

func invalidCredentialOutput(value Descriptor) bool {
	if value.CredentialOutputKind == nil {
		return false
	}
	return !value.Sealed || !value.ExplicitOnly || !credentialKindPattern.MatchString(*value.CredentialOutputKind)
}

func validateSurface(value Descriptor, toolPrefix string) error {
	if value.Internal && !validInternalSurface(value) {
		return fmt.Errorf("internal operation %q is agent-facing", value.Name)
	}
	if value.AgentFacing && !validAgentSurface(value, toolPrefix) {
		return fmt.Errorf("agent-facing operation %q has invalid UX metadata", value.Name)
	}
	return nil
}

func validateDefaultPolicyEffect(value Descriptor) error {
	if !slices.Contains([]DefaultPolicyEffect{DefaultEffectAllow, DefaultEffectRequest, DefaultEffectDeny}, value.DefaultPolicyEffect) {
		return fmt.Errorf("operation %q has invalid default policy effect", value.Name)
	}
	if operationRequiresDefaultDeny(value) && value.DefaultPolicyEffect != DefaultEffectDeny {
		return fmt.Errorf("operation %q must be denied by default", value.Name)
	}
	if value.DefaultPolicyEffect == DefaultEffectAllow && operationIsUnsafeDefaultAllow(value) {
		return fmt.Errorf("dangerous operation %q cannot be allowed by default", value.Name)
	}
	return nil
}

func operationRequiresDefaultDeny(value Descriptor) bool {
	return value.Internal || !value.AgentFacing || value.CredentialOutputKind != nil
}

func operationIsUnsafeDefaultAllow(value Descriptor) bool {
	return value.Risk == RiskHigh || value.Risk == RiskCritical || strings.Contains(value.Disposition, "E") || value.ExplicitOnly || value.Sealed
}

func validInternalSurface(value Descriptor) bool {
	if value.AgentFacing || value.MCPTool != nil || value.CLICommand != nil {
		return false
	}
	return value.Implementation == StatusInternal || value.Implementation == StatusCataloged
}

func validAgentSurface(value Descriptor, toolPrefix string) bool {
	return value.MCPTool != nil && value.CLICommand != nil &&
		strings.HasPrefix(*value.MCPTool, toolPrefix) && toolPattern.MatchString(*value.MCPTool) &&
		strings.TrimSpace(*value.CLICommand) != ""
}

func validStatus(value ImplementationStatus) bool {
	return slices.Contains([]ImplementationStatus{
		StatusImplemented, StatusProtocol, StatusGraphQL, StatusInternal,
		StatusOperatorOnly, StatusLocal, StatusDuplicate,
		StatusBlockedCredential, StatusBlockedUpstream,
		StatusCataloged,
	}, value)
}

func validRisk(value Risk) bool {
	return slices.Contains([]Risk{RiskLow, RiskMedium, RiskHigh, RiskCritical}, value)
}
