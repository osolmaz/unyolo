// Package ghplan owns immutable GitHub execution plans.
package ghplan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	ghpolicy "github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/providercredential"
	"github.com/osolmaz/brokerkit/state"
	"github.com/osolmaz/brokerkit/usebudget"
)

const (
	SchemaV1        = "gh-broker.io/plan/v1"
	MetadataSchema  = "github_plan_schema"
	MetadataDigest  = "github_plan_digest"
	MetadataTitle   = "github_plan_title"
	MetadataSummary = "github_plan_summary"

	maxTargetBytes        = 16 * 1024
	maxArgumentsBytes     = 1024 * 1024
	maxPreconditionsBytes = 64 * 1024
)

// Plan binds every execution-relevant provider value approved by policy and
// the operator. Mutable lifecycle state and notification metadata stay out of
// the digest.
type Plan struct {
	APIVersion         string               `json:"api_version"`
	Operation          string               `json:"operation"`
	OperationRevision  int                  `json:"operation_revision"`
	ClientID           string               `json:"client_id"`
	ClientRequestID    string               `json:"client_request_id"`
	Target             json.RawMessage      `json:"target"`
	Arguments          json.RawMessage      `json:"arguments"`
	Preconditions      json.RawMessage      `json:"preconditions"`
	CredentialSelector CredentialSelector   `json:"credential_selector"`
	Presentation       agentv1.Presentation `json:"presentation"`
	Authorization      Authorization        `json:"authorization"`
	CreatedAt          time.Time            `json:"created_at"`
	ExpiresAt          time.Time            `json:"expires_at"`
}

type CredentialSelector struct {
	Name    string                     `json:"name"`
	Kind    string                     `json:"kind"`
	Binding providercredential.Binding `json:"binding"`
}

type Authorization struct {
	Mode                      string              `json:"mode"`
	RequestedDurationSeconds  int64               `json:"requested_duration_seconds"`
	RequestedMaxUses          usebudget.Limit     `json:"requested_max_uses"`
	RequestedMaxUsesDefaulted bool                `json:"requested_max_uses_defaulted,omitempty"`
	Target                    GrantTarget         `json:"target"`
	Attributes                map[string][]string `json:"attributes,omitempty"`
	PolicyEffect              string              `json:"policy_effect,omitempty"`
	PolicyRuleIDs             []string            `json:"policy_rule_ids,omitempty"`
}

type GrantTarget struct {
	Kind   string              `json:"kind"`
	Fields map[string][]string `json:"fields"`
}

type grantArguments struct {
	Attributes map[string][]string `json:"attributes,omitempty"`
}

type Store struct {
	database           *state.Database
	credentialSelector string
	now                func() time.Time
}

func NewStore(database *state.Database, credentialSelector string) (*Store, error) {
	return newStore(database, credentialSelector, time.Now)
}

func NewStoreWithClock(database *state.Database, credentialSelector string, now func() time.Time) (*Store, error) {
	return newStore(database, credentialSelector, now)
}

func newStore(database *state.Database, credentialSelector string, now func() time.Time) (*Store, error) {
	if database == nil {
		return nil, errors.New("GitHub plan database is required")
	}
	if credentialSelector != "installation" && credentialSelector != "development-token" && credentialSelector != "user" {
		return nil, errors.New("GitHub credential selector is invalid")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{database: database, credentialSelector: credentialSelector, now: now}, nil
}

// FromRequest creates the immutable plan for a bounded protocol grant.
func FromRequest(request grants.Request, createdAt time.Time) Plan {
	target, _ := json.Marshal(GrantTarget{Kind: request.Target.Kind, Fields: cloneValues(request.Target.Fields)})
	arguments, _ := json.Marshal(grantArguments{Attributes: cloneValues(request.Attrs)})
	expiresAt := createdAt.Add(request.PendingTimeout + request.Duration)
	if !expiresAt.After(createdAt) {
		expiresAt = createdAt.Add(request.Duration)
	}
	return Plan{
		APIVersion: SchemaV1, Operation: request.Operation, OperationRevision: 1,
		ClientID: request.Client, ClientRequestID: request.ClientRequestID,
		Target: target, Arguments: arguments, Preconditions: json.RawMessage(`{}`),
		CredentialSelector: CredentialSelector{Name: "primary", Kind: modeCredentialKind(request.Operation, "")},
		Presentation:       agentv1.Presentation{Title: request.Operation, Summary: truncateUTF8(request.Reason, 500)},
		Authorization: Authorization{Mode: modeForOperation(request.Operation, request.Metadata["github_grant_mode"]), RequestedDurationSeconds: int64(request.Duration.Seconds()),
			RequestedMaxUses: request.MaxUses, RequestedMaxUsesDefaulted: request.MaxUsesDefaulted,
			Target: GrantTarget{Kind: request.Target.Kind, Fields: cloneValues(request.Target.Fields)}, Attributes: cloneValues(request.Attrs)},
		CreatedAt: createdAt.UTC(), ExpiresAt: expiresAt.UTC(),
	}
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

// Prepare canonicalizes and validates a plan without persisting it.
func Prepare(plan Plan) (grants.ImmutablePlan, error) {
	encoded, err := encode(plan)
	if err != nil {
		return grants.ImmutablePlan{}, err
	}
	return grants.ImmutablePlan{Digest: plandigest.Digest(encoded), SchemaName: SchemaV1, Canonical: encoded, CreatedAt: plan.CreatedAt.UTC()}, nil
}

func (s *Store) Put(plan Plan) (string, error) {
	if s == nil || s.database == nil {
		return "", errors.New("GitHub plan store is unavailable")
	}
	prepared, err := Prepare(plan)
	if err != nil {
		return "", err
	}
	return s.database.PutPlan(context.Background(), prepared.SchemaName, prepared.Canonical, prepared.CreatedAt)
}

func (s *Store) Get(value string) (Plan, error) {
	if s == nil || s.database == nil {
		return Plan{}, errors.New("GitHub plan store is unavailable")
	}
	record, err := s.database.Plan(context.Background(), value)
	if err != nil {
		return Plan{}, err
	}
	if record.SchemaName != SchemaV1 {
		return Plan{}, errors.New("GitHub plan schema is unsupported")
	}
	return decode(record.Canonical)
}

func decode(data []byte) (Plan, error) {
	var plan Plan
	if err := strictjson.Decode(data, &plan, true); err != nil {
		return Plan{}, fmt.Errorf("decode GitHub plan: %w", err)
	}
	if err := validate(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func (s *Store) Bind(request *grants.Request) error {
	if s == nil {
		return errors.New("GitHub grant request is required")
	}
	return s.BindAt(request, s.now().UTC())
}

func (s *Store) BindAt(request *grants.Request, createdAt time.Time) error {
	prepared, err := s.PrepareBindAt(request, createdAt)
	if err != nil {
		return err
	}
	_, err = s.database.PutPlan(context.Background(), prepared.SchemaName, prepared.Canonical, prepared.CreatedAt)
	return err
}

func (s *Store) PrepareBind(request *grants.Request) (grants.ImmutablePlan, error) {
	if s == nil {
		return grants.ImmutablePlan{}, errors.New("GitHub grant request is required")
	}
	return s.PrepareBindAt(request, s.now().UTC())
}

func (s *Store) PrepareBindAt(request *grants.Request, createdAt time.Time) (grants.ImmutablePlan, error) {
	if s == nil || request == nil {
		return grants.ImmutablePlan{}, errors.New("GitHub grant request is required")
	}
	if request.Metadata == nil {
		request.Metadata = map[string]string{}
	}
	request.Metadata["github_grant_mode"] = modeForOperation(request.Operation, request.Metadata["github_grant_mode"])
	plan := FromRequest(*request, createdAt)
	plan.CredentialSelector.Kind = modeCredentialKind(request.Operation, s.credentialSelector)
	prepared, err := Prepare(plan)
	if err != nil {
		return grants.ImmutablePlan{}, err
	}
	BindPrepared(request, prepared)
	BindPresentation(request, plan.Presentation)
	return prepared, nil
}

// BindPresentation copies the bounded, redacted plan projection into grant
// metadata consumed by transports that intentionally cannot read plan bodies.
func BindPresentation(request *grants.Request, presentation agentv1.Presentation) {
	if request.Metadata == nil {
		request.Metadata = map[string]string{}
	}
	request.Metadata[MetadataTitle] = truncateUTF8(strings.TrimSpace(presentation.Title), 160)
	request.Metadata[MetadataSummary] = truncateUTF8(strings.TrimSpace(presentation.Summary), 500)
}

// BindPrepared links a canonical immutable plan to one grant request.
func BindPrepared(request *grants.Request, prepared grants.ImmutablePlan) {
	if request.Metadata == nil {
		request.Metadata = map[string]string{}
	}
	request.Metadata[MetadataSchema] = prepared.SchemaName
	request.Metadata[MetadataDigest] = prepared.Digest
}

type Validator struct {
	Store       *Store
	Credential  func(Plan) (providercredential.Snapshot, error)
	Requirement func(string) (providercredential.Requirement, bool)
}

func (v Validator) ValidateActivation(_ context.Context, grant grants.Grant, constraints grants.ApprovalConstraints) error {
	return v.validate(grant, constraints)
}

func (v Validator) ValidateExecution(grant grants.Grant) error {
	return v.validate(grant, grants.ApprovalConstraints{})
}

func (v Validator) validate(grant grants.Grant, constraints grants.ApprovalConstraints) error {
	plan, requestedDuration, requestedMaxUses, err := v.loadGrantPlan(grant)
	if err != nil {
		return err
	}
	if err := v.validateCredential(plan); err != nil {
		return err
	}
	if constraints.Duration > requestedDuration || useConstraintExceeds(constraints, requestedMaxUses) {
		return grants.ErrConstraintExceeded
	}
	return nil
}

func (v Validator) loadGrantPlan(grant grants.Grant) (Plan, time.Duration, usebudget.Limit, error) {
	if v.Store == nil {
		return Plan{}, 0, 0, errors.New("GitHub plan store is unavailable")
	}
	if grant.Metadata[MetadataSchema] != SchemaV1 {
		return Plan{}, 0, 0, errors.New("GitHub grant plan schema is missing or unsupported")
	}
	plan, err := v.Store.Get(grant.Metadata[MetadataDigest])
	if err != nil {
		return Plan{}, 0, 0, err
	}
	requestedDuration, requestedMaxUses := requestedGrantBounds(grant)
	if !planMatchesGrant(plan, grant, requestedDuration, requestedMaxUses) {
		return Plan{}, 0, 0, errors.New("GitHub grant does not match its immutable plan")
	}
	return plan, requestedDuration, requestedMaxUses, nil
}

func (v Validator) validateCredential(plan Plan) error {
	if v.Credential == nil || plan.CredentialSelector.Binding.Generation == 0 {
		return nil
	}
	if v.Requirement == nil {
		return errors.New("GitHub credential requirement map is unavailable")
	}
	snapshot, credentialErr := v.Credential(plan)
	requirement, found := v.Requirement(plan.Operation)
	if credentialErr != nil || !found || providercredential.ValidateBinding(snapshot, plan.CredentialSelector.Binding) != nil ||
		!providercredential.EvaluateAt(snapshot, requirement, nil, plan.CreatedAt).Allowed {
		return errors.New("GitHub credential binding is stale or insufficient")
	}
	return nil
}

func useConstraintExceeds(constraints grants.ApprovalConstraints, requested usebudget.Limit) bool {
	if !constraints.MaxUsesSpecified && !constraints.MaxUses.IsFinite() {
		return false
	}
	return requested.IsFinite() && (constraints.MaxUses.IsUnlimited() || constraints.MaxUses > requested)
}

func requestedGrantBounds(grant grants.Grant) (time.Duration, usebudget.Limit) {
	duration := grant.RequestedDuration
	if duration <= 0 {
		duration = grant.Duration
	}
	maxUses := grant.RequestedMaxUses
	if maxUses < 0 {
		maxUses = grant.MaxUses
	}
	return duration, maxUses
}

func planMatchesGrant(plan Plan, grant grants.Grant, duration time.Duration, maxUses usebudget.Limit) bool {
	return planMatchesGrantIdentity(plan, grant) && planMatchesGrantAuthorization(plan.Authorization, grant, duration, maxUses)
}

func planMatchesGrantIdentity(plan Plan, grant grants.Grant) bool {
	return plan.ClientID == grant.Client && plan.ClientRequestID == grant.ClientRequestID && plan.Operation == grant.Operation
}

func planMatchesGrantAuthorization(auth Authorization, grant grants.Grant, duration time.Duration, maxUses usebudget.Limit) bool {
	return auth.Target.Kind == grant.Target.Kind && reflect.DeepEqual(auth.Target.Fields, grant.Target.Fields) &&
		reflect.DeepEqual(auth.Attributes, grant.Attrs) && auth.Mode == grant.Metadata["github_grant_mode"] &&
		auth.RequestedDurationSeconds == int64(duration.Seconds()) && auth.RequestedMaxUses == maxUses &&
		auth.RequestedMaxUsesDefaulted == grant.RequestedMaxUsesDefaulted
}

func encode(plan Plan) ([]byte, error) {
	canonical, err := canonicalize(plan)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

func canonicalize(plan Plan) (Plan, error) {
	var err error
	if plan.Target, err = canonicalObject(plan.Target, maxTargetBytes); err != nil {
		return Plan{}, fmt.Errorf("target: %w", err)
	}
	if plan.Arguments, err = canonicalObject(plan.Arguments, maxArgumentsBytes); err != nil {
		return Plan{}, fmt.Errorf("arguments: %w", err)
	}
	if plan.Preconditions, err = canonicalObject(plan.Preconditions, maxPreconditionsBytes); err != nil {
		return Plan{}, fmt.Errorf("preconditions: %w", err)
	}
	if err := validate(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func validate(plan Plan) error {
	if !validPlanIdentity(plan) {
		return errors.New("GitHub plan identity is invalid")
	}
	if !validPresentation(plan.Presentation) {
		return errors.New("GitHub plan presentation is invalid")
	}
	if !validAuthorization(plan.Authorization) {
		return errors.New("GitHub plan authorization is invalid")
	}
	if err := validateRawObjects(plan.Target, plan.Arguments, plan.Preconditions); err != nil {
		return err
	}
	if err := validateValues(plan.Authorization.Target.Fields); err != nil {
		return err
	}
	return validateValues(plan.Authorization.Attributes)
}

func validPlanIdentity(plan Plan) bool {
	return validPlanSchema(plan) && validPlanClient(plan) && validPlanCredential(plan.CredentialSelector) && validPlanTimes(plan)
}

func validPlanSchema(plan Plan) bool {
	return plan.APIVersion == SchemaV1 && plan.OperationRevision == 1 && ghpolicy.IsOperation(plan.Operation)
}

func validPlanClient(plan Plan) bool {
	return strings.TrimSpace(plan.ClientID) != "" && strings.TrimSpace(plan.ClientRequestID) != ""
}

func validPlanCredential(value CredentialSelector) bool {
	return value.Name == "primary" && validCredentialKind(value.Kind) && validCredentialBinding(value.Binding)
}

func validCredentialBinding(binding providercredential.Binding) bool {
	return binding.Generation == 0 && binding.CapabilityDigest == "" || binding.Generation > 0 && len(binding.CapabilityDigest) == 64
}

func validPlanTimes(plan Plan) bool {
	return !plan.CreatedAt.IsZero() && plan.ExpiresAt.After(plan.CreatedAt)
}

func validPresentation(value agentv1.Presentation) bool {
	return value.Title != "" && len(value.Title) <= 160 && len(value.Summary) <= 500
}

func validAuthorization(value Authorization) bool {
	if !validAuthorizationMode(value) {
		return false
	}
	if !validAuthorizationBounds(value) {
		return false
	}
	if value.Mode == "execution" && value.RequestedMaxUses != 1 {
		return false
	}
	return strings.TrimSpace(value.Target.Kind) != "" && len(value.Target.Fields) > 0
}

func validAuthorizationMode(value Authorization) bool {
	return value.Mode == "window" || value.Mode == "execution"
}

func validAuthorizationBounds(value Authorization) bool {
	return value.RequestedDurationSeconds > 0 && value.RequestedMaxUses >= 0
}

func validateRawObjects(values ...json.RawMessage) error {
	for _, value := range values {
		if len(value) == 0 {
			return errors.New("GitHub plan contains an empty object")
		}
		if containsRawSecret(value) {
			return errors.New("GitHub plan contains a raw secret field")
		}
	}
	return nil
}

func modeForOperation(operation, value string) string {
	if value == "window" || value == "execution" {
		return value
	}
	if descriptor, found := opcatalog.ByName(operation); found && descriptor.AuthorizationMode == opcatalog.ModeExecution {
		return "execution"
	}
	return "window"
}

func modeCredentialKind(operation, fallback string) string {
	if descriptor, found := opcatalog.ByName(operation); found {
		return descriptor.CredentialKind
	}
	return fallback
}

func validCredentialKind(value string) bool {
	return value == "installation" || value == "user" || value == "app-jwt" || value == "development-token"
}

func canonicalObject(value json.RawMessage, maximum int) (json.RawMessage, error) {
	if len(value) < 2 || len(value) > maximum {
		return nil, errors.New("JSON object size is invalid")
	}
	var object map[string]json.RawMessage
	if err := strictjson.Decode(value, &object, true); err != nil || object == nil {
		return nil, errors.New("value must be a closed JSON object")
	}
	return json.Marshal(object)
}

func containsRawSecret(value json.RawMessage) bool {
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return true
	}
	return hasRawSecret(decoded)
}

func hasRawSecret(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		return mapHasRawSecret(typed)
	case []any:
		return listHasRawSecret(typed)
	}
	return false
}

func mapHasRawSecret(values map[string]any) bool {
	for key, nested := range values {
		if rawSecretKey(key) || hasRawSecret(nested) {
			return true
		}
	}
	return false
}

func listHasRawSecret(values []any) bool {
	for _, nested := range values {
		if hasRawSecret(nested) {
			return true
		}
	}
	return false
}

func rawSecretKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	if strings.HasSuffix(normalized, "_id") || strings.HasSuffix(normalized, "_ref") || strings.HasSuffix(normalized, "_digest") || strings.HasSuffix(normalized, "_name") {
		return false
	}
	return rawSecretKeys[normalized] || strings.HasSuffix(normalized, "_token")
}

var rawSecretKeys = map[string]bool{
	"authorization": true,
	"cookie":        true,
	"password":      true,
	"private_key":   true,
	"secret":        true,
	"token":         true,
}

func validateValues(values map[string][]string) error {
	for key, list := range values {
		if strings.TrimSpace(key) == "" || len(list) == 0 {
			return errors.New("GitHub plan contains invalid authorization attributes")
		}
		for _, value := range list {
			if strings.TrimSpace(value) == "" {
				return errors.New("GitHub plan contains invalid authorization attributes")
			}
		}
	}
	return nil
}

func cloneValues(values map[string][]string) map[string][]string {
	out := make(map[string][]string, len(values))
	for key, list := range values {
		out[key] = append([]string(nil), list...)
	}
	return out
}
