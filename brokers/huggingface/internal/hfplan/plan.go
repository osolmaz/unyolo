// Package hfplan owns immutable Hugging Face execution plans.
package hfplan

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

	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/authorization/activation"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	hfpolicy "github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/credential/provider"
	"github.com/osolmaz/unyolo/internal/storage/state"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/operation/digest"
)

const (
	SchemaV1        = "hf-broker.io/plan/v1"
	MetadataSchema  = "hf_plan_schema"
	MetadataDigest  = "hf_plan_digest"
	MetadataTitle   = "hf_plan_title"
	MetadataSummary = "hf_plan_summary"

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
	database   *state.Database
	now        func() time.Time
	credential *providercredential.Service
}

// SetCredentialService binds every subsequently prepared plan to the active
// provider authority ceiling.
func (s *Store) SetCredentialService(service *providercredential.Service) { s.credential = service }

func NewStore(database *state.Database) (*Store, error) { return newStore(database, time.Now) }

func NewStoreWithClock(database *state.Database, now func() time.Time) (*Store, error) {
	return newStore(database, now)
}

func newStore(database *state.Database, now func() time.Time) (*Store, error) {
	if database == nil {
		return nil, errors.New("HF plan database is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{database: database, now: now}, nil
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
		CredentialSelector: CredentialSelector{Name: "primary"},
		Presentation:       agentv1.Presentation{Title: request.Operation, Summary: truncateUTF8(request.Reason, 500)},
		Authorization: Authorization{Mode: request.Metadata[grants.MetadataMode], RequestedDurationSeconds: int64(request.Duration.Seconds()),
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
		return "", errors.New("HF plan store is unavailable")
	}
	prepared, err := Prepare(plan)
	if err != nil {
		return "", err
	}
	return s.database.PutPlan(context.Background(), prepared.SchemaName, prepared.Canonical, prepared.CreatedAt)
}

func (s *Store) Get(value string) (Plan, error) {
	if s == nil || s.database == nil {
		return Plan{}, errors.New("HF plan store is unavailable")
	}
	record, err := s.database.Plan(context.Background(), value)
	if err != nil {
		return Plan{}, err
	}
	if record.SchemaName != SchemaV1 {
		return Plan{}, errors.New("HF plan schema is unsupported")
	}
	return decode(record.Canonical)
}

func decode(data []byte) (Plan, error) {
	var plan Plan
	if err := strictjson.Decode(data, &plan, true); err != nil {
		return Plan{}, fmt.Errorf("decode HF plan: %w", err)
	}
	if err := validate(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func (s *Store) Bind(request *grants.Request) error {
	if s == nil {
		return errors.New("HF grant request is required")
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
		return grants.ImmutablePlan{}, errors.New("HF grant request is required")
	}
	return s.PrepareBindAt(request, s.now().UTC())
}

func (s *Store) PrepareBindAt(request *grants.Request, createdAt time.Time) (grants.ImmutablePlan, error) {
	if s == nil || request == nil {
		return grants.ImmutablePlan{}, errors.New("HF grant request is required")
	}
	plan := FromRequest(*request, createdAt)
	if s.credential != nil {
		binding, err := s.credential.Binding()
		if err != nil {
			return grants.ImmutablePlan{}, errors.New("HF credential binding is unavailable")
		}
		plan.CredentialSelector.Binding = binding
	}
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
	Credential  *providercredential.Service
	Requirement func(string) (providercredential.Requirement, bool)
}

func (v Validator) ValidateActivation(_ context.Context, grant grants.Grant, constraints grants.ApprovalConstraints) error {
	return v.validate(grant, constraints)
}

func (v Validator) ValidateExecution(grant grants.Grant) error {
	return v.validate(grant, grants.ApprovalConstraints{})
}

func (v Validator) validate(grant grants.Grant, constraints grants.ApprovalConstraints) error {
	if v.Store == nil {
		return activation.New(activation.CodePlanUnavailable, errors.New("HF plan store is unavailable"))
	}
	if grant.Metadata[MetadataSchema] != SchemaV1 {
		return activation.New(activation.CodePlanUnavailable, errors.New("HF grant plan schema is missing or unsupported"))
	}
	plan, err := v.Store.Get(grant.Metadata[MetadataDigest])
	if err != nil {
		return activation.New(activation.CodePlanUnavailable, err)
	}
	requestedDuration, requestedMaxUses := requestedGrantBounds(grant)
	if !planMatchesGrant(plan, grant, requestedDuration, requestedMaxUses) {
		return activation.New(activation.CodePlanMismatch, errors.New("HF grant does not match its immutable plan"))
	}
	if err := v.ValidateCredential(plan); err != nil {
		return err
	}
	if constraints.Duration > requestedDuration || useConstraintExceeds(constraints, requestedMaxUses) {
		return grants.ErrConstraintExceeded
	}
	return nil
}

// ValidateCredential proves that the currently active credential still covers
// the exact authority bound into an immutable plan.
func (v Validator) ValidateCredential(plan Plan) error {
	if v.Credential == nil {
		return nil
	}
	if err := v.Credential.Validate(plan.CredentialSelector.Binding); err != nil {
		return activation.New(activation.CodeCredentialChanged, err)
	}
	if v.Requirement == nil {
		return activation.New(activation.CodeCredentialInsufficient, errors.New("HF credential requirement map is unavailable"))
	}
	requirement, found := v.Requirement(plan.Operation)
	target, targetErr := credentialTarget(plan)
	if !found || targetErr != nil || !v.Credential.Evaluate(requirement, target).Allowed {
		return activation.New(activation.CodeCredentialInsufficient, errors.Join(targetErr, errors.New("HF credential does not cover the operation target")))
	}
	return nil
}

func credentialTarget(plan Plan) (providercredential.Target, error) {
	target, err := providercredential.TargetFromJSON(plan.Target)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"owner", "namespace", "name", "repo"} {
		addCredentialTargetField(target, plan.Authorization.Target.Fields, name)
	}
	addCredentialResource(target, plan.Authorization.Target.Fields)
	return target, nil
}

func addCredentialTargetField(target providercredential.Target, fields map[string][]string, name string) {
	if value := credentialTargetField(fields, name); target[name] == "" && value != "" {
		target[name] = value
	}
}

func credentialTargetField(fields map[string][]string, name string) string {
	if values := fields[name]; len(values) == 1 {
		return values[0]
	}
	return ""
}

func addCredentialResource(target providercredential.Target, fields map[string][]string) {
	owner, name, resourceKind := credentialResourceParts(target, fields)
	if owner == "" || name == "" || resourceKind == "" {
		return
	}
	resource := owner + "/" + name
	if target["resource"] == "" {
		target["resource"] = resource
	}
	if target["resource"] == resource && target["resource_kind"] == "" {
		target["resource_kind"] = resourceKind
	}
}

func credentialResourceParts(target providercredential.Target, fields map[string][]string) (string, string, string) {
	owner := firstCredentialTargetValue(target, "owner", "namespace")
	name := firstCredentialTargetValue(target, "name", "repo")
	resourceKind := credentialTargetField(fields, "kind")
	if resourceKind == "" {
		resourceKind = target["kind"]
	}
	if owner != "" {
		return owner, name, resourceKind
	}
	return credentialRepositoryResource(name)
}

func firstCredentialTargetValue(target providercredential.Target, names ...string) string {
	for _, name := range names {
		if target[name] != "" {
			return target[name]
		}
	}
	return ""
}

func credentialRepositoryResource(value string) (string, string, string) {
	parts := strings.Split(value, "/")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return "", value, ""
	}
	switch hfpolicy.RepoType(parts[0]) {
	case hfpolicy.TypeModel, hfpolicy.TypeDataset, hfpolicy.TypeSpace, hfpolicy.TypeKernel:
		return parts[1], parts[2], string(hfpolicy.KindRepo)
	default:
		return "", value, ""
	}
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
	return planGrantIdentityMatches(plan, grant) && planGrantAuthorizationMatches(plan, grant, duration, maxUses)
}

func planGrantIdentityMatches(plan Plan, grant grants.Grant) bool {
	return plan.ClientID == grant.Client &&
		plan.ClientRequestID == grant.ClientRequestID &&
		plan.Operation == grant.Operation
}

func planGrantAuthorizationMatches(plan Plan, grant grants.Grant, duration time.Duration, maxUses usebudget.Limit) bool {
	return plan.Authorization.Target.Kind == grant.Target.Kind &&
		reflect.DeepEqual(plan.Authorization.Target.Fields, grant.Target.Fields) &&
		reflect.DeepEqual(plan.Authorization.Attributes, grant.Attrs) &&
		plan.Authorization.Mode == grant.Metadata[grants.MetadataMode] &&
		plan.Authorization.RequestedDurationSeconds == int64(duration.Seconds()) &&
		plan.Authorization.RequestedMaxUses == maxUses &&
		plan.Authorization.RequestedMaxUsesDefaulted == grant.RequestedMaxUsesDefaulted
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
		return errors.New("HF plan identity is invalid")
	}
	if !validPlanPresentation(plan.Presentation) {
		return errors.New("HF plan presentation is invalid")
	}
	if !validPlanAuthorization(plan.Authorization) {
		return errors.New("HF plan authorization is invalid")
	}
	if err := validatePlanRawMessages(plan.Target, plan.Arguments, plan.Preconditions); err != nil {
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
	return plan.APIVersion == SchemaV1 && plan.OperationRevision == 1 && hfpolicy.IsOperation(plan.Operation)
}

func validPlanClient(plan Plan) bool {
	return strings.TrimSpace(plan.ClientID) != "" && strings.TrimSpace(plan.ClientRequestID) != ""
}

func validPlanCredential(selector CredentialSelector) bool {
	return selector.Name == "primary" && validCredentialBinding(selector.Binding)
}

func validPlanTimes(plan Plan) bool {
	return !plan.CreatedAt.IsZero() && plan.ExpiresAt.After(plan.CreatedAt)
}

func validCredentialBinding(binding providercredential.Binding) bool {
	return binding.Generation == 0 && binding.CapabilityDigest == "" ||
		binding.Generation > 0 && len(binding.CapabilityDigest) == 64
}

func validPlanPresentation(presentation agentv1.Presentation) bool {
	return presentation.Title != "" &&
		len(presentation.Title) <= 160 &&
		len(presentation.Summary) <= 500
}

func validPlanAuthorization(authorization Authorization) bool {
	if authorization.Mode != "window" && authorization.Mode != "execution" {
		return false
	}
	if authorization.RequestedDurationSeconds <= 0 || authorization.RequestedMaxUses < 0 {
		return false
	}
	if authorization.Mode == "execution" && authorization.RequestedMaxUses != 1 {
		return false
	}
	return strings.TrimSpace(authorization.Target.Kind) != "" && len(authorization.Target.Fields) > 0
}

func validatePlanRawMessages(values ...json.RawMessage) error {
	for _, value := range values {
		if len(value) == 0 {
			return errors.New("HF plan contains an empty object")
		}
		if containsRawSecret(value) {
			return errors.New("HF plan contains a raw secret field")
		}
	}
	return nil
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
		for key, nested := range typed {
			if rawSecretKey(key) || hasRawSecret(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if hasRawSecret(nested) {
				return true
			}
		}
	}
	return false
}

var rawSecretNames = map[string]bool{
	"authorization": true,
	"cookie":        true,
	"password":      true,
	"private_key":   true,
	"secret":        true,
	"token":         true,
}

func rawSecretKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	if safeSecretLikeSuffix(normalized) {
		return false
	}
	return rawSecretNames[normalized] || strings.HasSuffix(normalized, "_token")
}

func safeSecretLikeSuffix(value string) bool {
	for _, suffix := range []string{"_id", "_ref", "_digest", "_name"} {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

func validateValues(values map[string][]string) error {
	for key, list := range values {
		if strings.TrimSpace(key) == "" || len(list) == 0 {
			return errors.New("HF plan contains invalid authorization attributes")
		}
		for _, value := range list {
			if strings.TrimSpace(value) == "" {
				return errors.New("HF plan contains invalid authorization attributes")
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
