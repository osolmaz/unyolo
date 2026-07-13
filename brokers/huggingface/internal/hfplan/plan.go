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

	"github.com/osolmaz/brokerkit/agentv1"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/state"
	"github.com/osolmaz/brokerkit/usebudget"
)

const (
	SchemaV1       = "hf-broker.io/plan/v1"
	MetadataSchema = "hf_plan_schema"
	MetadataDigest = "hf_plan_digest"

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
	Name string `json:"name"`
}

type Authorization struct {
	Mode                      string              `json:"mode"`
	RequestedDurationSeconds  int64               `json:"requested_duration_seconds"`
	RequestedMaxUses          usebudget.Limit     `json:"requested_max_uses"`
	RequestedMaxUsesDefaulted bool                `json:"requested_max_uses_defaulted,omitempty"`
	Target                    GrantTarget         `json:"target"`
	Attributes                map[string][]string `json:"attributes,omitempty"`
}

type GrantTarget struct {
	Kind   string              `json:"kind"`
	Fields map[string][]string `json:"fields"`
}

type grantArguments struct {
	Attributes map[string][]string `json:"attributes,omitempty"`
}

type Store struct {
	database *state.Database
	now      func() time.Time
}

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
		Authorization: Authorization{Mode: request.Metadata["hf_grant_mode"], RequestedDurationSeconds: int64(request.Duration.Seconds()),
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
	prepared, err := Prepare(FromRequest(*request, createdAt))
	if err != nil {
		return grants.ImmutablePlan{}, err
	}
	BindPrepared(request, prepared)
	return prepared, nil
}

// BindPrepared links a canonical immutable plan to one grant request.
func BindPrepared(request *grants.Request, prepared grants.ImmutablePlan) {
	if request.Metadata == nil {
		request.Metadata = map[string]string{}
	}
	request.Metadata[MetadataSchema] = prepared.SchemaName
	request.Metadata[MetadataDigest] = prepared.Digest
}

type Validator struct{ Store *Store }

func (v Validator) ValidateActivation(_ context.Context, grant grants.Grant, constraints grants.ApprovalConstraints) error {
	return v.validate(grant, constraints)
}

func (v Validator) ValidateExecution(grant grants.Grant) error {
	return v.validate(grant, grants.ApprovalConstraints{})
}

func (v Validator) validate(grant grants.Grant, constraints grants.ApprovalConstraints) error {
	if v.Store == nil {
		return errors.New("HF plan store is unavailable")
	}
	if grant.Metadata[MetadataSchema] != SchemaV1 {
		return errors.New("HF grant plan schema is missing or unsupported")
	}
	plan, err := v.Store.Get(grant.Metadata[MetadataDigest])
	if err != nil {
		return err
	}
	requestedDuration, requestedMaxUses := requestedGrantBounds(grant)
	if !planMatchesGrant(plan, grant, requestedDuration, requestedMaxUses) {
		return errors.New("HF grant does not match its immutable plan")
	}
	if constraints.Duration > requestedDuration || useConstraintExceeds(constraints, requestedMaxUses) {
		return grants.ErrConstraintExceeded
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
	return plan.ClientID == grant.Client && plan.ClientRequestID == grant.ClientRequestID && plan.Operation == grant.Operation &&
		plan.Authorization.Target.Kind == grant.Target.Kind && reflect.DeepEqual(plan.Authorization.Target.Fields, grant.Target.Fields) && reflect.DeepEqual(plan.Authorization.Attributes, grant.Attrs) &&
		plan.Authorization.Mode == grant.Metadata["hf_grant_mode"] && plan.Authorization.RequestedDurationSeconds == int64(duration.Seconds()) &&
		plan.Authorization.RequestedMaxUses == maxUses && plan.Authorization.RequestedMaxUsesDefaulted == grant.RequestedMaxUsesDefaulted
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
	if plan.APIVersion != SchemaV1 || plan.OperationRevision != 1 || !hfpolicy.IsOperation(plan.Operation) ||
		strings.TrimSpace(plan.ClientID) == "" || strings.TrimSpace(plan.ClientRequestID) == "" ||
		plan.CredentialSelector.Name != "primary" || plan.CreatedAt.IsZero() || !plan.ExpiresAt.After(plan.CreatedAt) {
		return errors.New("HF plan identity is invalid")
	}
	if plan.Presentation.Title == "" || len(plan.Presentation.Title) > 160 || len(plan.Presentation.Summary) > 500 {
		return errors.New("HF plan presentation is invalid")
	}
	if plan.Authorization.Mode != "window" && plan.Authorization.Mode != "execution" ||
		plan.Authorization.RequestedDurationSeconds <= 0 || plan.Authorization.RequestedMaxUses < 0 ||
		plan.Authorization.Mode == "execution" && plan.Authorization.RequestedMaxUses != 1 ||
		strings.TrimSpace(plan.Authorization.Target.Kind) == "" || len(plan.Authorization.Target.Fields) == 0 {
		return errors.New("HF plan authorization is invalid")
	}
	for _, value := range []json.RawMessage{plan.Target, plan.Arguments, plan.Preconditions} {
		if len(value) == 0 {
			return errors.New("HF plan contains an empty object")
		}
		if containsRawSecret(value) {
			return errors.New("HF plan contains a raw secret field")
		}
	}
	if err := validateValues(plan.Authorization.Target.Fields); err != nil {
		return err
	}
	return validateValues(plan.Authorization.Attributes)
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

func rawSecretKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	if strings.HasSuffix(normalized, "_id") || strings.HasSuffix(normalized, "_ref") || strings.HasSuffix(normalized, "_digest") || strings.HasSuffix(normalized, "_name") {
		return false
	}
	return normalized == "authorization" || normalized == "cookie" || normalized == "password" || normalized == "private_key" || normalized == "secret" || normalized == "token" || strings.HasSuffix(normalized, "_token")
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
