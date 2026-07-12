// Package hfplan owns immutable Hugging Face execution plans.
package hfplan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/state"
)

const (
	SchemaV1       = "hf-broker.io/plan/v1"
	MetadataSchema = "hf_plan_schema"
	MetadataDigest = "hf_plan_digest"
)

type Plan struct {
	SchemaVersion      string              `json:"schema_version"`
	Kind               string              `json:"kind"`
	ClientID           string              `json:"client_id"`
	ClientRequestID    string              `json:"client_request_id"`
	Operation          string              `json:"operation"`
	TargetKind         string              `json:"target_kind"`
	Target             map[string][]string `json:"target"`
	Constraints        Constraints         `json:"constraints"`
	CredentialSelector string              `json:"credential_selector"`
	CreatedAt          time.Time           `json:"created_at"`
}

type Constraints struct {
	Attributes               map[string][]string `json:"attributes,omitempty"`
	Mode                     string              `json:"mode"`
	RequestedDurationSeconds int64               `json:"requested_duration_seconds"`
	RequestedMaxUses         int                 `json:"requested_max_uses"`
}

type Store struct {
	database *state.Database
	now      func() time.Time
}

func NewStore(database *state.Database) (*Store, error) {
	return newStore(database, time.Now)
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

func FromRequest(request grants.Request, createdAt time.Time) Plan {
	kind := "capability_window"
	if request.Metadata["hf_grant_mode"] == "execution" {
		kind = "single_execution"
	}
	return Plan{SchemaVersion: SchemaV1, Kind: kind, ClientID: request.Client, ClientRequestID: request.ClientRequestID, Operation: request.Operation, TargetKind: request.Target.Kind,
		Target: cloneValues(request.Target.Fields), CredentialSelector: "primary", CreatedAt: createdAt.UTC(),
		Constraints: Constraints{Attributes: cloneValues(request.Attrs), Mode: request.Metadata["hf_grant_mode"],
			RequestedDurationSeconds: int64(request.Duration.Seconds()), RequestedMaxUses: request.MaxUses}}
}

func (s *Store) Put(plan Plan) (string, error) {
	if s == nil || s.database == nil {
		return "", errors.New("HF plan store is unavailable")
	}
	encoded, err := encode(plan)
	if err != nil {
		return "", err
	}
	return s.database.PutPlan(context.Background(), SchemaV1, encoded, plan.CreatedAt)
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
	if s == nil || request == nil {
		return errors.New("HF grant request is required")
	}
	digest, err := s.Put(FromRequest(*request, createdAt))
	if err != nil {
		return err
	}
	if request.Metadata == nil {
		request.Metadata = map[string]string{}
	}
	request.Metadata[MetadataSchema] = SchemaV1
	request.Metadata[MetadataDigest] = digest
	return nil
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
	if constraints.Duration > requestedDuration || constraints.MaxUses > requestedMaxUses {
		return grants.ErrConstraintExceeded
	}
	return nil
}

func requestedGrantBounds(grant grants.Grant) (time.Duration, int) {
	duration := grant.RequestedDuration
	if duration <= 0 {
		duration = grant.Duration
	}
	maxUses := grant.RequestedMaxUses
	if maxUses <= 0 {
		maxUses = grant.MaxUses
	}
	return duration, maxUses
}

func planMatchesGrant(plan Plan, grant grants.Grant, duration time.Duration, maxUses int) bool {
	return planMatchesGrantIdentity(plan, grant) && planMatchesGrantValues(plan, grant) &&
		plan.Constraints.Mode == grant.Metadata["hf_grant_mode"] &&
		plan.Constraints.RequestedDurationSeconds == int64(duration.Seconds()) && plan.Constraints.RequestedMaxUses == maxUses
}

func planMatchesGrantIdentity(plan Plan, grant grants.Grant) bool {
	return plan.ClientID == grant.Client && plan.ClientRequestID == grant.ClientRequestID &&
		plan.Operation == grant.Operation && plan.TargetKind == grant.Target.Kind
}

func planMatchesGrantValues(plan Plan, grant grants.Grant) bool {
	return equalValues(plan.Target, grant.Target.Fields) && equalValues(plan.Constraints.Attributes, grant.Attrs)
}

func encode(plan Plan) ([]byte, error) {
	if err := validate(plan); err != nil {
		return nil, err
	}
	return json.Marshal(plan)
}

func validate(plan Plan) error {
	if !validPlanIdentity(plan) || !validPlanConstraints(plan) {
		return errors.New("HF plan is invalid")
	}
	if !planKindMatchesMode(plan.Kind, plan.Constraints.Mode) {
		return errors.New("HF plan kind and mode do not match")
	}
	if err := validatePlanValues(plan.Target); err != nil {
		return err
	}
	if err := validatePlanValues(plan.Constraints.Attributes); err != nil {
		return err
	}
	return nil
}

func planKindMatchesMode(kind string, mode string) bool {
	return kind == "single_execution" && mode == "execution" || kind == "capability_window" && mode == "window"
}

func validPlanIdentity(plan Plan) bool {
	return plan.SchemaVersion == SchemaV1 && validPlanKind(plan.Kind) && strings.TrimSpace(plan.ClientID) != "" &&
		strings.TrimSpace(plan.ClientRequestID) != "" && hfpolicy.IsOperation(plan.Operation) && plan.TargetKind == "hf" && len(plan.Target) > 0
}

func validPlanKind(kind string) bool {
	return kind == "capability_window" || kind == "single_execution"
}

func validPlanConstraints(plan Plan) bool {
	return strings.TrimSpace(plan.Constraints.Mode) != "" && plan.Constraints.RequestedDurationSeconds > 0 &&
		plan.Constraints.RequestedMaxUses > 0 && plan.CredentialSelector == "primary" && !plan.CreatedAt.IsZero()
}

func validatePlanValues(values map[string][]string) error {
	for key, list := range values {
		if sensitivePlanKey(key) {
			return errors.New("HF plan contains a sensitive field")
		}
		if strings.TrimSpace(key) == "" || len(list) == 0 {
			return errors.New("HF plan contains an invalid value map")
		}
		for _, value := range list {
			if strings.TrimSpace(value) == "" {
				return errors.New("HF plan contains an invalid value map")
			}
		}
	}
	return nil
}

func sensitivePlanKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(key))
	for _, marker := range []string{"authorization", "credential", "password", "privatekey", "secret", "token", "cookie"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func cloneValues(values map[string][]string) map[string][]string {
	out := make(map[string][]string, len(values))
	for key, list := range values {
		out[key] = append([]string(nil), list...)
	}
	return out
}

func equalValues(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, values := range left {
		if !slices.Equal(values, right[key]) {
			return false
		}
	}
	return true
}
