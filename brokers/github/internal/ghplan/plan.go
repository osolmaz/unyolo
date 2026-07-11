// Package ghplan owns immutable GitHub execution plans.
package ghplan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/planstore"
)

const (
	SchemaV1       = "gh-broker.io/plan/v1"
	MetadataSchema = "github_plan_schema"
	MetadataDigest = "github_plan_digest"
	MetadataMode   = "github_plan_mode"
)

const (
	KindCapabilityWindow = "capability_window"
	KindSingleExecution  = "single_execution"
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
	RequestedDurationSeconds int64               `json:"requested_duration_seconds"`
	RequestedMaxUses         int                 `json:"requested_max_uses"`
}

type Store struct {
	shared             *planstore.Store
	credentialSelector string
	now                func() time.Time
}

func NewStore(directory string, credentialSelector string) (*Store, error) {
	return newStore(directory, credentialSelector, time.Now)
}

func newStore(directory string, credentialSelector string, now func() time.Time) (*Store, error) {
	if credentialSelector != "github_app" && credentialSelector != "development_pat" {
		return nil, errors.New("GitHub credential selector is invalid")
	}
	shared, err := planstore.New(directory, "GitHub")
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Store{shared: shared, credentialSelector: credentialSelector, now: now}, nil
}

func FromRequest(request grants.Request, credentialSelector string, createdAt time.Time) Plan {
	kind := request.Metadata[MetadataMode]
	if kind == "" {
		kind, _ = kindForOperation(request.Operation)
	}
	return Plan{
		SchemaVersion: SchemaV1, Kind: kind, ClientID: request.Client, ClientRequestID: request.ClientRequestID,
		Operation: request.Operation, TargetKind: request.Target.Kind, Target: cloneValues(request.Target.Fields),
		Constraints:        Constraints{Attributes: cloneValues(request.Attrs), RequestedDurationSeconds: int64(request.Duration.Seconds()), RequestedMaxUses: request.MaxUses},
		CredentialSelector: credentialSelector, CreatedAt: createdAt.UTC(),
	}
}

func kindForOperation(operation string) (string, bool) {
	switch operation {
	case "git.push.branch_create", "git.push.fast_forward", "git.push.force", "git.ref.delete", "git.tag.update":
		return KindCapabilityWindow, true
	case "pr.create", "pr.update", "pr.merge":
		return KindSingleExecution, true
	default:
		return "", false
	}
}

func (s *Store) Put(plan Plan) (string, error) {
	if s == nil || s.shared == nil {
		return "", errors.New("GitHub plan store is unavailable")
	}
	encoded, err := encode(plan)
	if err != nil {
		return "", err
	}
	return s.shared.Put(encoded)
}

func (s *Store) Get(digest string) (Plan, error) {
	if s == nil || s.shared == nil {
		return Plan{}, errors.New("GitHub plan store is unavailable")
	}
	data, err := s.shared.Get(digest)
	if err != nil {
		return Plan{}, err
	}
	return decode(data)
}

func decode(data []byte) (Plan, error) {
	if err := strictjson.RejectDuplicateKeys(data); err != nil {
		return Plan{}, fmt.Errorf("decode GitHub plan: %w", err)
	}
	var plan Plan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("decode GitHub plan: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Plan{}, errors.New("decode GitHub plan: trailing data")
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
	if s == nil || request == nil {
		return errors.New("GitHub grant request is required")
	}
	kind, ok := kindForOperation(request.Operation)
	if !ok {
		return fmt.Errorf("GitHub operation %q is not grantable", request.Operation)
	}
	if request.Metadata == nil {
		request.Metadata = map[string]string{}
	}
	request.Metadata[MetadataMode] = kind
	digest, err := s.Put(FromRequest(*request, s.credentialSelector, createdAt))
	if err != nil {
		return err
	}
	request.Metadata[MetadataSchema] = SchemaV1
	request.Metadata[MetadataDigest] = digest
	return nil
}

func (s *Store) CollectOrphans(referenced map[string]bool, olderThan time.Time) (int, error) {
	if s == nil || s.shared == nil {
		return 0, errors.New("GitHub plan store is unavailable")
	}
	return s.shared.CollectOrphans(referenced, olderThan)
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
		return errors.New("GitHub plan store is unavailable")
	}
	if grant.Metadata[MetadataSchema] != SchemaV1 {
		return errors.New("GitHub grant plan schema is missing or unsupported")
	}
	plan, err := v.Store.Get(grant.Metadata[MetadataDigest])
	if err != nil {
		return err
	}
	requestedDuration, requestedMaxUses := requestedGrantBounds(grant)
	if !planMatchesGrant(plan, grant, v.Store.credentialSelector, requestedDuration, requestedMaxUses) {
		return errors.New("GitHub grant does not match its immutable plan")
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

func planMatchesGrant(plan Plan, grant grants.Grant, selector string, duration time.Duration, maxUses int) bool {
	return planMatchesGrantIdentity(plan, grant) && planMatchesGrantValues(plan, grant) &&
		plan.CredentialSelector == selector && plan.Constraints.RequestedDurationSeconds == int64(duration.Seconds()) &&
		plan.Constraints.RequestedMaxUses == maxUses
}

func planMatchesGrantIdentity(plan Plan, grant grants.Grant) bool {
	return plan.Kind == grant.Metadata[MetadataMode] && plan.ClientID == grant.Client &&
		plan.ClientRequestID == grant.ClientRequestID && plan.Operation == grant.Operation && plan.TargetKind == grant.Target.Kind
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
	kind, grantable := kindForOperation(plan.Operation)
	if !validPlanIdentity(plan, kind, grantable) || !validPlanConstraints(plan) {
		return errors.New("GitHub plan is invalid")
	}
	if err := validatePlanValues(plan.Target); err != nil {
		return err
	}
	return validatePlanValues(plan.Constraints.Attributes)
}

func validPlanIdentity(plan Plan, kind string, grantable bool) bool {
	return plan.SchemaVersion == SchemaV1 && grantable && plan.Kind == kind && strings.TrimSpace(plan.ClientID) != "" &&
		strings.TrimSpace(plan.ClientRequestID) != "" && plan.TargetKind == "repo" && validTarget(plan.Target) &&
		validAttrs(plan.Operation, plan.Constraints.Attributes)
}

func validPlanConstraints(plan Plan) bool {
	return validCredentialSelector(plan.CredentialSelector) && plan.Constraints.RequestedDurationSeconds > 0 &&
		plan.Constraints.RequestedMaxUses > 0 && !plan.CreatedAt.IsZero()
}

func validCredentialSelector(value string) bool {
	return value == "github_app" || value == "development_pat"
}

func validTarget(target map[string][]string) bool {
	return len(target) == 2 && oneNonEmpty(target["owner"]) && oneNonEmpty(target["name"])
}

func validAttrs(operation string, attrs map[string][]string) bool {
	allowed := map[string]bool{}
	switch operation {
	case "git.push.branch_create", "git.push.fast_forward", "git.push.force", "git.ref.delete", "git.tag.update":
		allowed["ref"] = true
	case "pr.create", "pr.update", "pr.merge":
		allowed["ref"], allowed["base_ref"], allowed["head_ref"] = true, true, true
	}
	for key, values := range attrs {
		if !allowed[key] || !oneNonEmpty(values) {
			return false
		}
	}
	return true
}

func validatePlanValues(values map[string][]string) error {
	for key, list := range values {
		if sensitivePlanKey(key) {
			return errors.New("GitHub plan contains a sensitive field")
		}
		if !validPlanValueEntry(key, list) {
			return errors.New("GitHub plan contains an invalid value map")
		}
	}
	return nil
}

func validPlanValueEntry(key string, values []string) bool {
	if strings.TrimSpace(key) == "" || len(values) == 0 {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
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

func oneNonEmpty(values []string) bool {
	return len(values) == 1 && strings.TrimSpace(values[0]) != ""
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
