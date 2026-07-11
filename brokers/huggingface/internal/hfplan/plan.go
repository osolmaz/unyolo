// Package hfplan owns immutable Hugging Face execution plans.
package hfplan

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

	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/planstore"
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
	shared *planstore.Store
	now    func() time.Time
}

func NewStore(directory string) (*Store, error) {
	return newStore(directory, time.Now)
}

func newStore(directory string, now func() time.Time) (*Store, error) {
	shared, err := planstore.New(directory, "HF")
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Store{shared: shared, now: now}, nil
}

func FromRequest(request grants.Request, createdAt time.Time) Plan {
	kind := "capability_window"
	if request.Metadata["hf_grant_mode"] == "execution" {
		kind = "single_execution"
	}
	return Plan{SchemaVersion: SchemaV1, Kind: kind, ClientID: request.Client, ClientRequestID: request.ClientRequestID, Operation: request.Operation,
		Target: cloneValues(request.Target.Fields), CredentialSelector: "primary", CreatedAt: createdAt.UTC(),
		Constraints: Constraints{Attributes: cloneValues(request.Attrs), Mode: request.Metadata["hf_grant_mode"],
			RequestedDurationSeconds: int64(request.Duration.Seconds()), RequestedMaxUses: request.MaxUses}}
}

func (s *Store) Put(plan Plan) (string, error) {
	if s == nil || s.shared == nil {
		return "", errors.New("HF plan store is unavailable")
	}
	encoded, err := encode(plan)
	if err != nil {
		return "", err
	}
	return s.shared.Put(encoded)
}

func (s *Store) Get(value string) (Plan, error) {
	if s == nil || s.shared == nil {
		return Plan{}, errors.New("HF plan store is unavailable")
	}
	data, err := s.shared.Get(value)
	if err != nil {
		return Plan{}, err
	}
	return decode(data)
}

func decode(data []byte) (Plan, error) {
	if err := strictjson.RejectDuplicateKeys(data); err != nil {
		return Plan{}, fmt.Errorf("decode HF plan: %w", err)
	}
	var plan Plan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("decode HF plan: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Plan{}, errors.New("decode HF plan: trailing data")
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

func (s *Store) CollectOrphans(referenced map[string]bool, olderThan time.Time) (int, error) {
	if s == nil || s.shared == nil {
		return 0, errors.New("HF plan store is unavailable")
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
		return errors.New("HF plan store is unavailable")
	}
	if grant.Metadata[MetadataSchema] != SchemaV1 {
		return errors.New("HF grant plan schema is missing or unsupported")
	}
	plan, err := v.Store.Get(grant.Metadata[MetadataDigest])
	if err != nil {
		return err
	}
	requestedDuration := grant.RequestedDuration
	if requestedDuration <= 0 {
		requestedDuration = grant.Duration
	}
	requestedMaxUses := grant.RequestedMaxUses
	if requestedMaxUses <= 0 {
		requestedMaxUses = grant.MaxUses
	}
	if plan.ClientID != grant.Client || plan.ClientRequestID != grant.ClientRequestID || plan.Operation != grant.Operation ||
		!equalValues(plan.Target, grant.Target.Fields) || !equalValues(plan.Constraints.Attributes, grant.Attrs) ||
		plan.Constraints.Mode != grant.Metadata["hf_grant_mode"] || plan.Constraints.RequestedDurationSeconds != int64(requestedDuration.Seconds()) ||
		plan.Constraints.RequestedMaxUses != requestedMaxUses {
		return errors.New("HF grant does not match its immutable plan")
	}
	if constraints.Duration > requestedDuration || constraints.MaxUses > requestedMaxUses {
		return grants.ErrConstraintExceeded
	}
	return nil
}

func encode(plan Plan) ([]byte, error) {
	if err := validate(plan); err != nil {
		return nil, err
	}
	return json.Marshal(plan)
}

func validate(plan Plan) error {
	if plan.SchemaVersion != SchemaV1 || (plan.Kind != "capability_window" && plan.Kind != "single_execution") ||
		strings.TrimSpace(plan.ClientID) == "" || strings.TrimSpace(plan.ClientRequestID) == "" || !hfpolicy.IsOperation(plan.Operation) ||
		len(plan.Target) == 0 || strings.TrimSpace(plan.Constraints.Mode) == "" || plan.Constraints.RequestedDurationSeconds <= 0 ||
		plan.Constraints.RequestedMaxUses <= 0 || plan.CredentialSelector != "primary" || plan.CreatedAt.IsZero() {
		return errors.New("HF plan is invalid")
	}
	if plan.Kind == "single_execution" && plan.Constraints.Mode != "execution" || plan.Kind == "capability_window" && plan.Constraints.Mode != "window" {
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

func validatePlanValues(values map[string][]string) error {
	for key, list := range values {
		normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(key))
		for _, marker := range []string{"authorization", "credential", "password", "privatekey", "secret", "token", "cookie"} {
			if strings.Contains(normalized, marker) {
				return errors.New("HF plan contains a sensitive field")
			}
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
