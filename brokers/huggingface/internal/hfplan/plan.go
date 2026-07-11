// Package hfplan owns immutable Hugging Face execution plans.
package hfplan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/store"
)

const (
	SchemaV1       = "hf-plan/v1"
	MetadataSchema = "hf_plan_schema"
	MetadataDigest = "hf_plan_digest"
)

type Plan struct {
	Schema                   string              `json:"schema"`
	Kind                     string              `json:"kind"`
	Operation                string              `json:"operation"`
	Target                   map[string][]string `json:"target"`
	Attributes               map[string][]string `json:"attributes,omitempty"`
	Mode                     string              `json:"mode"`
	RequestedDurationSeconds int64               `json:"requested_duration_seconds"`
	RequestedMaxUses         int                 `json:"requested_max_uses"`
}

type Store struct{ directory string }

func NewStore(directory string) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("HF plan directory is required")
	}
	return &Store{directory: directory}, nil
}

func FromRequest(request grants.Request) Plan {
	kind := "capability_window"
	if request.Metadata["hf_grant_mode"] == "execution" {
		kind = "single_execution"
	}
	return Plan{Schema: SchemaV1, Kind: kind, Operation: request.Operation,
		Target: cloneValues(request.Target.Fields), Attributes: cloneValues(request.Attrs), Mode: request.Metadata["hf_grant_mode"],
		RequestedDurationSeconds: int64(request.Duration.Seconds()), RequestedMaxUses: request.MaxUses}
}

func (s *Store) Put(plan Plan) (string, error) {
	encoded, err := encode(plan)
	if err != nil {
		return "", err
	}
	digest := digest(encoded)
	path := s.path(digest)
	if current, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(bytes.TrimSpace(current), encoded) {
			return "", errors.New("HF plan digest collision")
		}
		return digest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := store.WriteFileAtomic(path, append(encoded, '\n'), 0o600); err != nil {
		return "", err
	}
	return digest, nil
}

func (s *Store) Get(value string) (Plan, error) {
	if len(value) != sha256.Size*2 {
		return Plan{}, errors.New("HF plan digest is invalid")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return Plan{}, errors.New("HF plan digest is invalid")
	}
	data, err := os.ReadFile(s.path(value))
	if err != nil {
		return Plan{}, fmt.Errorf("read HF plan: %w", err)
	}
	if digest(bytes.TrimSpace(data)) != value {
		return Plan{}, errors.New("HF plan content digest mismatch")
	}
	var plan Plan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("decode HF plan: %w", err)
	}
	if err := validate(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func (s *Store) Bind(request *grants.Request) error {
	if s == nil || request == nil {
		return errors.New("HF grant request is required")
	}
	digest, err := s.Put(FromRequest(*request))
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
	requestedDuration := grant.RequestedDuration
	if requestedDuration <= 0 {
		requestedDuration = grant.Duration
	}
	requestedMaxUses := grant.RequestedMaxUses
	if requestedMaxUses <= 0 {
		requestedMaxUses = grant.MaxUses
	}
	if plan.Operation != grant.Operation || !equalValues(plan.Target, grant.Target.Fields) || !equalValues(plan.Attributes, grant.Attrs) ||
		plan.Mode != grant.Metadata["hf_grant_mode"] || plan.RequestedDurationSeconds != int64(requestedDuration.Seconds()) ||
		plan.RequestedMaxUses != requestedMaxUses {
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
	if plan.Schema != SchemaV1 || (plan.Kind != "capability_window" && plan.Kind != "single_execution") || strings.TrimSpace(plan.Operation) == "" ||
		len(plan.Target) == 0 || strings.TrimSpace(plan.Mode) == "" || plan.RequestedDurationSeconds <= 0 || plan.RequestedMaxUses <= 0 {
		return errors.New("HF plan is invalid")
	}
	return nil
}

func digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }

func (s *Store) path(value string) string { return filepath.Join(s.directory, value+".json") }

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
