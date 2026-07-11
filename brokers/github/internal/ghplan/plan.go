// Package ghplan owns immutable GitHub execution plans.
package ghplan

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
	Schema                   string              `json:"schema"`
	Kind                     string              `json:"kind"`
	Operation                string              `json:"operation"`
	Target                   map[string][]string `json:"target"`
	Attributes               map[string][]string `json:"attributes,omitempty"`
	CredentialMode           string              `json:"credential_mode"`
	RequestedDurationSeconds int64               `json:"requested_duration_seconds"`
	RequestedMaxUses         int                 `json:"requested_max_uses"`
}

type Store struct {
	directory      string
	credentialMode string
}

func NewStore(directory string, credentialMode string) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("GitHub plan directory is required")
	}
	if credentialMode != "github_app" && credentialMode != "development_pat" {
		return nil, errors.New("GitHub credential mode is invalid")
	}
	return &Store{directory: directory, credentialMode: credentialMode}, nil
}

func FromRequest(request grants.Request, credentialMode string) Plan {
	kind := request.Metadata[MetadataMode]
	if kind == "" {
		kind, _ = kindForOperation(request.Operation)
	}
	return Plan{
		Schema: SchemaV1, Kind: kind, Operation: request.Operation,
		Target: cloneValues(request.Target.Fields), Attributes: cloneValues(request.Attrs), CredentialMode: credentialMode,
		RequestedDurationSeconds: int64(request.Duration.Seconds()), RequestedMaxUses: request.MaxUses,
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
	encoded, err := encode(plan)
	if err != nil {
		return "", err
	}
	digest := digest(encoded)
	path := s.path(digest)
	if current, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(bytes.TrimSpace(current), encoded) {
			return "", errors.New("GitHub plan digest collision")
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
		return Plan{}, errors.New("GitHub plan digest is invalid")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return Plan{}, errors.New("GitHub plan digest is invalid")
	}
	data, err := os.ReadFile(s.path(value))
	if err != nil {
		return Plan{}, fmt.Errorf("read GitHub plan: %w", err)
	}
	if digest(bytes.TrimSpace(data)) != value {
		return Plan{}, errors.New("GitHub plan content digest mismatch")
	}
	var plan Plan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("decode GitHub plan: %w", err)
	}
	if err := validate(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func (s *Store) Bind(request *grants.Request) error {
	if s == nil || request == nil {
		return errors.New("GitHub grant request is required")
	}
	if request.Metadata == nil {
		request.Metadata = map[string]string{}
	}
	kind, ok := kindForOperation(request.Operation)
	if !ok {
		return fmt.Errorf("GitHub operation %q is not grantable", request.Operation)
	}
	request.Metadata[MetadataMode] = kind
	digest, err := s.Put(FromRequest(*request, s.credentialMode))
	if err != nil {
		return err
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
		return errors.New("GitHub plan store is unavailable")
	}
	if grant.Metadata[MetadataSchema] != SchemaV1 {
		return errors.New("GitHub grant plan schema is missing or unsupported")
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
	if plan.Kind != grant.Metadata[MetadataMode] || plan.Operation != grant.Operation ||
		!equalValues(plan.Target, grant.Target.Fields) || !equalValues(plan.Attributes, grant.Attrs) ||
		plan.CredentialMode != v.Store.credentialMode || plan.RequestedDurationSeconds != int64(requestedDuration.Seconds()) ||
		plan.RequestedMaxUses != requestedMaxUses {
		return errors.New("GitHub grant does not match its immutable plan")
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
	kind, grantable := kindForOperation(plan.Operation)
	if plan.Schema != SchemaV1 || !grantable || plan.Kind != kind || !validTarget(plan.Target) || !validAttrs(plan.Operation, plan.Attributes) ||
		(plan.CredentialMode != "github_app" && plan.CredentialMode != "development_pat") ||
		plan.RequestedDurationSeconds <= 0 || plan.RequestedMaxUses <= 0 {
		return errors.New("GitHub plan is invalid")
	}
	return nil
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

func oneNonEmpty(values []string) bool {
	return len(values) == 1 && strings.TrimSpace(values[0]) != ""
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
