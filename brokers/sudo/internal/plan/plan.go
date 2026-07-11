// Package plan owns immutable sudo execution plans and activation validation.
package plan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/user"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/planstore"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

const (
	SchemaV1       = "sudo-broker.io/plan/v1"
	MetadataSchema = "sudo_plan_schema"
	MetadataDigest = "sudo_plan_digest"
)

type Plan struct {
	Schema                   string            `json:"schema"`
	RequestID                string            `json:"request_id"`
	ClientID                 string            `json:"client_id"`
	Operation                string            `json:"operation"`
	CommandID                string            `json:"command_id"`
	TargetUser               string            `json:"target_user"`
	TargetUID                uint32            `json:"target_uid"`
	TargetGID                uint32            `json:"target_gid"`
	SupplementaryGIDs        []uint32          `json:"supplementary_gids"`
	Executable               string            `json:"executable"`
	Arguments                []string          `json:"arguments"`
	WorkingDirectory         string            `json:"working_directory"`
	Environment              []string          `json:"environment"`
	TimeoutSeconds           uint32            `json:"timeout_seconds"`
	MaxOutputBytes           uint32            `json:"max_output_bytes"`
	SlotValues               map[string]string `json:"slot_values,omitempty"`
	CatalogDigest            string            `json:"catalog_digest"`
	RequestedDurationSeconds int64             `json:"requested_duration_seconds"`
	RequestedMaxUses         int               `json:"requested_max_uses"`
	CreatedAt                time.Time         `json:"created_at"`
}

type Identity struct {
	Name              string
	UID               uint32
	GID               uint32
	SupplementaryGIDs []uint32
}

type IdentityResolver interface {
	Lookup(string) (Identity, error)
}

type SystemIdentityResolver struct{}

func (SystemIdentityResolver) Lookup(name string) (Identity, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return Identity{}, errors.New("target user does not exist")
	}
	uid, err := parseID(account.Uid)
	if err != nil {
		return Identity{}, errors.New("target user uid is invalid")
	}
	gid, err := parseID(account.Gid)
	if err != nil {
		return Identity{}, errors.New("target user gid is invalid")
	}
	groups, err := account.GroupIds()
	if err != nil {
		return Identity{}, errors.New("target supplementary groups cannot be resolved")
	}
	supplementary := make([]uint32, 0, len(groups))
	for _, value := range groups {
		groupID, err := parseID(value)
		if err != nil {
			return Identity{}, errors.New("target supplementary group is invalid")
		}
		if groupID != gid && !slices.Contains(supplementary, groupID) {
			supplementary = append(supplementary, groupID)
		}
	}
	slices.Sort(supplementary)
	return Identity{Name: account.Username, UID: uid, GID: gid, SupplementaryGIDs: supplementary}, nil
}

type Store struct{ content *planstore.Store }

func NewStore(directory string) (*Store, error) {
	content, err := planstore.New(directory, "sudo")
	if err != nil {
		return nil, err
	}
	return &Store{content: content}, nil
}

func Build(request grants.Request, resolved catalog.Resolved, identity Identity, now time.Time) (Plan, error) {
	if request.Operation != sudopolicy.OperationExecCommand || request.Client == "" || request.ClientRequestID == "" ||
		request.Duration <= 0 || request.MaxUses != 1 || identity.Name != resolved.TargetUser {
		return Plan{}, errors.New("sudo plan input is invalid")
	}
	if request.Target.Kind != sudopolicy.TargetUser || corepolicy.FirstValue(request.Target.Fields[sudopolicy.TargetName]) != resolved.TargetUser ||
		corepolicy.FirstValue(request.Attrs[sudopolicy.AttrCommandID]) != resolved.CommandID {
		return Plan{}, errors.New("sudo plan request does not match resolved command")
	}
	for slot, value := range resolved.SlotValues {
		if corepolicy.FirstValue(request.Attrs[sudopolicy.ArgumentPrefix+slot]) != value {
			return Plan{}, errors.New("sudo plan slot values do not match request")
		}
	}
	boundEnvironment := map[string]string{"LANG": "C", "LC_ALL": "C"}
	for key, value := range resolved.Environment {
		boundEnvironment[key] = value
	}
	environment := make([]string, 0, len(boundEnvironment))
	for key, value := range boundEnvironment {
		environment = append(environment, key+"="+value)
	}
	sort.Strings(environment)
	arguments := append([]string(nil), resolved.Arguments...)
	if len(arguments) == 0 || arguments[0] != resolved.Executable {
		return Plan{}, errors.New("sudo resolved argv is invalid")
	}
	supplementary := append([]uint32(nil), identity.SupplementaryGIDs...)
	slices.Sort(supplementary)
	return Plan{
		Schema: SchemaV1, RequestID: request.ClientRequestID, ClientID: request.Client, Operation: request.Operation,
		CommandID: resolved.CommandID, TargetUser: resolved.TargetUser, TargetUID: identity.UID, TargetGID: identity.GID,
		SupplementaryGIDs: supplementary, Executable: resolved.Executable,
		Arguments: append([]string(nil), arguments[1:]...), WorkingDirectory: resolved.WorkingDirectory, Environment: environment,
		TimeoutSeconds: uint32(resolved.TimeoutSeconds), MaxOutputBytes: uint32(resolved.MaxOutputBytes),
		SlotValues: cloneMap(resolved.SlotValues), CatalogDigest: resolved.CatalogDigest,
		RequestedDurationSeconds: int64(request.Duration.Seconds()), RequestedMaxUses: request.MaxUses, CreatedAt: now.UTC(),
	}, nil
}

func (s *Store) Bind(request *grants.Request, value Plan) error {
	if s == nil || s.content == nil || request == nil {
		return errors.New("sudo plan store and request are required")
	}
	encoded, err := encode(value)
	if err != nil {
		return err
	}
	digest, err := s.content.Put(encoded)
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

func (s *Store) Get(digest string) (Plan, error) {
	if s == nil || s.content == nil {
		return Plan{}, errors.New("sudo plan store is unavailable")
	}
	data, err := s.content.Get(digest)
	if err != nil {
		return Plan{}, err
	}
	return decode(data)
}

func (s *Store) Canonical(digest string) ([]byte, error) {
	if s == nil || s.content == nil {
		return nil, errors.New("sudo plan store is unavailable")
	}
	return s.content.Get(digest)
}

func EncodeCanonical(value Plan) ([]byte, error) { return encode(value) }

func DecodeCanonical(data []byte) (Plan, error) { return decode(data) }

func ValidateForHelper(value Plan, snapshot *catalog.Snapshot, identities IdentityResolver) error {
	if err := validate(value); err != nil {
		return err
	}
	if snapshot == nil || identities == nil {
		return errors.New("sudo helper validation dependencies are unavailable")
	}
	if err := validateCatalogBinding(value, snapshot); err != nil {
		return err
	}
	identity, err := identities.Lookup(value.TargetUser)
	if err != nil || identity.Name != value.TargetUser || identity.UID != value.TargetUID || identity.GID != value.TargetGID ||
		!slices.Equal(identity.SupplementaryGIDs, value.SupplementaryGIDs) {
		return errors.New("sudo target identity does not match the execution plan")
	}
	return nil
}

type Readiness interface {
	Ready(context.Context) error
}

type Validator struct {
	Store      *Store
	Catalog    *catalog.Snapshot
	Identities IdentityResolver
	Helper     Readiness
}

func (v Validator) ValidateActivation(ctx context.Context, grant grants.Grant, constraints grants.ApprovalConstraints) error {
	if err := v.validateGrant(grant, constraints); err != nil {
		return err
	}
	if v.Helper == nil {
		return errors.New("sudo privileged helper is unavailable")
	}
	return v.Helper.Ready(ctx)
}

func (v Validator) ValidateExecution(ctx context.Context, grant grants.Grant) (Plan, error) {
	if err := v.validateGrant(grant, grants.ApprovalConstraints{}); err != nil {
		return Plan{}, err
	}
	if v.Helper == nil {
		return Plan{}, errors.New("sudo privileged helper is unavailable")
	}
	if err := v.Helper.Ready(ctx); err != nil {
		return Plan{}, err
	}
	return v.Store.Get(grant.Metadata[MetadataDigest])
}

func (v Validator) validateGrant(grant grants.Grant, constraints grants.ApprovalConstraints) error {
	if v.Store == nil || v.Catalog == nil || v.Identities == nil {
		return errors.New("sudo plan validator is unavailable")
	}
	if grant.Metadata[MetadataSchema] != SchemaV1 {
		return errors.New("sudo grant plan schema is missing or unsupported")
	}
	value, err := v.Store.Get(grant.Metadata[MetadataDigest])
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
	if value.RequestID != grant.ClientRequestID || value.ClientID != grant.Client || value.Operation != grant.Operation ||
		value.Operation != sudopolicy.OperationExecCommand || value.TargetUser != corepolicy.FirstValue(grant.Target.Fields[sudopolicy.TargetName]) ||
		value.CommandID != corepolicy.FirstValue(grant.Attrs[sudopolicy.AttrCommandID]) ||
		grant.Target.Kind != sudopolicy.TargetUser || len(grant.Target.Fields) != 1 || len(grant.Attrs) != len(value.SlotValues)+1 ||
		value.RequestedDurationSeconds != int64(requestedDuration.Seconds()) || value.RequestedMaxUses != requestedMaxUses || requestedMaxUses != 1 {
		return errors.New("sudo grant does not match its immutable plan")
	}
	for slot, expected := range value.SlotValues {
		if corepolicy.FirstValue(grant.Attrs[sudopolicy.ArgumentPrefix+slot]) != expected {
			return errors.New("sudo grant slot values do not match its plan")
		}
	}
	if err := validateCatalogBinding(value, v.Catalog); err != nil {
		return err
	}
	identity, err := v.Identities.Lookup(value.TargetUser)
	if err != nil || identity.Name != value.TargetUser || identity.UID != value.TargetUID || identity.GID != value.TargetGID ||
		!slices.Equal(identity.SupplementaryGIDs, value.SupplementaryGIDs) {
		return errors.New("sudo target identity changed after request")
	}
	if constraints.Duration > requestedDuration || constraints.MaxUses > 1 {
		return grants.ErrConstraintExceeded
	}
	return nil
}

func validateCatalogBinding(value Plan, snapshot *catalog.Snapshot) error {
	command, ok := snapshot.Command(value.CommandID)
	if !ok {
		return errors.New("sudo command no longer exists")
	}
	expectedEnvironment := map[string]string{"LANG": "C", "LC_ALL": "C"}
	for key, item := range command.Environment {
		expectedEnvironment[key] = item
	}
	expectedEntries := make([]string, 0, len(expectedEnvironment))
	for key, item := range expectedEnvironment {
		expectedEntries = append(expectedEntries, key+"="+item)
	}
	sort.Strings(expectedEntries)
	if !slices.Equal(expectedEntries, value.Environment) {
		return errors.New("sudo plan environment no longer matches the catalog")
	}
	resolved := resolvedFromPlan(value)
	resolved.Environment = command.Environment
	return snapshot.ValidateResolved(resolved)
}

func resolvedFromPlan(value Plan) catalog.Resolved {
	return catalog.Resolved{
		CommandID: value.CommandID, TargetUser: value.TargetUser, Executable: value.Executable,
		Arguments: append([]string{value.Executable}, value.Arguments...), WorkingDirectory: value.WorkingDirectory,
		Environment: environmentMap(value.Environment), TimeoutSeconds: int(value.TimeoutSeconds), MaxOutputBytes: int(value.MaxOutputBytes),
		SlotValues: cloneMap(value.SlotValues), CatalogDigest: value.CatalogDigest,
	}
}

func encode(value Plan) ([]byte, error) {
	if err := validate(value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func decode(data []byte) (Plan, error) {
	if err := strictjson.RejectDuplicateKeys(data); err != nil {
		return Plan{}, err
	}
	var value Plan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Plan{}, err
	}
	if err := validate(value); err != nil {
		return Plan{}, err
	}
	return value, nil
}

func validate(value Plan) error {
	if value.Schema != SchemaV1 || value.RequestID == "" || value.ClientID == "" || value.Operation != sudopolicy.OperationExecCommand ||
		value.CommandID == "" || value.TargetUser == "" || value.Executable == "" || value.WorkingDirectory == "" ||
		value.TimeoutSeconds == 0 || value.TimeoutSeconds > 3600 || value.MaxOutputBytes > 1<<20 || value.CatalogDigest == "" ||
		value.RequestedDurationSeconds <= 0 || value.RequestedMaxUses != 1 || value.CreatedAt.IsZero() {
		return errors.New("sudo plan is invalid")
	}
	return nil
}

func parseID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err
}

func environmentMap(values []string) map[string]string {
	out := make(map[string]string, len(values))
	for _, value := range values {
		key, item, ok := strings.Cut(value, "=")
		if !ok || key == "" || out[key] != "" {
			return nil
		}
		out[key] = item
	}
	return out
}

func cloneMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
