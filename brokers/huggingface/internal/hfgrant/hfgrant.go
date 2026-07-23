// Package hfgrant maps Hugging Face request fields onto canonical Brokerkit grants.
package hfgrant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/authorization/budget"
	"github.com/osolmaz/brokerkit/authorization/grants"
	bkpolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const (
	DefaultPendingTimeout     = 10 * time.Minute
	DefaultDuration           = 5 * time.Minute
	MaxDuration               = 7 * 24 * time.Hour
	DefaultMaxUses            = 1
	MaxUses                   = 25
	DefaultReservationTimeout = 5 * time.Minute

	ModeWindow    = "window"
	ModeExecution = "execution"

	metadataMode     = "hf_grant_mode"
	targetKind       = "kind"
	targetType       = "type"
	targetOwner      = "owner"
	targetName       = "name"
	targetRefs       = "refs"
	targetPaths      = "paths"
	targetKeys       = "keys"
	targetVisibility = "visibility"
)

// Input contains the provider fields accepted by HF Broker's request boundary.
type Input struct {
	Client            string
	ClientRequestID   string
	Operation         string
	Mode              string
	Target            string
	Ref               string
	PolicyTarget      *hfpolicy.Target
	Attrs             map[string]any
	Reason            string
	RequestedDuration time.Duration
	PendingTimeout    time.Duration
	MaxUses           int
	MaxUsesSpecified  bool
}

// Request validates provider fields and creates a canonical grant request.
func Request(store *grants.Store, plans *hfplan.Store, input Input) (grants.RequestResult, bool, error) {
	if store == nil || plans == nil {
		return grants.RequestResult{}, false, errors.New("grant and plan stores are required")
	}
	request, plan, err := Prepare(store, plans, input)
	if err != nil {
		return grants.RequestResult{}, false, err
	}
	return store.RequestWithPlan(request, plan)
}

// Prepare validates a provider request and builds its immutable plan without
// committing either record.
func Prepare(store *grants.Store, plans *hfplan.Store, input Input) (grants.Request, grants.ImmutablePlan, error) {
	if store == nil || plans == nil {
		return grants.Request{}, grants.ImmutablePlan{}, errors.New("grant and plan stores are required")
	}
	request, err := CanonicalRequest(input)
	if err != nil {
		return grants.Request{}, grants.ImmutablePlan{}, err
	}
	createdAt, exists, err := existingPlanCreatedAt(store, plans, request.Client, request.ClientRequestID)
	if err != nil {
		return grants.Request{}, grants.ImmutablePlan{}, err
	}
	plan, err := prepareRequestPlan(plans, &request, createdAt, exists)
	if err != nil {
		return grants.Request{}, grants.ImmutablePlan{}, err
	}
	return request, plan, nil
}

func prepareRequestPlan(plans *hfplan.Store, request *grants.Request, createdAt time.Time, exists bool) (grants.ImmutablePlan, error) {
	if exists {
		return plans.PrepareBindAt(request, createdAt)
	}
	return plans.PrepareBind(request)
}

func existingPlanCreatedAt(store *grants.Store, plans *hfplan.Store, client, clientRequestID string) (time.Time, bool, error) {
	values, err := store.ListForClient(client)
	if err != nil {
		return time.Time{}, false, err
	}
	for _, grant := range values {
		if grant.ClientRequestID != clientRequestID || grant.Status == grants.StatusCanceled {
			continue
		}
		plan, err := plans.Get(grant.Metadata[hfplan.MetadataDigest])
		if err != nil {
			return time.Time{}, false, err
		}
		return plan.CreatedAt, true, nil
	}
	return time.Time{}, false, nil
}

// CanonicalRequest validates and converts one HF request.
func CanonicalRequest(input Input) (grants.Request, error) {
	clientRequestID, reason, err := normalizeIdentity(input)
	if err != nil {
		return grants.Request{}, err
	}
	mode, duration, maxUses, err := normalizeGrant(input)
	if err != nil {
		return grants.Request{}, err
	}
	attrs, err := encodeAttrs(input.Attrs)
	if err != nil {
		return grants.Request{}, err
	}
	fields, err := canonicalTargetFields(input)
	if err != nil {
		return grants.Request{}, err
	}
	return grants.Request{
		Client: input.Client, ClientRequestID: clientRequestID, Operation: input.Operation,
		Target: bkpolicy.Target{Kind: "hf", Fields: fields}, Attrs: attrs,
		Metadata: map[string]string{metadataMode: mode}, Reason: reason,
		Duration: duration, PendingTimeout: input.PendingTimeout, MaxUses: maxUses, MaxUsesSpecified: true,
		MaxUsesDefaulted: !input.MaxUsesSpecified,
	}, nil
}

func normalizeIdentity(input Input) (string, string, error) {
	if !validInputIdentity(input) {
		return "", "", errors.New("client, operation, and target are required")
	}
	clientRequestID := strings.TrimSpace(input.ClientRequestID)
	if clientRequestID == "" || len(clientRequestID) > 128 || strings.ContainsAny(clientRequestID, " \t\r\n") {
		return "", "", errors.New("client_request_id must be 1-128 non-whitespace bytes")
	}
	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		return "", "", errors.New("grant reason is required")
	}
	if len(reason) > 2000 {
		return "", "", errors.New("grant reason is longer than 2000 bytes")
	}
	return clientRequestID, reason, nil
}

func validInputIdentity(input Input) bool {
	return input.Client != "" && hfpolicy.IsOperation(input.Operation) && (input.PolicyTarget != nil || input.Target != "")
}

func canonicalTargetFields(input Input) (map[string][]string, error) {
	if input.PolicyTarget == nil {
		fields := map[string][]string{targetName: {input.Target}}
		if input.Ref != "" {
			fields[targetRefs] = []string{input.Ref}
		}
		return fields, nil
	}
	target := *input.PolicyTarget
	if err := hfpolicy.ValidateGrantRequest(hfpolicy.Request{Operation: hfpolicy.Operation(input.Operation), Target: target, Attrs: input.Attrs}); err != nil {
		return nil, err
	}
	fields := map[string][]string{targetKind: {string(target.Kind)}, targetOwner: {target.Owner}, targetName: {target.Name}}
	if target.Type != "" {
		fields[targetType] = []string{string(target.Type)}
	}
	copyTargetField(fields, targetRefs, target.Refs)
	copyTargetField(fields, targetPaths, target.Paths)
	copyTargetField(fields, targetKeys, target.Keys)
	copyTargetField(fields, targetVisibility, target.Visibility)
	return fields, nil
}

func copyTargetField(fields map[string][]string, name string, values []string) {
	if len(values) > 0 {
		fields[name] = append([]string(nil), values...)
	}
}

func normalizeGrant(input Input) (string, time.Duration, usebudget.Limit, error) {
	mode, err := normalizeMode(input.Mode)
	if err != nil {
		return "", 0, 0, err
	}
	duration, err := normalizeDuration(input.RequestedDuration)
	if err != nil {
		return "", 0, 0, err
	}
	maxUses, err := normalizeMaxUses(input.MaxUses, input.MaxUsesSpecified)
	if err != nil {
		return "", 0, 0, err
	}
	if mode == ModeExecution && maxUses != 1 {
		return "", 0, 0, errors.New("execution approvals must have exactly one use")
	}
	return mode, duration, maxUses, nil
}

func normalizeMode(mode string) (string, error) {
	if mode == "" {
		return ModeWindow, nil
	}
	if mode != ModeWindow && mode != ModeExecution {
		return "", errors.New("grant mode is invalid")
	}
	return mode, nil
}

func normalizeDuration(duration time.Duration) (time.Duration, error) {
	if duration <= 0 {
		return DefaultDuration, nil
	}
	if duration > MaxDuration {
		return 0, fmt.Errorf("grant duration exceeds %d minutes", int(MaxDuration/time.Minute))
	}
	if duration%time.Minute != 0 {
		return 0, errors.New("grant duration must be a positive whole number of minutes")
	}
	return duration, nil
}

func normalizeMaxUses(maxUses int, specified bool) (usebudget.Limit, error) {
	if maxUses < 0 {
		return 0, errors.New("grant max uses must be positive")
	}
	if maxUses == 0 && !specified {
		return DefaultMaxUses, nil
	}
	if maxUses > MaxUses {
		return 0, fmt.Errorf("grant max uses exceeds %d", MaxUses)
	}
	return usebudget.Limit(maxUses), nil
}

func encodeAttrs(attrs map[string]any) (map[string][]string, error) {
	if len(attrs) == 0 {
		return nil, nil
	}
	out := make(map[string][]string, len(attrs))
	for key, value := range attrs {
		data, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("grant attr %q is invalid: %w", key, err)
		}
		out[key] = []string{string(data)}
	}
	return out, nil
}

// Attrs decodes provider attributes from canonical values.
func Attrs(grant grants.Grant) (map[string]any, error) {
	if len(grant.Attrs) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(grant.Attrs))
	for key, values := range grant.Attrs {
		value, err := decodeAttr(key, values)
		if err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, nil
}

func decodeAttr(key string, values []string) (any, error) {
	if len(values) != 1 {
		return nil, fmt.Errorf("stored grant attr %q is invalid", key)
	}
	if err := strictjson.RejectDuplicateKeys([]byte(values[0])); err != nil {
		return nil, fmt.Errorf("decode stored grant attr %q: %w", key, err)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(values[0]))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode stored grant attr %q: %w", key, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode stored grant attr %q: trailing data", key)
	}
	return normalizeAttrNumber(value), nil
}

func normalizeAttrNumber(value any) any {
	number, ok := value.(json.Number)
	if !ok {
		return value
	}
	integer, err := number.Int64()
	if err != nil {
		return value
	}
	return integer
}

// Target returns the canonical exact HF resource name used in logs and Git
// transport matching.
func Target(grant grants.Grant) string {
	fields := grant.Target.Fields
	if kind := bkpolicy.FirstValue(fields[targetKind]); kind != "" {
		owner, name := bkpolicy.FirstValue(fields[targetOwner]), bkpolicy.FirstValue(fields[targetName])
		if kind == string(hfpolicy.KindRepo) {
			return bkpolicy.FirstValue(fields[targetType]) + "/" + owner + "/" + name
		}
		return kind + "/" + owner + "/" + name
	}
	return bkpolicy.FirstValue(fields[targetName])
}

// Ref returns the optional exact Git ref.
func Ref(grant grants.Grant) string { return bkpolicy.FirstValue(grant.Target.Fields[targetRefs]) }

// PolicyTarget reconstructs the exact provider target persisted in a grant.
func PolicyTarget(grant grants.Grant) (hfpolicy.Target, error) {
	fields := grant.Target.Fields
	kind := hfpolicy.TargetKind(bkpolicy.FirstValue(fields[targetKind]))
	if kind == "" {
		return legacyPolicyTarget(grant)
	}
	target := hfpolicy.Target{Kind: kind, Type: hfpolicy.RepoType(bkpolicy.FirstValue(fields[targetType])),
		Owner: bkpolicy.FirstValue(fields[targetOwner]), Name: bkpolicy.FirstValue(fields[targetName]),
		Refs: append([]string(nil), fields[targetRefs]...), Paths: append([]string(nil), fields[targetPaths]...),
		Keys: append([]string(nil), fields[targetKeys]...), Visibility: append([]string(nil), fields[targetVisibility]...)}
	if err := hfpolicy.ValidateRequest(hfpolicy.Request{Operation: hfpolicy.Operation(grant.Operation), Target: target}); err != nil {
		return hfpolicy.Target{}, fmt.Errorf("stored grant target is invalid: %w", err)
	}
	return target, nil
}

func legacyPolicyTarget(grant grants.Grant) (hfpolicy.Target, error) {
	parts := strings.Split(Target(grant), "/")
	if len(parts) != 3 {
		return hfpolicy.Target{}, errors.New("stored grant target is invalid")
	}
	return hfpolicy.Target{Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(parts[0]), Owner: parts[1], Name: parts[2],
		Refs: append([]string(nil), grant.Target.Fields[targetRefs]...)}, nil
}

// Mode returns the provider grant mode.
func Mode(grant grants.Grant) string { return grant.Metadata[metadataMode] }

// RequestedMinutes returns the requested active duration in minutes.
func RequestedMinutes(grant grants.Grant) int {
	duration := grant.RequestedDuration
	if duration <= 0 {
		duration = grant.Duration
	}
	return int(duration / time.Minute)
}

// GetForClient returns a grant only when it belongs to client.
func GetForClient(store *grants.Store, client, id string) (grants.Grant, error) {
	grant, err := store.Get(id)
	if err != nil || grant.Client != client {
		return grants.Grant{}, grants.ErrNotFound
	}
	return grant, nil
}

// MatchActiveFunc finds one exact usable HF grant and applies a provider matcher.
func MatchActiveFunc(store *grants.Store, client, operation, target, ref string, match func(grants.Grant) bool) (grants.Grant, bool, error) {
	values, err := store.ListForClient(client)
	if err != nil {
		return grants.Grant{}, false, err
	}
	for _, grant := range values {
		if usableGrant(grant, operation, target, ref) && (match == nil || match(grant)) {
			return grant, true, nil
		}
	}
	return grants.Grant{}, false, nil
}

func usableGrant(grant grants.Grant, operation, target, ref string) bool {
	return grant.Status == grants.StatusActive && !grant.ReservationRetained && grant.Operation == operation &&
		Target(grant) == target && Ref(grant) == ref && grant.MaxUses.Allows(grant.UsedCount, grant.ReservedCount)
}
