// Package hfgrant maps Hugging Face request fields onto canonical Brokerkit grants.
package hfgrant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/grants"
	bkpolicy "github.com/osolmaz/brokerkit/policy"
)

const (
	DefaultPendingTimeout     = 10 * time.Minute
	DefaultDuration           = 5 * time.Minute
	MaxDuration               = time.Hour
	DefaultMaxUses            = 1
	MaxUses                   = 25
	DefaultReservationTimeout = 5 * time.Minute

	ModeWindow    = "window"
	ModeExecution = "execution"

	metadataMode = "hf_grant_mode"
	targetName   = "name"
	targetRef    = "ref"
)

// Input contains the provider fields accepted by HF Broker's request boundary.
type Input struct {
	Client            string
	ClientRequestID   string
	Operation         string
	Mode              string
	Target            string
	Ref               string
	Attrs             map[string]any
	Reason            string
	RequestedDuration time.Duration
	PendingTimeout    time.Duration
	MaxUses           int
}

// Request validates provider fields and creates a canonical grant request.
func Request(store *grants.Store, plans *hfplan.Store, input Input) (grants.RequestResult, bool, error) {
	request, err := CanonicalRequest(input)
	if err != nil {
		return grants.RequestResult{}, false, err
	}
	if err := plans.Bind(&request); err != nil {
		return grants.RequestResult{}, false, err
	}
	return store.Request(request)
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
	fields := map[string][]string{targetName: {input.Target}}
	if input.Ref != "" {
		fields[targetRef] = []string{input.Ref}
	}
	return grants.Request{
		Client: input.Client, ClientRequestID: clientRequestID, Operation: input.Operation,
		Target: bkpolicy.Target{Kind: "hf", Fields: fields}, Attrs: attrs,
		Metadata: map[string]string{metadataMode: mode}, Reason: reason,
		Duration: duration, PendingTimeout: input.PendingTimeout, MaxUses: maxUses,
	}, nil
}

func normalizeIdentity(input Input) (string, string, error) {
	if input.Client == "" || input.Operation == "" || input.Target == "" {
		return "", "", errors.New("client, operation, and target are required")
	}
	clientRequestID := strings.TrimSpace(input.ClientRequestID)
	if len(clientRequestID) > 128 || strings.ContainsAny(clientRequestID, " \t\r\n") {
		return "", "", errors.New("client_request_id must be 1-128 non-whitespace bytes")
	}
	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		return "", "", errors.New("grant reason is required")
	}
	if len(reason) > 512 {
		return "", "", errors.New("grant reason is longer than 512 bytes")
	}
	return clientRequestID, reason, nil
}

func normalizeGrant(input Input) (string, time.Duration, int, error) {
	mode, err := normalizeMode(input.Mode)
	if err != nil {
		return "", 0, 0, err
	}
	duration, err := normalizeDuration(input.RequestedDuration)
	if err != nil {
		return "", 0, 0, err
	}
	maxUses, err := normalizeMaxUses(input.MaxUses)
	if err != nil {
		return "", 0, 0, err
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

func normalizeMaxUses(maxUses int) (int, error) {
	if maxUses < 0 {
		return 0, errors.New("grant max uses must be positive")
	}
	if maxUses == 0 {
		return DefaultMaxUses, nil
	}
	if maxUses > MaxUses {
		return 0, fmt.Errorf("grant max uses exceeds %d", MaxUses)
	}
	return maxUses, nil
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
		if len(values) != 1 {
			return nil, fmt.Errorf("stored grant attr %q is invalid", key)
		}
		decoder := json.NewDecoder(bytes.NewBufferString(values[0]))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("decode stored grant attr %q: %w", key, err)
		}
		if number, ok := value.(json.Number); ok {
			if integer, err := number.Int64(); err == nil {
				value = integer
			}
		}
		out[key] = value
	}
	return out, nil
}

// Target returns the canonical exact HF resource name.
func Target(grant grants.Grant) string { return bkpolicy.FirstValue(grant.Target.Fields[targetName]) }

// Ref returns the optional exact Git ref.
func Ref(grant grants.Grant) string { return bkpolicy.FirstValue(grant.Target.Fields[targetRef]) }

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
		Target(grant) == target && Ref(grant) == ref && grant.UsedCount+grant.ReservedCount < grant.MaxUses
}
