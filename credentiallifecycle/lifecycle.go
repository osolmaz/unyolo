// Package credentiallifecycle records secret-safe credential lifecycle events.
package credentiallifecycle

import (
	"errors"
	"regexp"
	"strings"

	"github.com/osolmaz/brokerkit/audit"
)

const Operation = "credential.lifecycle"

type Action string

const (
	ActionCreated Action = "created"
	ActionRotated Action = "rotated"
	ActionRevoked Action = "revoked"
)

type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
)

var safeValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)

// ValidIdentifier reports whether a non-secret lifecycle identifier is within
// the closed, bounded audit vocabulary.
func ValidIdentifier(value string) bool { return safeValue.MatchString(value) }

// Event contains only stable identifiers and closed lifecycle values.
type Event struct {
	Class      string
	Action     Action
	Outcome    Outcome
	PreviousID string
	CurrentID  string
	Provider   string
}

// Reporter writes lifecycle events through the broker audit boundary.
type Reporter struct {
	recorder audit.Recorder
	broker   string
	actor    string
}

func New(recorder audit.Recorder, broker, actor string) (*Reporter, error) {
	if recorder == nil || !safeValue.MatchString(broker) || !safeValue.MatchString(actor) {
		return nil, errors.New("credential lifecycle audit configuration is invalid")
	}
	return &Reporter{recorder: recorder, broker: broker, actor: actor}, nil
}

func (r *Reporter) Record(event Event) error {
	if r == nil || r.recorder == nil || !validEvent(event) {
		return errors.New("credential lifecycle event is invalid")
	}
	attrs := map[string]string{"lifecycle_action": string(event.Action), "lifecycle_outcome": string(event.Outcome)}
	addSafe(attrs, "previous_id", event.PreviousID)
	addSafe(attrs, "current_id", event.CurrentID)
	addSafe(attrs, "provider", event.Provider)
	return r.recorder.Record(audit.Event{
		Broker: r.broker, Client: r.actor, Operation: Operation, Target: event.Class,
		Decision: string(event.Outcome), Reason: string(event.Action), Attrs: attrs,
	})
}

func validEvent(event Event) bool {
	return safeValue.MatchString(event.Class) && validLifecycleValues(event) && validReferences(event)
}

func validLifecycleValues(event Event) bool {
	validAction := event.Action == ActionCreated || event.Action == ActionRotated || event.Action == ActionRevoked
	validOutcome := event.Outcome == OutcomeSucceeded || event.Outcome == OutcomeFailed
	return validAction && validOutcome
}

func validReferences(event Event) bool {
	return optionalSafe(event.PreviousID) && optionalSafe(event.CurrentID) && optionalSafe(event.Provider)
}

func optionalSafe(value string) bool {
	return strings.TrimSpace(value) == "" || safeValue.MatchString(value)
}

func addSafe(values map[string]string, key, value string) {
	if value != "" {
		values[key] = value
	}
}
