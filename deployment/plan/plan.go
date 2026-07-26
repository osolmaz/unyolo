// Package plan creates canonical secret-safe host deployment plans.
package plan

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/deployment/api"
	"github.com/osolmaz/brokerkit/deployment/profile"
)

const APIVersion = "brokerkit.io/system-plan/v1"

// Kind is the overall deployment result.
type Kind string

const (
	KindNoop      Kind = "noop"
	KindInstall   Kind = "install"
	KindReconcile Kind = "reconcile"
	KindUpgrade   Kind = "upgrade"
	KindBlocked   Kind = "blocked"
)

// Action is one ordered host or component mutation.
type Action struct {
	ID            string       `json:"id"`
	ComponentID   string       `json:"component_id"`
	Type          string       `json:"type"`
	Risk          string       `json:"risk"`
	Resource      api.Resource `json:"resource"`
	CurrentDigest string       `json:"current_digest,omitempty"`
	DesiredDigest string       `json:"desired_digest,omitempty"`
	Restart       bool         `json:"restart,omitempty"`
	DependsOn     []string     `json:"depends_on,omitempty"`
}

// Component records one adapter plan without provider secrets.
type Component struct {
	ID            string                 `json:"id"`
	PlanDigest    string                 `json:"plan_digest"`
	Credentials   []api.CredentialAction `json:"credentials,omitempty"`
	Verification  []string               `json:"verification,omitempty"`
	BlockedReason string                 `json:"blocked_reason,omitempty"`
}

// Plan is one canonical reviewed host change.
type Plan struct {
	APIVersion          string      `json:"api_version"`
	DeploymentName      string      `json:"deployment_name"`
	DeploymentDigest    string      `json:"deployment_digest"`
	ObservedFingerprint string      `json:"observed_fingerprint"`
	RuntimeBundleID     string      `json:"runtime_bundle_id"`
	Kind                Kind        `json:"kind"`
	Actions             []Action    `json:"actions"`
	Components          []Component `json:"components"`
	Digest              string      `json:"digest"`
}

// Build combines component plans into one dependency-ordered canonical plan.
//
//nolint:cyclop // Canonical planning combines all bounded host and component action classes in one ordering pass.
func Build(snapshot profile.Snapshot, observedFingerprint string, responses []api.Response, activeBundleID string) (Plan, error) {
	if !validDigest(observedFingerprint) {
		return Plan{}, errors.New("observed-state fingerprint is invalid")
	}
	result := Plan{
		APIVersion: APIVersion, DeploymentName: snapshot.Deployment.Name,
		DeploymentDigest: snapshot.Digest, ObservedFingerprint: observedFingerprint,
		RuntimeBundleID: snapshot.Manifest.BundleID,
	}
	if activeBundleID == "" {
		result.Kind = KindInstall
	} else if activeBundleID != snapshot.Manifest.BundleID {
		result.Kind = KindUpgrade
	} else {
		result.Kind = KindNoop
	}
	seenComponents := map[string]bool{}
	for _, response := range responses {
		if err := response.Validate(); err != nil {
			return Plan{}, fmt.Errorf("component %q plan: %w", response.ComponentID, err)
		}
		if seenComponents[response.ComponentID] {
			return Plan{}, fmt.Errorf("component %q returned more than one plan", response.ComponentID)
		}
		seenComponents[response.ComponentID] = true
		component := Component{
			ID: response.ComponentID, PlanDigest: response.PlanDigest,
			Credentials: response.Credentials, Verification: response.Verification,
			BlockedReason: response.BlockedReason,
		}
		result.Components = append(result.Components, component)
		if response.Status == "blocked" {
			result.Kind = KindBlocked
		}
		for _, componentAction := range response.Actions {
			result.Actions = append(result.Actions, Action{
				ID:          response.ComponentID + "." + componentAction.ID,
				ComponentID: response.ComponentID, Type: componentAction.Type,
				Risk: componentAction.Risk, Resource: componentAction.Resource,
				CurrentDigest: componentAction.CurrentDigest,
				DesiredDigest: componentAction.DesiredDigest, Restart: componentAction.Restart,
				DependsOn: qualifyDependencies(response.ComponentID, componentAction.DependsOn),
			})
		}
	}
	if len(result.Actions) > 0 && result.Kind == KindNoop {
		result.Kind = KindReconcile
	}
	ordered, err := orderActions(result.Actions)
	if err != nil {
		return Plan{}, err
	}
	result.Actions = ordered
	slices.SortFunc(result.Components, func(a, b Component) int { return strings.Compare(a.ID, b.ID) })
	for index := range result.Components {
		slices.SortFunc(result.Components[index].Credentials, func(a, b api.CredentialAction) int { return strings.Compare(a.Slot, b.Slot) })
		slices.Sort(result.Components[index].Verification)
	}
	digest, err := calculateDigest(result)
	if err != nil {
		return Plan{}, err
	}
	result.Digest = digest
	return result, nil
}

// Validate checks a decoded plan and its canonical digest.
//
//nolint:cyclop // The complete plan artifact is validated field by field before apply.
func (value Plan) Validate() error {
	if value.APIVersion != APIVersion || value.DeploymentName == "" || !validDigest(value.DeploymentDigest) ||
		!validDigest(value.ObservedFingerprint) || value.RuntimeBundleID == "" || !validDigest(value.Digest) {
		return errors.New("system plan identity is invalid")
	}
	if !slices.Contains([]Kind{KindNoop, KindInstall, KindReconcile, KindUpgrade, KindBlocked}, value.Kind) {
		return errors.New("system plan kind is invalid")
	}
	ordered, err := orderActions(value.Actions)
	if err != nil {
		return err
	}
	if !slices.EqualFunc(ordered, value.Actions, func(a, b Action) bool { return a.ID == b.ID }) {
		return errors.New("system plan actions are not in canonical order")
	}
	actual, err := calculateDigest(value)
	if err != nil {
		return err
	}
	if actual != value.Digest {
		return errors.New("system plan digest does not match contents")
	}
	return nil
}

// Marshal returns canonical indented JSON for review.
func Marshal(value Plan) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	return append(data, '\n'), err
}

func calculateDigest(value Plan) (string, error) {
	value.Digest = ""
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum), nil
}

func qualifyDependencies(componentID string, dependencies []string) []string {
	result := make([]string, len(dependencies))
	for index, dependency := range dependencies {
		if strings.Contains(dependency, ".") {
			result[index] = dependency
		} else {
			result[index] = componentID + "." + dependency
		}
	}
	slices.Sort(result)
	return result
}

//nolint:cyclop // Stable topological ordering handles each dependency edge and failure explicitly.
func orderActions(actions []Action) ([]Action, error) {
	byID := make(map[string]Action, len(actions))
	for _, action := range actions {
		if action.ID == "" || byID[action.ID].ID != "" {
			return nil, errors.New("system plan action identity is invalid or duplicated")
		}
		byID[action.ID] = action
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	result := make([]Action, 0, len(actions))
	ids := make([]string, 0, len(actions))
	for id := range byID {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var visit func(string) error
	visit = func(id string) error {
		if visited[id] {
			return nil
		}
		if visiting[id] {
			return errors.New("system plan action dependency cycle")
		}
		action, exists := byID[id]
		if !exists {
			return fmt.Errorf("system plan references unknown action %q", id)
		}
		visiting[id] = true
		dependencies := append([]string(nil), action.DependsOn...)
		slices.Sort(dependencies)
		action.DependsOn = dependencies
		for _, dependency := range dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true
		result = append(result, action)
		return nil
	}
	for _, id := range ids {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[7:] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
