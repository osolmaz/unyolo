// Package transaction coordinates durable host deployment steps and rollback.
package transaction

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/osolmaz/unyolo/internal/securefile"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

const APIVersion = "unyolo.io/host-transaction/v1"

// Step is one durable host mutation with a secret-safe rollback handle.
type Step struct {
	ID              string
	Kind            string
	Apply           func(context.Context) (string, error)
	Rollback        func(context.Context, string) error
	RollbackRunning func(context.Context) error
}

// StepRecord is one durable completion marker.
type StepRecord struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	State          string `json:"state"`
	RollbackHandle string `json:"rollback_handle,omitempty"`
}

// Journal is the closed crash-recovery record.
type Journal struct {
	APIVersion       string       `json:"api_version"`
	ID               string       `json:"id"`
	DeploymentDigest string       `json:"deployment_digest"`
	PlanDigest       string       `json:"plan_digest"`
	CandidateBundle  string       `json:"candidate_bundle_id"`
	PreviousBundle   string       `json:"previous_bundle_id,omitempty"`
	Phase            string       `json:"phase"`
	Steps            []StepRecord `json:"steps"`
	StartedAt        time.Time    `json:"started_at"`
}

// Coordinator persists one journal below a private host state directory.
type Coordinator struct {
	StateDirectory string
	Now            func() time.Time
}

// Run applies steps in order and rolls completed steps back on failure.
//
//nolint:cyclop // Journaled apply and reverse rollback share one ordered transaction state machine.
func (coordinator Coordinator) Run(ctx context.Context, deploymentDigest, planDigest, candidate, previous string, steps []Step) error {
	if err := validateSteps(steps); err != nil {
		return err
	}
	if err := os.MkdirAll(coordinator.StateDirectory, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(coordinator.path()); err == nil {
		return errors.New("unfinished host deployment transaction requires recovery")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	id, err := transactionID()
	if err != nil {
		return err
	}
	journal := Journal{
		APIVersion: APIVersion, ID: id, DeploymentDigest: deploymentDigest,
		PlanDigest: planDigest, CandidateBundle: candidate, PreviousBundle: previous,
		Phase: "applying", StartedAt: coordinator.now(),
	}
	for _, step := range steps {
		journal.Steps = append(journal.Steps, StepRecord{ID: step.ID, Kind: step.Kind, State: "pending"})
	}
	if err := coordinator.write(journal); err != nil {
		return err
	}
	for index, step := range steps {
		journal.Steps[index].State = "running"
		if err := coordinator.write(journal); err != nil {
			journal.Steps[index].State = "pending"
			return coordinator.rollback(ctx, journal, stepCompensations(steps), err)
		}
		handle, applyErr := step.Apply(ctx)
		if applyErr != nil {
			journal.Phase = "rolling_back"
			if err := coordinator.write(journal); err != nil {
				return errors.Join(applyErr, err)
			}
			return coordinator.rollback(ctx, journal, stepCompensations(steps), applyErr)
		}
		journal.Steps[index].State = "complete"
		journal.Steps[index].RollbackHandle = handle
		if err := coordinator.write(journal); err != nil {
			return coordinator.rollback(ctx, journal, stepCompensations(steps), err)
		}
	}
	journal.Phase = "committed"
	return coordinator.write(journal)
}

// Pending returns the durable transaction, when present, for recovery binding.
func (coordinator Coordinator) Pending() (Journal, bool, error) { return coordinator.read() }

// Finalize cleans committed step rollback artifacts before clearing the journal.
func (coordinator Coordinator) Finalize(ctx context.Context, handlers map[string]func(context.Context, string) error) error {
	journal, found, err := coordinator.read()
	if err != nil || !found || journal.Phase != "committed" {
		return err
	}
	for index, record := range journal.Steps {
		if record.State == "finalized" {
			continue
		}
		if record.State != "complete" {
			return errors.New("committed host deployment transaction has an invalid step state")
		}
		handler := handlers[record.Kind]
		if handler == nil {
			return fmt.Errorf("finalizer for %q is unavailable", record.Kind)
		}
		if err := handler(ctx, record.RollbackHandle); err != nil {
			return err
		}
		journal.Steps[index].State = "finalized"
		if err := coordinator.write(journal); err != nil {
			return err
		}
	}
	return coordinator.clear()
}

// Recover rolls back a noncommitted journal with matching step handlers. A
// step that was still running uses the handler for "running:" plus its kind.
// Without that handler, the step's outcome is uncertain and needs manual
// recovery.
func (coordinator Coordinator) Recover(ctx context.Context, handlers map[string]func(context.Context, string) error) error {
	journal, found, err := coordinator.read()
	if err != nil || !found {
		return err
	}
	if journal.Phase == "committed" {
		return errors.New("committed host deployment transaction requires finalization")
	}
	compensations := map[int]compensation{}
	for index, record := range journal.Steps {
		switch record.State {
		case "running":
			handler := handlers["running:"+record.Kind]
			if handler == nil {
				journal.Phase = "recovery_required"
				if err := coordinator.write(journal); err != nil {
					return err
				}
				return fmt.Errorf("transaction step %q has an uncertain apply outcome; manual recovery is required", record.ID)
			}
			compensations[index] = compensation{running: func(ctx context.Context) error { return handler(ctx, "") }}
		case "complete":
			handler := handlers[record.Kind]
			if handler == nil {
				journal.Phase = "recovery_required"
				_ = coordinator.write(journal)
				return fmt.Errorf("recovery handler for %q is unavailable", record.Kind)
			}
			compensations[index] = compensation{complete: handler}
		}
	}
	return coordinator.rollback(ctx, journal, func(index int) compensation { return compensations[index] }, nil)
}

// compensation undoes one step: complete undoes a finished step with its
// rollback handle, and running undoes a step whose apply did not finish.
type compensation struct {
	complete func(context.Context, string) error
	running  func(context.Context) error
}

func stepCompensations(steps []Step) func(int) compensation {
	return func(index int) compensation {
		return compensation{complete: steps[index].Rollback, running: steps[index].RollbackRunning}
	}
}

// rollback undoes every running and completed step, the newest first. One
// undo can depend on another that comes later: a runtime can start again
// only after the components restore their earlier configuration. So each
// failed undo is tried once more after all the others.
func (coordinator Coordinator) rollback(ctx context.Context, journal Journal, compensations func(int) compensation, cause error) error {
	journal.Phase = "rolling_back"
	_ = coordinator.write(journal)
	var pending []int
	for index := len(journal.Steps) - 1; index >= 0; index-- {
		if state := journal.Steps[index].State; state == "running" || state == "complete" {
			pending = append(pending, index)
		}
	}
	var failures []error
	for attempt := 0; attempt < 2 && len(pending) > 0; attempt++ {
		var failed []int
		failures = nil
		for _, index := range pending {
			undone, err := coordinator.compensate(ctx, &journal, index, compensations(index))
			if err != nil {
				failures = append(failures, err)
			}
			if !undone {
				failed = append(failed, index)
			}
		}
		pending = failed
	}
	if len(pending) > 0 || len(failures) > 0 {
		journal.Phase = "recovery_required"
		_ = coordinator.write(journal)
		return errors.Join(append([]error{cause}, failures...)...)
	}
	return errors.Join(cause, coordinator.clear())
}

// compensate undoes one step and records it. It reports whether the undo
// itself succeeded, even when the record write afterwards failed.
func (coordinator Coordinator) compensate(ctx context.Context, journal *Journal, index int, undo compensation) (bool, error) {
	record := journal.Steps[index]
	var err error
	if record.State == "running" {
		err = undo.running(ctx)
	} else {
		err = undo.complete(ctx, record.RollbackHandle)
	}
	if err != nil {
		return false, err
	}
	journal.Steps[index].State = "rolled_back"
	return true, coordinator.write(*journal)
}

func (coordinator Coordinator) read() (Journal, bool, error) {
	data, err := os.ReadFile(coordinator.path()) // #nosec G304 -- fixed private state path.
	if errors.Is(err, os.ErrNotExist) {
		return Journal{}, false, nil
	}
	if err != nil {
		return Journal{}, false, err
	}
	var journal Journal
	if err := strictjson.Decode(data, &journal, true); err != nil || journal.APIVersion != APIVersion {
		return Journal{}, false, errors.New("host deployment transaction is invalid")
	}
	return journal, true, nil
}

func (coordinator Coordinator) write(journal Journal) error {
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return securefile.AtomicWrite(coordinator.path(), append(data, '\n'), 0o600, "host deployment transaction")
}

func (coordinator Coordinator) clear() error {
	if err := os.Remove(coordinator.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (coordinator Coordinator) path() string {
	return filepath.Join(coordinator.StateDirectory, "deployment-transaction.json")
}

func (coordinator Coordinator) now() time.Time {
	if coordinator.Now != nil {
		return coordinator.Now().UTC()
	}
	return time.Now().UTC()
}

func validateSteps(steps []Step) error {
	if len(steps) == 0 || len(steps) > 1024 {
		return errors.New("host deployment transaction step count is invalid")
	}
	ids := make([]string, 0, len(steps))
	for _, step := range steps {
		if step.ID == "" || step.Kind == "" || step.Apply == nil || step.Rollback == nil || step.RollbackRunning == nil || slices.Contains(ids, step.ID) {
			return errors.New("host deployment transaction step is invalid or duplicated")
		}
		ids = append(ids, step.ID)
	}
	return nil
}

func transactionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
