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

	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const APIVersion = "brokerkit.io/host-transaction/v1"

// Step is one durable host mutation with a secret-safe rollback handle.
type Step struct {
	ID       string
	Kind     string
	Apply    func(context.Context) (string, error)
	Rollback func(context.Context, string) error
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
			return coordinator.rollback(ctx, journal, steps, index-1, err)
		}
		handle, applyErr := step.Apply(ctx)
		if applyErr != nil {
			return coordinator.rollback(ctx, journal, steps, index-1, applyErr)
		}
		journal.Steps[index].State = "complete"
		journal.Steps[index].RollbackHandle = handle
		if err := coordinator.write(journal); err != nil {
			return coordinator.rollback(ctx, journal, steps, index, err)
		}
	}
	journal.Phase = "committed"
	if err := coordinator.write(journal); err != nil {
		return err
	}
	return coordinator.clear()
}

// Recover rolls back a noncommitted journal with matching step handlers.
//
//nolint:cyclop // Recovery handles committed, uncertain, missing-handler, failed, and durable rollback states.
func (coordinator Coordinator) Recover(ctx context.Context, handlers map[string]func(context.Context, string) error) error {
	journal, found, err := coordinator.read()
	if err != nil || !found {
		return err
	}
	if journal.Phase == "committed" {
		return coordinator.clear()
	}
	for index := len(journal.Steps) - 1; index >= 0; index-- {
		record := journal.Steps[index]
		if record.State == "running" {
			journal.Phase = "recovery_required"
			if err := coordinator.write(journal); err != nil {
				return err
			}
			return fmt.Errorf("transaction step %q has an uncertain apply outcome; manual recovery is required", record.ID)
		}
		if record.State != "complete" {
			continue
		}
		handler := handlers[record.Kind]
		if handler == nil {
			journal.Phase = "recovery_required"
			_ = coordinator.write(journal)
			return fmt.Errorf("recovery handler for %q is unavailable", record.Kind)
		}
		if err := handler(ctx, record.RollbackHandle); err != nil {
			journal.Phase = "recovery_required"
			_ = coordinator.write(journal)
			return err
		}
		journal.Steps[index].State = "rolled_back"
		if err := coordinator.write(journal); err != nil {
			return err
		}
	}
	return coordinator.clear()
}

func (coordinator Coordinator) rollback(ctx context.Context, journal Journal, steps []Step, last int, cause error) error {
	journal.Phase = "rolling_back"
	_ = coordinator.write(journal)
	var rollbackErrors []error
	for index := last; index >= 0; index-- {
		if journal.Steps[index].State != "complete" {
			continue
		}
		if err := steps[index].Rollback(ctx, journal.Steps[index].RollbackHandle); err != nil {
			rollbackErrors = append(rollbackErrors, err)
			continue
		}
		journal.Steps[index].State = "rolled_back"
		if err := coordinator.write(journal); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if len(rollbackErrors) > 0 {
		journal.Phase = "recovery_required"
		_ = coordinator.write(journal)
		return errors.Join(append([]error{cause}, rollbackErrors...)...)
	}
	return errors.Join(cause, coordinator.clear())
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
	data = append(data, '\n')
	file, err := os.CreateTemp(coordinator.StateDirectory, ".transaction-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, coordinator.path())
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
		if step.ID == "" || step.Kind == "" || step.Apply == nil || step.Rollback == nil || slices.Contains(ids, step.ID) {
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
