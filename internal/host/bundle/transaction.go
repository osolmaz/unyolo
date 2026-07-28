package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/osolmaz/unyolo/internal/strictjson"
)

type activationTransaction struct {
	APIVersion         string      `json:"api_version"`
	CandidateBundleID  string      `json:"candidate_bundle_id"`
	PreviousBundleID   string      `json:"previous_bundle_id,omitempty"`
	PreviousActivation *Activation `json:"previous_activation,omitempty"`
	FinalActivation    Activation  `json:"final_activation"`
	StartedAt          time.Time   `json:"started_at"`
}

func (i Installer) readActivation() (Activation, error) {
	data, err := os.ReadFile(filepath.Join(i.Paths.StateDir, activationFilename)) // #nosec G304 -- fixed host state path.
	if err != nil {
		return Activation{}, err
	}
	var record Activation
	if err := strictjson.Decode(data, &record, true); err != nil || record.APIVersion != APIVersion {
		return Activation{}, errors.New("host activation record is invalid")
	}
	return record, nil
}

func (i Installer) activationSnapshot() (*Activation, error) {
	record, err := i.readActivation()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (i Installer) recoverInterruptedActivation() error {
	transaction, found, err := i.readActivationTransaction()
	if err != nil || !found {
		return err
	}
	committed, err := i.transactionCommitted(transaction)
	if err != nil {
		return err
	}
	if committed {
		return i.clearTransaction()
	}
	return i.restoreInterruptedTransaction(transaction)
}

func (i Installer) readActivationTransaction() (activationTransaction, bool, error) {
	data, err := os.ReadFile(filepath.Join(i.Paths.StateDir, transactionFilename)) // #nosec G304 -- fixed private host state path.
	if errors.Is(err, os.ErrNotExist) {
		return activationTransaction{}, false, nil
	}
	if err != nil {
		return activationTransaction{}, false, err
	}
	var transaction activationTransaction
	if err := strictjson.Decode(data, &transaction, true); err != nil || !validActivationTransaction(transaction) {
		return activationTransaction{}, false, errors.New("host activation transaction is invalid")
	}
	return transaction, true, nil
}

func (i Installer) transactionCommitted(transaction activationTransaction) (bool, error) {
	current, err := i.activationSnapshot()
	if err != nil || current == nil || !reflect.DeepEqual(*current, transaction.FinalActivation) {
		return false, err
	}
	active, manifest, err := i.currentManifest()
	if err != nil || active != current.ActiveBundleID {
		return transactionNotCommitted()
	}
	err = i.verifyRelease(manifest, filepath.Join(i.Paths.Root, "releases", active))
	return err == nil, nil
}

func transactionNotCommitted() (bool, error) { return false, nil }

func (i Installer) restoreInterruptedTransaction(transaction activationTransaction) error {
	candidate, err := i.manifest(transaction.CandidateBundleID)
	if err != nil {
		return err
	}
	var previous Manifest
	if transaction.PreviousBundleID != "" {
		previous, err = i.manifest(transaction.PreviousBundleID)
		if err != nil {
			return err
		}
	}
	if err := i.restore(transaction.PreviousBundleID, previous, candidate); err != nil {
		return errors.Join(err, i.writeRecoveryRecord(transaction.PreviousBundleID, transaction.CandidateBundleID))
	}
	if err := i.restoreActivationRecord(transaction.PreviousActivation); err != nil {
		return errors.Join(err, i.writeRecoveryRecord(transaction.PreviousBundleID, transaction.CandidateBundleID))
	}
	return i.clearTransaction()
}

func validActivationTransaction(transaction activationTransaction) bool {
	if !validTransactionHeader(transaction) || !validFinalActivation(transaction.FinalActivation) {
		return false
	}
	if transaction.PreviousActivation == nil {
		return validFirstActivationTransaction(transaction)
	}
	return validReplacementTransaction(transaction)
}

func validTransactionHeader(transaction activationTransaction) bool {
	return transaction.APIVersion == APIVersion && !transaction.StartedAt.IsZero() &&
		identifierPattern.MatchString(transaction.CandidateBundleID) &&
		(transaction.PreviousBundleID == "" || identifierPattern.MatchString(transaction.PreviousBundleID)) &&
		transaction.CandidateBundleID != transaction.PreviousBundleID &&
		(transaction.PreviousBundleID == "") == (transaction.PreviousActivation == nil)
}

func validFinalActivation(final Activation) bool {
	return final.APIVersion == APIVersion && !final.RecoveryRequired &&
		!final.ActivatedAt.IsZero() && identifierPattern.MatchString(final.ActiveBundleID)
}

func validFirstActivationTransaction(transaction activationTransaction) bool {
	return transaction.FinalActivation.ActiveBundleID == transaction.CandidateBundleID &&
		transaction.FinalActivation.PreviousBundleID == ""
}

func validReplacementTransaction(transaction activationTransaction) bool {
	previous := transaction.PreviousActivation
	return previous.APIVersion == APIVersion && !previous.RecoveryRequired && !previous.ActivatedAt.IsZero() &&
		previous.ActiveBundleID == transaction.PreviousBundleID &&
		transaction.FinalActivation.ActiveBundleID == transaction.CandidateBundleID &&
		transaction.FinalActivation.PreviousBundleID == previous.ActiveBundleID
}

func (i Installer) restoreActivationRecord(previous *Activation) error {
	path := filepath.Join(i.Paths.StateDir, activationFilename)
	if previous != nil {
		return writeJSONAtomic(path, *previous, 0o600)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(i.Paths.StateDir)
}

func (i Installer) writeRecoveryRecord(previous, candidate string) error {
	active, _, currentErr := i.currentManifest()
	if active == "" {
		active = candidate
	}
	record := Activation{APIVersion: APIVersion, ActiveBundleID: active,
		PreviousBundleID: previous, ActivatedAt: i.Now().UTC(), RecoveryRequired: true}
	return errors.Join(currentErr, writeJSONAtomic(filepath.Join(i.Paths.StateDir, activationFilename), record, 0o600))
}

func (i Installer) clearTransaction() error {
	if err := os.Remove(filepath.Join(i.Paths.StateDir, transactionFilename)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(i.Paths.StateDir)
}
