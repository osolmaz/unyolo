package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"

	"github.com/osolmaz/brokerkit/credentiallifecycle"
)

type previousManagedCredential struct {
	existed bool
	data    []byte
}

func validateCredentialClasses(files []ManagedFile, removals []ManagedFileRef) error {
	seen := make(map[string]struct{})
	if err := validateCredentialClassItems(seen, files, func(file ManagedFile) string { return file.CredentialClass }); err != nil {
		return err
	}
	return validateCredentialClassItems(seen, removals, func(file ManagedFileRef) string { return file.CredentialClass })
}

func validateCredentialClassItems[T any](seen map[string]struct{}, files []T, classFor func(T) string) error {
	for _, file := range files {
		class := classFor(file)
		if class != "" && !credentiallifecycle.ValidIdentifier(class) {
			return errors.New("managed credential class is invalid")
		}
		if err := addCredentialClass(seen, class); err != nil {
			return err
		}
	}
	return nil
}

func addCredentialClass(seen map[string]struct{}, class string) error {
	if class == "" {
		return nil
	}
	if _, exists := seen[class]; exists {
		return errors.New("managed credential classes must be unique")
	}
	seen[class] = struct{}{}
	return nil
}

func recordManagedCredentialChanges(reporter *credentiallifecycle.Reporter, files []ManagedFile,
	previous []previousManagedCredential, removed map[string]string) error {
	if reporter == nil {
		return nil
	}
	return errors.Join(recordCredentialWrites(reporter, files, previous), recordCredentialRemovals(reporter, removed))
}

func recordCredentialWrites(reporter *credentiallifecycle.Reporter, files []ManagedFile, previous []previousManagedCredential) error {
	var recordErr error
	for index, file := range files {
		if file.CredentialClass == "" || index >= len(previous) {
			continue
		}
		old := previous[index]
		if old.existed && credentialIdentifier(old.data) == credentialIdentifier(file.Data) {
			continue
		}
		recordErr = errors.Join(recordErr, reporter.Record(credentialWriteEvent(file, old)))
	}
	return recordErr
}

func credentialWriteEvent(file ManagedFile, old previousManagedCredential) credentiallifecycle.Event {
	event := credentiallifecycle.Event{Class: file.CredentialClass, Action: credentiallifecycle.ActionCreated,
		Outcome: credentiallifecycle.OutcomeSucceeded, CurrentID: credentialIdentifier(file.Data)}
	if old.existed {
		event.Action = credentiallifecycle.ActionRotated
		event.PreviousID = credentialIdentifier(old.data)
	}
	return event
}

func recordCredentialRemovals(reporter *credentiallifecycle.Reporter, removed map[string]string) error {
	var recordErr error
	classes := make([]string, 0, len(removed))
	for class := range removed {
		classes = append(classes, class)
	}
	slices.Sort(classes)
	for _, class := range classes {
		id := removed[class]
		if class == "" || id == "" {
			continue
		}
		recordErr = errors.Join(recordErr, reporter.Record(credentiallifecycle.Event{Class: class,
			Action: credentiallifecycle.ActionRevoked, Outcome: credentiallifecycle.OutcomeSucceeded, PreviousID: id}))
	}
	return recordErr
}

func credentialIdentifier(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:8])
}
