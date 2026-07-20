package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/credential/lifecycle"
)

const (
	maxManagedFileBytes      = 16 * 1024 * 1024
	defaultReadinessTimeout  = 15 * time.Second
	defaultReadinessInterval = 100 * time.Millisecond
)

var errServiceReadinessFailed = errors.New("service readiness check failed before retiring managed files")

// ManagedFileArea selects the trusted root beneath which a setup file lives.
type ManagedFileArea string

const (
	ManagedFileConfig ManagedFileArea = "config"
	ManagedFileState  ManagedFileArea = "state"
)

// ManagedFileOwner selects the ownership class for a setup file.
type ManagedFileOwner string

const (
	ManagedFileOwnerRoot    ManagedFileOwner = "root"
	ManagedFileOwnerService ManagedFileOwner = "service"
)

// ManagedFile is one opaque provider-owned setup payload.
type ManagedFile struct {
	Area            ManagedFileArea
	Name            string
	Data            []byte
	Mode            os.FileMode
	Owner           ManagedFileOwner
	CredentialClass string
}

// ManagedFileRef identifies one provider-owned file that should no longer
// exist after a successful configuration cutover.
type ManagedFileRef struct {
	Area            ManagedFileArea
	Name            string
	CredentialClass string
}

// ReadinessCheck confirms that a restarted broker initialized with its new
// configuration before retired credentials are deleted.
type ReadinessCheck func(context.Context) error

type installTransaction struct {
	write    func() error
	restore  func() error
	start    func() error
	rollback func() error
	ready    func() error
	retire   func() error
	noStart  bool
}

func (transaction installTransaction) apply() error {
	if err := transaction.write(); err != nil {
		return errors.Join(err, transaction.restore())
	}
	if transaction.noStart {
		return nil
	}
	if err := transaction.start(); err != nil {
		return errors.Join(err, transaction.rollback())
	}
	if err := transaction.ready(); err != nil {
		return errors.Join(err, transaction.rollback())
	}
	return transaction.retire()
}

func durationOr(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

func validateInstallReadiness(timeout, interval time.Duration, removalCount int, noStart bool, check ReadinessCheck) error {
	if timeout < 0 || interval < 0 {
		return errors.New("readiness timeout and interval must not be negative")
	}
	if removalCount > 0 && !noStart && check == nil {
		return errors.New("managed file retirement requires a readiness check")
	}
	return nil
}

func validateManagedFilePayload(file ManagedFile) error {
	if len(file.Data) > maxManagedFileBytes {
		return fmt.Errorf("managed file %q exceeds %d bytes", file.Name, maxManagedFileBytes)
	}
	return nil
}

func validateManagedFileOwner(file ManagedFile) error {
	if file.Owner != ManagedFileOwnerRoot && file.Owner != ManagedFileOwnerService {
		return fmt.Errorf("managed file %q has invalid owner %q", file.Name, file.Owner)
	}
	return nil
}

func validateManagedFileMode(file ManagedFile, readable bool) error {
	if file.Mode == 0 || file.Mode&^os.ModePerm != 0 || file.Mode.Perm()&0o022 != 0 {
		return fmt.Errorf("managed file %q has unsafe mode", file.Name)
	}
	if !readable {
		return fmt.Errorf("managed file %q is not readable by the service", file.Name)
	}
	return nil
}

func managedFileReadable(serviceUser string, file ManagedFile) bool {
	if file.Owner == ManagedFileOwnerService || serviceUser == "root" {
		return file.Mode.Perm()&0o400 != 0
	}
	return file.Mode.Perm()&0o044 != 0
}

func validManagedFileName(name string) bool {
	if name == "" || name == "." || filepath.Base(name) != name {
		return false
	}
	for _, char := range name {
		if !isPortableManagedFileNameCharacter(char) {
			return false
		}
	}
	return true
}

func isPortableManagedFileNameCharacter(char rune) bool {
	switch {
	case char >= 'a' && char <= 'z':
		return true
	case char >= 'A' && char <= 'Z':
		return true
	case char >= '0' && char <= '9':
		return true
	default:
		return strings.ContainsRune("._+-", char)
	}
}

func previousCredentials[T any](files []ManagedFile, snapshots []T, inspect func(T) previousManagedCredential) []previousManagedCredential {
	previous := make([]previousManagedCredential, len(files))
	for index := range files {
		previous[index] = inspect(snapshots[index])
	}
	return previous
}

func recordSnapshotCredentialChanges[T any](reporter *credentiallifecycle.Reporter, files []ManagedFile, snapshots []T,
	inspect func(T) previousManagedCredential, removed map[string]string) error {
	return recordManagedCredentialChanges(reporter, files, previousCredentials(files, snapshots, inspect), removed)
}

func captureCredentialRemovals(files []ManagedFileRef, capture func(ManagedFileRef) (bool, []byte, error)) (map[string]string, error) {
	result := make(map[string]string)
	for _, file := range files {
		class, id, err := captureCredentialRemoval(file, capture)
		if err != nil {
			return nil, err
		}
		if class != "" {
			result[class] = id
		}
	}
	return result, nil
}

func captureCredentialRemoval(file ManagedFileRef, capture func(ManagedFileRef) (bool, []byte, error)) (string, string, error) {
	if file.CredentialClass == "" {
		return "", "", nil
	}
	exists, data, err := capture(file)
	if err != nil {
		return "", "", err
	}
	defer clearSecretBytes(data)
	if !exists {
		return "", "", nil
	}
	return file.CredentialClass, credentialIdentifier(data), nil
}

func reverseJoin[T any](values []T, apply func(T) error) error {
	var result error
	for index := len(values) - 1; index >= 0; index-- {
		result = errors.Join(result, apply(values[index]))
	}
	return result
}

func reverseRestore[T any](values []T, preview bool, apply func(T, bool) error) error {
	return reverseJoin(values, func(value T) error { return apply(value, preview) })
}

func clearSnapshotSecrets[T any](values []T, dataFor func(*T) []byte) {
	for index := range values {
		clearSecretBytes(dataFor(&values[index]))
	}
}

// SystemdInstallPlan describes one complete broker systemd installation.
type SystemdInstallPlan struct {
	User             string
	Group            string
	AdditionalGroups []string
	GroupMembers     map[string][]string
	ConfigDir        string
	StateDir         string
	SharedStateDir   string
	SystemdDir       string
	UnitName         string
	Files            []ManagedFile
	RemoveFiles      []ManagedFileRef
	ReadyCheck       ReadinessCheck
	ReadyTimeout     time.Duration
	ReadyInterval    time.Duration
	Unit             SystemdUnit
	SocketUnits      []SystemdSocketInstall
	ActivationUnits  []string
	NoStart          bool
	AllowNonRoot     bool
	Runner           CommandRunner
	Lifecycle        *credentiallifecycle.Reporter
}
