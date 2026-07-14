package service

import (
	"context"
	"errors"
	"os"
	"time"
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
	Area  ManagedFileArea
	Name  string
	Data  []byte
	Mode  os.FileMode
	Owner ManagedFileOwner
}

// ManagedFileRef identifies one provider-owned file that should no longer
// exist after a successful configuration cutover.
type ManagedFileRef struct {
	Area ManagedFileArea
	Name string
}

// ReadinessCheck confirms that a restarted broker initialized with its new
// configuration before retired credentials are deleted.
type ReadinessCheck func(context.Context) error

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
}
