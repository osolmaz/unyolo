package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/credential/lifecycle"
)

const credentialRollbackRestartTimeout = 30 * time.Second

// CredentialReplacePlan describes an exact replacement of credentials owned
// by an already-installed broker service.
type CredentialReplacePlan struct {
	Provider      string
	User          string
	Group         string
	ConfigDir     string
	Files         []ManagedFile
	SystemdUnit   string
	LaunchdLabel  string
	ReadyCheck    ReadinessCheck
	ReadyTimeout  time.Duration
	ReadyInterval time.Duration
	Runner        CommandRunner
	AllowNonRoot  bool
	Lifecycle     *credentiallifecycle.Reporter
}

type credentialFileSnapshot struct {
	file    ManagedFile
	existed bool
	data    []byte
	mode    os.FileMode
}

// ReplaceCredential transactionally replaces managed credential files and
// proves that the existing broker service restarted successfully.
func ReplaceCredential(ctx context.Context, plan CredentialReplacePlan) error {
	if err := validateCredentialReplacePlan(plan); err != nil {
		return err
	}
	if os.Geteuid() != 0 && !plan.AllowNonRoot {
		return errors.New("credential replacement must run as root")
	}
	uid, gid, err := credentialOwnerIDs(plan)
	if err != nil {
		return err
	}
	root, err := openCredentialRoot(plan.ConfigDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	snapshots, err := captureCredentialFiles(root, plan.Files)
	if err != nil {
		return err
	}
	defer clearCredentialSnapshots(snapshots)
	return applyCredentialReplacement(ctx, root, snapshots, uid, gid, plan)
}

func applyCredentialReplacement(ctx context.Context, root *os.Root, snapshots []credentialFileSnapshot, uid, gid int, plan CredentialReplacePlan) error {
	runner := credentialRunner(plan.Runner)
	if err := writeCredentialFiles(root, plan.Files, uid, gid, plan.AllowNonRoot); err != nil {
		return errors.Join(err, restoreCredentialFiles(root, snapshots, uid, gid, plan.AllowNonRoot))
	}
	if err := restartCredentialService(ctx, runner, plan); err != nil {
		return rollbackCredentialReplacement(ctx, root, snapshots, uid, gid, runner, plan, err)
	}
	if err := waitForCredentialReady(ctx, plan); err != nil {
		return rollbackCredentialReplacement(ctx, root, snapshots, uid, gid, runner, plan, err)
	}
	return recordCredentialReplacement(plan, snapshots)
}

func credentialRunner(runner CommandRunner) CommandRunner {
	if runner == nil {
		return credentialCommandRunner{}
	}
	return runner
}

func validateCredentialReplacePlan(plan CredentialReplacePlan) error {
	if err := validateCredentialReplaceIdentity(plan); err != nil {
		return err
	}
	if err := validateCredentialReplaceFiles(plan.Files); err != nil {
		return err
	}
	return validateCredentialRestartIdentity(plan)
}

func validateCredentialReplaceIdentity(plan CredentialReplacePlan) error {
	if strings.TrimSpace(plan.Provider) == "" {
		return errors.New("credential provider is required")
	}
	if !filepath.IsAbs(plan.ConfigDir) || filepath.Clean(plan.ConfigDir) == string(filepath.Separator) {
		return errors.New("credential config directory must be an absolute non-root path")
	}
	if strings.TrimSpace(plan.User) == "" || strings.TrimSpace(plan.Group) == "" {
		return errors.New("credential service user and group are required")
	}
	return nil
}

func validateCredentialReplaceFiles(files []ManagedFile) error {
	if len(files) == 0 {
		return errors.New("at least one credential file is required")
	}
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		if err := validateCredentialReplaceFile(file, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateCredentialReplaceFile(file ManagedFile, seen map[string]struct{}) error {
	if file.Area != ManagedFileConfig || !validManagedFileName(file.Name) || file.CredentialClass == "" {
		return fmt.Errorf("invalid credential file %q", file.Name)
	}
	if _, exists := seen[file.Name]; exists {
		return fmt.Errorf("duplicate credential file %q", file.Name)
	}
	seen[file.Name] = struct{}{}
	if err := validateManagedFilePayload(file); err != nil {
		return err
	}
	if err := validateManagedFileOwner(file); err != nil {
		return err
	}
	return validateManagedFileMode(file, true)
}

func validateCredentialRestartIdentity(plan CredentialReplacePlan) error {
	switch runtime.GOOS {
	case "linux":
		if !validCredentialSystemdUnit(plan.SystemdUnit) {
			return errors.New("a literal systemd service unit is required")
		}
	case "darwin":
		if !validCredentialLaunchdLabel(plan.LaunchdLabel) {
			return errors.New("a literal launchd label is required")
		}
	default:
		return errors.New("credential replacement is supported only on Linux and macOS")
	}
	return nil
}

func validCredentialSystemdUnit(unit string) bool {
	return unit != "" && filepath.Base(unit) == unit && strings.HasSuffix(unit, ".service")
}

func validCredentialLaunchdLabel(label string) bool {
	return label != "" && !strings.ContainsAny(label, "/\\\r\n\t ")
}

func credentialOwnerIDs(plan CredentialReplacePlan) (int, int, error) {
	if plan.AllowNonRoot {
		return os.Geteuid(), os.Getegid(), nil
	}
	uid, err := credentialIdentityID(plan.User, "user")
	if err != nil {
		return 0, 0, err
	}
	gid, err := credentialIdentityID(plan.Group, "group")
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func credentialIdentityID(name, kind string) (int, error) {
	var id string
	var err error
	switch kind {
	case "user":
		var account *user.User
		account, err = user.Lookup(name)
		if err == nil {
			id = account.Uid
		}
	case "group":
		var group *user.Group
		group, err = user.LookupGroup(name)
		if err == nil {
			id = group.Gid
		}
	default:
		return 0, errors.New("credential service identity kind is invalid")
	}
	if err != nil {
		return 0, fmt.Errorf("credential service %s does not exist", kind)
	}
	value, err := strconv.Atoi(id)
	if err != nil {
		return 0, errors.New("credential service identity is invalid")
	}
	return value, nil
}

func openCredentialRoot(path string) (*os.Root, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("credential config directory is unavailable or unsafe")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.New("open credential config directory")
	}
	return root, nil
}

func captureCredentialFiles(root *os.Root, files []ManagedFile) ([]credentialFileSnapshot, error) {
	snapshots := make([]credentialFileSnapshot, 0, len(files))
	for _, file := range files {
		snapshot, err := captureCredentialFile(root, file)
		if err != nil {
			clearCredentialSnapshots(snapshots)
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func captureCredentialFile(root *os.Root, file ManagedFile) (credentialFileSnapshot, error) {
	snapshot := credentialFileSnapshot{file: file}
	info, err := root.Lstat(file.Name)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil || !safeCredentialFileInfo(info) {
		return credentialFileSnapshot{}, fmt.Errorf("previous credential file %q is unavailable or unsafe", file.Name)
	}
	data, err := readCredentialFile(root, file.Name)
	if err != nil {
		return credentialFileSnapshot{}, err
	}
	snapshot.existed, snapshot.data, snapshot.mode = true, data, info.Mode().Perm()
	return snapshot, nil
}

func safeCredentialFileInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Size() <= maxManagedFileBytes
}

func readCredentialFile(root *os.Root, name string) ([]byte, error) {
	handle, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open previous credential file %q", name)
	}
	data, readErr := io.ReadAll(io.LimitReader(handle, maxManagedFileBytes+1))
	closeErr := handle.Close()
	if readErr != nil || closeErr != nil || len(data) > maxManagedFileBytes {
		clear(data)
		return nil, fmt.Errorf("read previous credential file %q", name)
	}
	return data, nil
}

func writeCredentialFiles(root *os.Root, files []ManagedFile, serviceUID, serviceGID int, preview bool) error {
	for _, file := range files {
		uid := 0
		if file.Owner == ManagedFileOwnerService {
			uid = serviceUID
		}
		if preview {
			uid, serviceGID = os.Geteuid(), os.Getegid()
		}
		if err := writeCredentialFile(root, file.Name, file.Data, file.Mode, uid, serviceGID); err != nil {
			return fmt.Errorf("write credential file %q: %w", file.Name, err)
		}
	}
	return nil
}

func writeCredentialFile(root *os.Root, name string, data []byte, mode os.FileMode, uid, gid int) error {
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(suffix[:]) + ".tmp"
	handle, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeCredentialHandle(handle, data, mode, uid, gid)
	closeErr := handle.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func writeCredentialHandle(handle *os.File, data []byte, mode os.FileMode, uid, gid int) error {
	if _, err := handle.Write(data); err != nil {
		return err
	}
	if err := handle.Chown(uid, gid); err != nil {
		return err
	}
	if err := handle.Chmod(mode); err != nil {
		return err
	}
	return handle.Sync()
}

func rollbackCredentialReplacement(ctx context.Context, root *os.Root, snapshots []credentialFileSnapshot, uid, gid int,
	runner CommandRunner, plan CredentialReplacePlan, cause error) error {
	restoreErr := restoreCredentialFiles(root, snapshots, uid, gid, plan.AllowNonRoot)
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialRollbackRestartTimeout)
	defer cancel()
	restartErr := restartCredentialService(rollbackCtx, runner, plan)
	return errors.Join(cause, restoreErr, restartErr)
}

func restoreCredentialFiles(root *os.Root, snapshots []credentialFileSnapshot, uid, gid int, preview bool) error {
	var result error
	for index := len(snapshots) - 1; index >= 0; index-- {
		snapshot := snapshots[index]
		if !snapshot.existed {
			if err := root.Remove(snapshot.file.Name); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
			continue
		}
		owner := 0
		if snapshot.file.Owner == ManagedFileOwnerService {
			owner = uid
		}
		if preview {
			owner, gid = os.Geteuid(), os.Getegid()
		}
		result = errors.Join(result, writeCredentialFile(root, snapshot.file.Name, snapshot.data, snapshot.mode, owner, gid))
	}
	return result
}

func restartCredentialService(ctx context.Context, runner CommandRunner, plan CredentialReplacePlan) error {
	if plan.AllowNonRoot {
		return nil
	}
	if runtime.GOOS == "linux" {
		return runner.Run(ctx, "systemctl", "restart", plan.SystemdUnit)
	}
	return runner.Run(ctx, "launchctl", "kickstart", "-k", "system/"+plan.LaunchdLabel)
}

func waitForCredentialReady(ctx context.Context, plan CredentialReplacePlan) error {
	if plan.ReadyCheck == nil || plan.AllowNonRoot {
		return nil
	}
	return waitForReadiness(ctx, plan.ReadyCheck, plan.ReadyTimeout, plan.ReadyInterval)
}

func recordCredentialReplacement(plan CredentialReplacePlan, snapshots []credentialFileSnapshot) error {
	if plan.Lifecycle == nil {
		return nil
	}
	for index, file := range plan.Files {
		if file.CredentialClass == "" {
			continue
		}
		action := credentiallifecycle.ActionCreated
		previous := ""
		if snapshots[index].existed {
			action = credentiallifecycle.ActionRotated
			previous = credentialIdentifier(snapshots[index].data)
		}
		if err := plan.Lifecycle.Record(credentiallifecycle.Event{
			Class: file.CredentialClass, Action: action, Outcome: credentiallifecycle.OutcomeSucceeded,
			PreviousID: previous, CurrentID: credentialIdentifier(file.Data), Provider: plan.Provider,
		}); err != nil {
			return err
		}
	}
	return nil
}

func clearCredentialSnapshots(snapshots []credentialFileSnapshot) {
	for index := range snapshots {
		clear(snapshots[index].data)
	}
}

type credentialCommandRunner struct{}

func (credentialCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run() // #nosec G204 -- command and arguments are closed by the plan.
}
