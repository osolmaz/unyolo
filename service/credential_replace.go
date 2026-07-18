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

	"github.com/osolmaz/brokerkit/credentiallifecycle"
)

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
	defer root.Close()
	snapshots, err := captureCredentialFiles(root, plan.Files)
	if err != nil {
		return err
	}
	defer clearCredentialSnapshots(snapshots)
	runner := plan.Runner
	if runner == nil {
		runner = credentialCommandRunner{}
	}
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

func validateCredentialReplacePlan(plan CredentialReplacePlan) error {
	if strings.TrimSpace(plan.Provider) == "" {
		return errors.New("credential provider is required")
	}
	if !filepath.IsAbs(plan.ConfigDir) || filepath.Clean(plan.ConfigDir) == string(filepath.Separator) {
		return errors.New("credential config directory must be an absolute non-root path")
	}
	if strings.TrimSpace(plan.User) == "" || strings.TrimSpace(plan.Group) == "" {
		return errors.New("credential service user and group are required")
	}
	if len(plan.Files) == 0 {
		return errors.New("at least one credential file is required")
	}
	seen := make(map[string]struct{}, len(plan.Files))
	for _, file := range plan.Files {
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
		if err := validateManagedFileMode(file, true); err != nil {
			return err
		}
	}
	switch runtime.GOOS {
	case "linux":
		if plan.SystemdUnit == "" || filepath.Base(plan.SystemdUnit) != plan.SystemdUnit || !strings.HasSuffix(plan.SystemdUnit, ".service") {
			return errors.New("a literal systemd service unit is required")
		}
	case "darwin":
		if plan.LaunchdLabel == "" || strings.ContainsAny(plan.LaunchdLabel, "/\\\r\n\t ") {
			return errors.New("a literal launchd label is required")
		}
	default:
		return errors.New("credential replacement is supported only on Linux and macOS")
	}
	return nil
}

func credentialOwnerIDs(plan CredentialReplacePlan) (int, int, error) {
	if plan.AllowNonRoot {
		return os.Geteuid(), os.Getegid(), nil
	}
	account, err := user.Lookup(plan.User)
	if err != nil {
		return 0, 0, errors.New("credential service user does not exist")
	}
	group, err := user.LookupGroup(plan.Group)
	if err != nil {
		return 0, 0, errors.New("credential service group does not exist")
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(group.Gid)
	if uidErr != nil || gidErr != nil {
		return 0, 0, errors.New("credential service identity is invalid")
	}
	return uid, gid, nil
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
		snapshot := credentialFileSnapshot{file: file}
		info, err := root.Lstat(file.Name)
		if errors.Is(err, os.ErrNotExist) {
			snapshots = append(snapshots, snapshot)
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxManagedFileBytes {
			clearCredentialSnapshots(snapshots)
			return nil, fmt.Errorf("previous credential file %q is unavailable or unsafe", file.Name)
		}
		handle, err := root.Open(file.Name)
		if err != nil {
			clearCredentialSnapshots(snapshots)
			return nil, fmt.Errorf("open previous credential file %q", file.Name)
		}
		data, readErr := io.ReadAll(io.LimitReader(handle, maxManagedFileBytes+1))
		closeErr := handle.Close()
		if readErr != nil || closeErr != nil || len(data) > maxManagedFileBytes {
			clear(data)
			clearCredentialSnapshots(snapshots)
			return nil, fmt.Errorf("read previous credential file %q", file.Name)
		}
		snapshot.existed, snapshot.data, snapshot.mode = true, data, info.Mode().Perm()
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
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
	restartErr := restartCredentialService(ctx, runner, plan)
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
	readyContext, cancel := context.WithTimeout(ctx, durationOr(plan.ReadyTimeout, defaultReadinessTimeout))
	defer cancel()
	ticker := time.NewTicker(durationOr(plan.ReadyInterval, defaultReadinessInterval))
	defer ticker.Stop()
	for {
		if err := plan.ReadyCheck(readyContext); err == nil && readyContext.Err() == nil {
			return nil
		}
		select {
		case <-readyContext.Done():
			return errServiceReadinessFailed
		case <-ticker.C:
		}
	}
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
