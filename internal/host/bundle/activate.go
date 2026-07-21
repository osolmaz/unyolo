package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/osolmaz/brokerkit/internal/fsx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/operator/client"
	"golang.org/x/sys/unix"
)

const (
	manifestFilename   = "manifest.json"
	activationFilename = "activation.json"
	lockFilename       = "activation.lock"
	maximumArtifact    = 512 * 1024 * 1024
)

// Paths selects the host release and state roots.
type Paths struct {
	Root     string
	StateDir string
}

// DefaultPaths returns the system installation paths for the current host.
func DefaultPaths() Paths {
	if runtimeGOOS() == "darwin" {
		root := "/Library/Application Support/BrokerKit"
		return Paths{Root: root, StateDir: root}
	}
	return Paths{Root: "/opt/brokerkit", StateDir: "/var/lib/brokerkit-host"}
}

var runtimeGOOS = func() string { return runtime.GOOS }

// ServiceManager performs native lifecycle operations.
type ServiceManager interface {
	Stop(context.Context, string) error
	Start(context.Context, string) error
	Reload(context.Context) error
	Status(context.Context, string) (ServiceStatus, error)
}

// ServiceStatus is the process identity used by status and doctor.
type ServiceStatus struct {
	Active     bool   `json:"active"`
	PID        int    `json:"pid,omitempty"`
	Executable string `json:"executable,omitempty"`
}

// Installer atomically activates complete host bundles.
type Installer struct {
	Paths       Paths
	Manager     ServiceManager
	Now         func() time.Time
	Probe       func(context.Context, Component) error
	Development bool
}

// Activation records the current and rollback releases.
type Activation struct {
	APIVersion       string    `json:"api_version"`
	ActiveBundleID   string    `json:"active_bundle_id"`
	PreviousBundleID string    `json:"previous_bundle_id,omitempty"`
	ActivatedAt      time.Time `json:"activated_at"`
	RecoveryRequired bool      `json:"recovery_required"`
}

// Report is the secret-safe host status projection.
type Report struct {
	Healthy    bool              `json:"healthy"`
	Activation Activation        `json:"activation"`
	Components []ComponentReport `json:"components"`
	Problems   []string          `json:"problems,omitempty"`
}

// ComponentReport compares desired artifact and live service identity.
type ComponentReport struct {
	Name     string          `json:"name"`
	BuildID  string          `json:"build_id"`
	DigestOK bool            `json:"digest_ok"`
	Services []ServiceReport `json:"services,omitempty"`
}

type ServiceReport struct {
	Name       string `json:"name"`
	Active     bool   `json:"active"`
	PID        int    `json:"pid,omitempty"`
	Executable string `json:"executable,omitempty"`
	Expected   string `json:"expected"`
	Matches    bool   `json:"matches"`
}

// Activate stages and commits a complete release or restores the previous one.
func (i Installer) Activate(ctx context.Context, manifest Manifest, manifestData []byte, artifacts string) error {
	if err := i.normalize(); err != nil {
		return err
	}
	if err := manifest.Validate(i.Development); err != nil {
		return err
	}
	var storedManifest Manifest
	if err := strictjson.Decode(manifestData, &storedManifest, true); err != nil || !reflect.DeepEqual(storedManifest, manifest) {
		return errors.New("runtime bundle manifest bytes do not match the validated manifest")
	}
	lock, err := acquireLock(i.Paths.StateDir)
	if err != nil {
		return err
	}
	defer lock.close()
	release, err := i.stage(manifest, manifestData, artifacts)
	if err != nil {
		return err
	}
	previous, previousManifest, err := i.currentManifest()
	if err != nil {
		return err
	}
	if previous == manifest.BundleID {
		return i.verifyRelease(manifest, release)
	}
	if err := i.stop(ctx, previousManifest); err != nil {
		return err
	}
	if err := i.prepareState(previousManifest, manifest); err != nil {
		return errors.Join(err, i.start(ctx, previousManifest))
	}
	if err := i.switchCurrent(manifest.BundleID); err != nil {
		return errors.Join(err, i.restoreState(previousManifest, manifest), i.start(ctx, previousManifest))
	}
	activationErr := errors.Join(i.Manager.Reload(ctx), i.start(ctx, manifest))
	if activationErr == nil {
		activationErr = i.verifyRuntime(ctx, manifest)
	}
	if activationErr != nil {
		rollbackErr := i.restore(previous, previousManifest, manifest)
		if rollbackErr != nil {
			active, _, currentErr := i.currentManifest()
			if active == "" {
				active = manifest.BundleID
			}
			record := Activation{APIVersion: APIVersion, ActiveBundleID: active,
				PreviousBundleID: previous, ActivatedAt: i.Now().UTC(), RecoveryRequired: true}
			recordErr := writeJSONAtomic(filepath.Join(i.Paths.StateDir, activationFilename), record, 0o600)
			return errors.Join(activationErr, rollbackErr, currentErr, recordErr)
		}
		return activationErr
	}
	record := Activation{APIVersion: APIVersion, ActiveBundleID: manifest.BundleID, PreviousBundleID: previous, ActivatedAt: i.Now().UTC()}
	return writeJSONAtomic(filepath.Join(i.Paths.StateDir, activationFilename), record, 0o600)
}

// Rollback restores the previous complete bundle recorded by Activate.
func (i Installer) Rollback(ctx context.Context) error {
	if err := i.normalize(); err != nil {
		return err
	}
	lock, err := acquireLock(i.Paths.StateDir)
	if err != nil {
		return err
	}
	defer lock.close()
	record, err := i.readActivation()
	if err != nil {
		return err
	}
	if record.PreviousBundleID == "" {
		return errors.New("no previous BrokerKit bundle is available")
	}
	activeManifest, err := i.manifest(record.ActiveBundleID)
	if err != nil {
		return err
	}
	previousManifest, err := i.manifest(record.PreviousBundleID)
	if err != nil {
		return err
	}
	if err := i.restore(record.PreviousBundleID, previousManifest, activeManifest); err != nil {
		record.RecoveryRequired = true
		_ = writeJSONAtomic(filepath.Join(i.Paths.StateDir, activationFilename), record, 0o600)
		return err
	}
	next := Activation{APIVersion: APIVersion, ActiveBundleID: record.PreviousBundleID,
		PreviousBundleID: record.ActiveBundleID, ActivatedAt: i.Now().UTC()}
	return writeJSONAtomic(filepath.Join(i.Paths.StateDir, activationFilename), next, 0o600)
}

// Status verifies the active immutable release and every managed service.
func (i Installer) Status(ctx context.Context) (Report, error) {
	if err := i.normalize(); err != nil {
		return Report{}, err
	}
	record, err := i.readActivation()
	if err != nil {
		return Report{}, err
	}
	manifest, err := i.manifest(record.ActiveBundleID)
	if err != nil {
		return Report{}, err
	}
	report := Report{Healthy: !record.RecoveryRequired, Activation: record}
	release := filepath.Join(i.Paths.Root, "releases", manifest.BundleID)
	for _, component := range manifest.Components {
		actual, digestErr := digestFile(filepath.Join(release, component.Destination))
		item := ComponentReport{Name: component.Name, BuildID: component.BuildID, DigestOK: digestErr == nil && actual == component.SHA256}
		if !item.DigestOK {
			report.Healthy = false
			report.Problems = append(report.Problems, component.Name+": artifact digest mismatch")
		}
		for _, service := range component.Services {
			status, statusErr := i.Manager.Status(ctx, service)
			expected := filepath.Join(release, component.Destination)
			matches := statusErr == nil && status.Active && processPathMatches(status.Executable, expected)
			item.Services = append(item.Services, ServiceReport{Name: service, Active: status.Active, PID: status.PID,
				Executable: status.Executable, Expected: expected, Matches: matches})
			if !matches {
				report.Healthy = false
				report.Problems = append(report.Problems, service+": running executable does not match active bundle")
			}
		}
		if probeErr := i.Probe(ctx, component); probeErr != nil {
			report.Healthy = false
			report.Problems = append(report.Problems, component.Name+": readiness check failed")
		}
		report.Components = append(report.Components, item)
	}
	return report, nil
}

func (i *Installer) normalize() error {
	if i.Paths.Root == "" || i.Paths.StateDir == "" || !filepath.IsAbs(i.Paths.Root) || !filepath.IsAbs(i.Paths.StateDir) {
		return errors.New("bundle root and state directory must be absolute")
	}
	if i.Manager == nil {
		return errors.New("native service manager is required")
	}
	if i.Now == nil {
		i.Now = time.Now
	}
	if i.Probe == nil {
		i.Probe = operatorProbe
	}
	return nil
}

func operatorProbe(ctx context.Context, component Component) error {
	if component.OperatorEndpoint == "" {
		return nil
	}
	token, err := readOperatorToken(component.OperatorTokenFile)
	if err != nil {
		return err
	}
	client, err := operatorclient.New(component.OperatorEndpoint, token, nil)
	if err != nil {
		return err
	}
	descriptor, err := client.Discover(ctx)
	if err != nil {
		return err
	}
	if descriptor.BuildID != component.BuildID {
		return errors.New("operator build identity does not match runtime bundle")
	}
	return client.Health(ctx)
}

func readOperatorToken(path string) (string, error) {
	data, err := readBounded(path, 64*1024)
	if err != nil {
		return "", fmt.Errorf("read operator token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("operator token is empty")
	}
	return token, nil
}

func (i Installer) stage(manifest Manifest, data []byte, artifacts string) (string, error) {
	if !filepath.IsAbs(artifacts) {
		return "", errors.New("artifact directory must be absolute")
	}
	releases := filepath.Join(i.Paths.Root, "releases")
	if err := os.MkdirAll(releases, 0o755); err != nil {
		return "", err
	}
	release := filepath.Join(releases, manifest.BundleID)
	if _, err := os.Stat(release); err == nil {
		stored, readErr := os.ReadFile(filepath.Join(release, manifestFilename)) // #nosec G304 -- immutable release path.
		if readErr != nil || !bytes.Equal(stored, data) {
			return "", errors.New("bundle identity already exists with different manifest content")
		}
		return release, i.verifyRelease(manifest, release)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	temporary, err := os.MkdirTemp(releases, ".stage-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	for _, component := range manifest.Components {
		if err := copyArtifact(artifacts, temporary, component); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(temporary, manifestFilename), data, 0o444); err != nil {
		return "", err
	}
	if err := syncTree(temporary); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, release); err != nil {
		return "", err
	}
	if err := syncDirectory(releases); err != nil {
		return "", err
	}
	return release, nil
}

func copyArtifact(artifacts, release string, component Component) error {
	source := filepath.Join(artifacts, component.Source)
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximumArtifact {
		return fmt.Errorf("component %s source is not a bounded regular file", component.Name)
	}
	actual, err := digestFile(source)
	if err != nil || actual != component.SHA256 {
		return fmt.Errorf("component %s artifact digest mismatch", component.Name)
	}
	destination := filepath.Join(release, component.Destination)
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source) // #nosec G304 -- validated source beneath explicit artifact root.
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o555) // #nosec G304 -- validated release destination.
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(in, maximumArtifact+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	return errors.Join(copyErr, syncErr, closeErr)
}

func (i Installer) verifyRelease(manifest Manifest, release string) error {
	for _, component := range manifest.Components {
		digest, err := digestFile(filepath.Join(release, component.Destination))
		if err != nil || digest != component.SHA256 {
			return fmt.Errorf("component %s active artifact is invalid", component.Name)
		}
	}
	return nil
}

func (i Installer) switchCurrent(bundleID string) error {
	if err := os.MkdirAll(i.Paths.Root, 0o755); err != nil {
		return err
	}
	temporary := filepath.Join(i.Paths.Root, ".current-next")
	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.Join("releases", bundleID), temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(i.Paths.Root, "current")); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(i.Paths.Root)
}

func (i Installer) restore(previous string, oldManifest, candidate Manifest) error {
	recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stopErr := i.stop(recoveryCtx, candidate)
	stateErr := i.restoreState(oldManifest, candidate)
	var switchErr error
	if previous == "" {
		switchErr = os.Remove(filepath.Join(i.Paths.Root, "current"))
		if errors.Is(switchErr, os.ErrNotExist) {
			switchErr = nil
		}
	} else {
		switchErr = i.switchCurrent(previous)
	}
	reloadErr := i.Manager.Reload(recoveryCtx)
	startErr := i.start(recoveryCtx, oldManifest)
	verifyErr := i.verifyRuntime(recoveryCtx, oldManifest)
	return errors.Join(stopErr, stateErr, switchErr, reloadErr, startErr, verifyErr)
}

func (i Installer) prepareState(previous, candidate Manifest) error {
	old := componentsByName(previous.Components)
	var prepared []Component
	for _, component := range candidate.Components {
		prior, exists := old[component.Name]
		if !exists || prior.StateFormatDigest == component.StateFormatDigest {
			continue
		}
		if !component.ReplaceState || component.StateDir == "" {
			_ = i.undoPreparedState(candidate.BundleID, prepared)
			return fmt.Errorf("component %s changes state format without explicit replacement", component.Name)
		}
		if err := replaceStateDirectory(component.StateDir, stateBackupPath(component.StateDir, candidate.BundleID)); err != nil {
			_ = i.undoPreparedState(candidate.BundleID, prepared)
			return err
		}
		prepared = append(prepared, component)
	}
	return nil
}

func (i Installer) undoPreparedState(bundleID string, components []Component) error {
	var result error
	for index := len(components) - 1; index >= 0; index-- {
		component := components[index]
		result = errors.Join(result, restoreStateDirectory(component.StateDir, stateBackupPath(component.StateDir, bundleID)))
	}
	return result
}

func (i Installer) restoreState(previous, candidate Manifest) error {
	old := componentsByName(previous.Components)
	var changed []Component
	for _, component := range candidate.Components {
		prior, exists := old[component.Name]
		if exists && prior.StateFormatDigest != component.StateFormatDigest && component.ReplaceState {
			changed = append(changed, component)
		}
	}
	return i.undoPreparedState(candidate.BundleID, changed)
}

func componentsByName(components []Component) map[string]Component {
	result := map[string]Component{}
	for _, component := range components {
		result[component.Name] = component
	}
	return result
}

func stateBackupPath(stateDir, bundleID string) string {
	return stateDir + ".brokerkit-backup-" + bundleID
}

func replaceStateDirectory(stateDir, backup string) error {
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		return errors.New("state replacement backup already exists or cannot be inspected")
	}
	info, err := os.Stat(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(stateDir, 0o700)
	}
	if err != nil || !info.IsDir() {
		return errors.New("state replacement source is not a directory")
	}
	if err := os.Rename(stateDir, backup); err != nil {
		return fmt.Errorf("archive previous state: %w", err)
	}
	if err := os.Mkdir(stateDir, info.Mode().Perm()); err != nil {
		_ = os.Rename(backup, stateDir)
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := os.Chown(stateDir, int(stat.Uid), int(stat.Gid)); err != nil {
			_ = os.Remove(stateDir)
			_ = os.Rename(backup, stateDir)
			return err
		}
	}
	return syncDirectory(filepath.Dir(stateDir))
}

func restoreStateDirectory(stateDir, backup string) error {
	if _, err := os.Lstat(backup); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	retired := stateDir + ".brokerkit-retired"
	_ = os.RemoveAll(retired)
	if err := os.Rename(stateDir, retired); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(backup, stateDir); err != nil {
		_ = os.Rename(retired, stateDir)
		return err
	}
	return os.RemoveAll(retired)
}

func (i Installer) stop(ctx context.Context, manifest Manifest) error {
	var result error
	for _, service := range orderedServices(manifest, true) {
		result = errors.Join(result, i.Manager.Stop(ctx, service))
	}
	return result
}

func (i Installer) start(ctx context.Context, manifest Manifest) error {
	for _, service := range orderedServices(manifest, false) {
		if err := i.Manager.Start(ctx, service); err != nil {
			return err
		}
	}
	return nil
}

func (i Installer) verifyRuntime(ctx context.Context, manifest Manifest) error {
	release := filepath.Join(i.Paths.Root, "releases", manifest.BundleID)
	for _, component := range manifest.Components {
		for _, service := range component.Services {
			status, err := i.Manager.Status(ctx, service)
			if err != nil || !status.Active {
				return fmt.Errorf("service %s is not active", service)
			}
			expected := filepath.Join(release, component.Destination)
			if !processPathMatches(status.Executable, expected) {
				return fmt.Errorf("service %s executable does not match candidate bundle", service)
			}
		}
		if err := i.Probe(ctx, component); err != nil {
			return fmt.Errorf("component %s is not ready: %w", component.Name, err)
		}
	}
	return nil
}

func orderedServices(manifest Manifest, stopping bool) []string {
	roleOrder := map[Role]int{RoleProvider: 0, RoleConsumer: 1, RoleCompanion: 2}
	if stopping {
		roleOrder = map[Role]int{RoleConsumer: 0, RoleProvider: 1, RoleCompanion: 2}
	}
	type item struct {
		role Role
		name string
	}
	var values []item
	for _, component := range manifest.Components {
		for _, service := range component.Services {
			values = append(values, item{component.Role, service})
		}
	}
	sort.Slice(values, func(a, b int) bool {
		if roleOrder[values[a].role] == roleOrder[values[b].role] {
			return values[a].name < values[b].name
		}
		return roleOrder[values[a].role] < roleOrder[values[b].role]
	})
	result := make([]string, len(values))
	for index := range values {
		result[index] = values[index].name
	}
	return result
}

func (i Installer) currentManifest() (string, Manifest, error) {
	target, err := os.Readlink(filepath.Join(i.Paths.Root, "current"))
	if errors.Is(err, os.ErrNotExist) {
		return "", Manifest{}, nil
	}
	if err != nil {
		return "", Manifest{}, err
	}
	bundleID := filepath.Base(filepath.Clean(target))
	manifest, err := i.manifest(bundleID)
	return bundleID, manifest, err
}

func (i Installer) manifest(bundleID string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Join(i.Paths.Root, "releases", bundleID, manifestFilename)) // #nosec G304 -- validated stored bundle identity.
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := strictjson.Decode(data, &manifest, true); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
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

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".write-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	_, writeErr := temporary.Write(data)
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		file, err := os.Open(path) // #nosec G304 -- path is beneath private staging root.
		if err != nil {
			return err
		}
		return errors.Join(file.Sync(), file.Close())
	})
}

func syncDirectory(path string) error { return fsx.SyncDirectory(path) }

func processPathMatches(actual, expected string) bool {
	if strings.HasSuffix(actual, " (deleted)") || actual == "" {
		return false
	}
	actualPath, actualErr := filepath.EvalSymlinks(actual)
	expectedPath, expectedErr := filepath.EvalSymlinks(expected)
	return actualErr == nil && expectedErr == nil && actualPath == expectedPath
}

type activationLock struct{ file *os.File }

func acquireLock(stateDir string) (*activationLock, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(stateDir, lockFilename), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- fixed host state path.
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another BrokerKit activation is running")
	}
	return &activationLock{file: file}, nil
}

func (l *activationLock) close() {
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	_ = l.file.Close()
}
