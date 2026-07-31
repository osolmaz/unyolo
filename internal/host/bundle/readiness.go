package bundle

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/internal/config/secretfile"
	"github.com/osolmaz/unyolo/operator/client"
)

func (i *Installer) normalize() error {
	if err := validateInstallerDependencies(i.Paths, i.Manager); err != nil {
		return err
	}
	i.applyReadinessDefaults()
	return nil
}

func validateInstallerDependencies(paths Paths, manager ServiceManager) error {
	if !absolutePath(paths.Root) || !absolutePath(paths.StateDir) {
		return errors.New("bundle root and state directory must be absolute")
	}
	if manager == nil {
		return errors.New("native service manager is required")
	}
	return nil
}

func absolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path)
}

func (i *Installer) applyReadinessDefaults() {
	if i.Now == nil {
		i.Now = time.Now
	}
	if i.Probe == nil {
		i.Probe = operatorProbe
	}
	if i.ReadyTimeout <= 0 {
		i.ReadyTimeout = 15 * time.Second
	}
	if i.ReadyInterval <= 0 {
		i.ReadyInterval = 100 * time.Millisecond
	}
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
	values, err := secretfile.ParseBytes(data)
	clear(data)
	if err != nil || len(values) == 0 {
		return "", errors.New("operator credential store is invalid or empty")
	}
	identities := make([]string, 0, len(values))
	for identity := range values {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	return strings.TrimSpace(values[identities[0]]), nil
}

func (i Installer) startAndVerify(ctx context.Context, manifest Manifest) error {
	for _, role := range []Role{RoleProvider, RoleConsumer, RoleCompanion} {
		if err := i.startRole(ctx, manifest, role); err != nil {
			return err
		}
		if err := i.waitForRole(ctx, manifest, role); err != nil {
			return err
		}
	}
	return nil
}

func (i Installer) startRole(ctx context.Context, manifest Manifest, role Role) error {
	var services []string
	for _, component := range manifest.Components {
		if component.Role == role {
			services = append(services, component.Services...)
		}
	}
	sort.Strings(services)
	for _, service := range services {
		if err := i.Manager.Start(ctx, service); err != nil {
			return err
		}
	}
	return nil
}

func (i Installer) waitForRole(ctx context.Context, manifest Manifest, role Role) error {
	readyCtx, cancel := context.WithTimeout(ctx, i.ReadyTimeout)
	defer cancel()
	var lastErr error
	for {
		lastErr = i.verifyRoleRuntime(readyCtx, manifest, role)
		if lastErr == nil {
			return nil
		}
		timer := time.NewTimer(i.ReadyInterval)
		select {
		case <-readyCtx.Done():
			timer.Stop()
			return errors.Join(lastErr, readyCtx.Err())
		case <-timer.C:
		}
	}
}

func (i Installer) verifyRuntime(ctx context.Context, manifest Manifest) error {
	for _, role := range []Role{RoleProvider, RoleConsumer, RoleCompanion} {
		if err := i.verifyRoleRuntime(ctx, manifest, role); err != nil {
			return err
		}
	}
	return nil
}

func (i Installer) verifyRoleRuntime(ctx context.Context, manifest Manifest, role Role) error {
	release := filepath.Join(i.Paths.Root, "releases", manifest.BundleID)
	for _, component := range manifest.Components {
		if component.Role != role {
			continue
		}
		if err := i.verifyComponentRuntime(ctx, release, component); err != nil {
			return err
		}
	}
	return nil
}

func (i Installer) verifyComponentRuntime(ctx context.Context, release string, component Component) error {
	for _, service := range component.Services {
		status, err := i.Manager.Status(ctx, service)
		if err != nil || !status.Active {
			return fmt.Errorf("service %s is not active", service)
		}
		if strings.HasSuffix(service, ".socket") {
			continue
		}
		expected := filepath.Join(release, component.Destination)
		if !processPathMatches(status.Executable, expected) {
			return fmt.Errorf("service %s executable does not match candidate bundle", service)
		}
	}
	if err := i.Probe(ctx, component); err != nil {
		return fmt.Errorf("component %s is not ready: %w", component.Name, err)
	}
	return nil
}
