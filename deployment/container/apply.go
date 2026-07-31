package container

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OverrideFilename is the fixed filename for the generated override.
const OverrideFilename = "unyolo-compose-override.yml"

// InvitationFilename is the fixed filename for the pending invitation.
const InvitationFilename = "unyolo-pending-invitation"

// AgentApplyInputs is the closed input to the two-phase Compose agent apply.
type AgentApplyInputs struct {
	Runner       Runner
	Options      ProjectOptions
	Override     *AgentOverride
	Invitation   []byte
	SecretMode   os.FileMode
	OverrideMode os.FileMode
}

// AgentApplyResult holds the exact resources the transaction created so the
// caller can safely reverse them.
type AgentApplyResult struct {
	OverridePath      string
	InvitationPath    string
	OverrideRestored  bool
	InvitationCleared bool
	ProjectName       string
	AgentService      string
}

// PlanAgentApply writes the override and pending invitation atomically. It
// does NOT start the compose services; the caller runs `docker compose up`
// after the pairing service has recorded the pending connection so we can
// roll back cleanly if activation is cancelled.
func PlanAgentApply(inputs AgentApplyInputs) (AgentApplyResult, func() error, error) {
	if err := validateApplyInputs(inputs); err != nil {
		return AgentApplyResult{}, nil, err
	}
	directory := inputs.Options.Directory
	overridePath := filepath.Join(directory, OverrideFilename)
	invitationPath := filepath.Join(directory, InvitationFilename)
	rendered, err := inputs.Override.Render()
	if err != nil {
		return AgentApplyResult{}, nil, err
	}
	previousOverride, hadOverride, err := readExisting(overridePath)
	if err != nil {
		return AgentApplyResult{}, nil, err
	}
	previousInvitation, hadInvitation, err := readExisting(invitationPath)
	if err != nil {
		return AgentApplyResult{}, nil, err
	}
	overrideMode := inputs.OverrideMode
	if overrideMode == 0 {
		overrideMode = 0o600
	}
	secretMode := inputs.SecretMode
	if secretMode == 0 {
		secretMode = 0o600
	}
	if err := writeAtomic(overridePath, rendered, overrideMode); err != nil {
		return AgentApplyResult{}, nil, err
	}
	if err := writeAtomic(invitationPath, inputs.Invitation, secretMode); err != nil {
		_ = restoreExisting(overridePath, previousOverride, hadOverride, overrideMode)
		return AgentApplyResult{}, nil, err
	}
	rollback := func() error {
		var failures []error
		if err := restoreExisting(overridePath, previousOverride, hadOverride, overrideMode); err != nil {
			failures = append(failures, err)
		}
		if err := restoreExisting(invitationPath, previousInvitation, hadInvitation, secretMode); err != nil {
			failures = append(failures, err)
		}
		return errors.Join(failures...)
	}
	return AgentApplyResult{
		OverridePath: overridePath, InvitationPath: invitationPath,
		ProjectName: inputs.Options.ProjectName, AgentService: inputs.Override.AgentService,
	}, rollback, nil
}

// StartInit runs `docker compose up` on the init service and waits for it to
// finish successfully. The agent service is not recreated by this call.
func StartInit(ctx context.Context, runner Runner, options ProjectOptions, overridePath string) error {
	if runner == nil {
		runner = CLIRunner{}
	}
	if err := options.Validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(overridePath) || filepath.Clean(overridePath) != overridePath {
		return errors.New("override path must be absolute and clean")
	}
	arguments := composeArguments(options, overridePath)
	arguments = append(arguments, "up", "--no-deps", "--exit-code-from", InitServiceName, "--abort-on-container-exit", InitServiceName)
	_, stderr, err := runner.Run(ctx, options.Directory, arguments...)
	if err != nil {
		return fmt.Errorf("docker compose up %s: %w: %s", InitServiceName, err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

// RecreateAgent restarts only the reviewed agent service so it picks up the
// initialized client configuration. Other services in the project are not
// touched.
func RecreateAgent(ctx context.Context, runner Runner, options ProjectOptions, overridePath, agentService string) error {
	if runner == nil {
		runner = CLIRunner{}
	}
	if err := options.Validate(); err != nil {
		return err
	}
	if !composeServiceNamePattern.MatchString(agentService) {
		return errors.New("agent service name is invalid")
	}
	if !filepath.IsAbs(overridePath) || filepath.Clean(overridePath) != overridePath {
		return errors.New("override path must be absolute and clean")
	}
	arguments := composeArguments(options, overridePath)
	arguments = append(arguments, "up", "-d", "--no-deps", "--force-recreate", agentService)
	_, stderr, err := runner.Run(ctx, options.Directory, arguments...)
	if err != nil {
		return fmt.Errorf("docker compose up %s: %w: %s", agentService, err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

// StopInit removes only the init container after the agent has been recreated.
// Failure is logged by the caller and does not affect readiness.
func StopInit(ctx context.Context, runner Runner, options ProjectOptions, overridePath string) error {
	if runner == nil {
		runner = CLIRunner{}
	}
	if err := options.Validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(overridePath) || filepath.Clean(overridePath) != overridePath {
		return errors.New("override path must be absolute and clean")
	}
	arguments := composeArguments(options, overridePath)
	arguments = append(arguments, "rm", "-fsv", InitServiceName)
	_, stderr, err := runner.Run(ctx, options.Directory, arguments...)
	if err != nil {
		return fmt.Errorf("docker compose rm %s: %w: %s", InitServiceName, err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

func composeArguments(options ProjectOptions, overridePath string) []string {
	arguments := []string{"compose"}
	if options.ProjectName != "" {
		arguments = append(arguments, "-p", options.ProjectName)
	}
	arguments = append(arguments, "-f", filepath.Join(options.Directory, "compose.yaml"), "-f", overridePath)
	return arguments
}

func validateApplyInputs(inputs AgentApplyInputs) error {
	if err := inputs.Options.Validate(); err != nil {
		return err
	}
	if inputs.Override == nil {
		return errors.New("override is required")
	}
	if inputs.Override.APIVersion != OverrideAPIVersion {
		return errors.New("override API version is invalid")
	}
	if len(inputs.Invitation) == 0 {
		return errors.New("invitation is required")
	}
	return nil
}

func readExisting(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- validated caller path.
	if err == nil {
		return data, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, err
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".unyolo-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

func restoreExisting(path string, previous []byte, existed bool, mode os.FileMode) error {
	if existed {
		return writeAtomic(path, previous, mode)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
