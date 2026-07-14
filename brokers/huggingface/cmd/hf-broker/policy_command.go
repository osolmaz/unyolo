package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policypreset"
)

const policyUsage = `usage:
  hf-broker policy render --output <scope.json> --profile-out <profile.json> --manifest-out <manifest.json> [flags]
  hf-broker policy check --file <scope.json>`

func runPolicy(_ context.Context, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return exitError{code: 64, message: policyUsage}
	}
	switch args[0] {
	case "render":
		return runPolicyRender(stdout, stderr, args[1:])
	case "check":
		return runPolicyCheck(stdout, stderr, args[1:])
	default:
		return exitError{code: 64, message: policyUsage}
	}
}

func runPolicyRender(stdout, stderr io.Writer, args []string) error {
	command, err := parsePolicyRender(stderr, args)
	if err != nil {
		return err
	}
	artifacts, err := policypreset.Render(policypreset.Profile{
		Version: policypreset.ProfileVersion, Preset: command.preset,
		Clients: command.clients, DeniedOperations: command.deniedOperations,
	})
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	outputs := policyArtifactOutputs(command, artifacts)
	if err := writePolicyArtifactOutputs(outputs, command.replace); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Rendered %s for %d operation(s).\nPolicy: %s\nProfile: %s\nManifest: %s\n", artifacts.Profile.Preset, artifacts.Manifest.OperationCounts.Total, command.policyOutput, command.profileOutput, command.manifestOutput)
	return err
}

type policyRenderCommand struct {
	preset           string
	clients          stringListFlag
	deniedOperations stringListFlag
	policyOutput     string
	profileOutput    string
	manifestOutput   string
	replace          bool
}

func parsePolicyRender(stderr io.Writer, args []string) (policyRenderCommand, error) {
	var command policyRenderCommand
	var clients stringListFlag
	var denied stringListFlag
	var flagOutput bytes.Buffer
	fs := flag.NewFlagSet("hf-broker policy render", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	fs.StringVar(&command.preset, "preset", policypreset.RequestAllAgentOperations, "Hugging Face policy preset")
	fs.Var(&clients, "client", "client identity; repeatable")
	fs.Var(&denied, "deny-operation", "exact operation to deny; repeatable")
	fs.StringVar(&command.policyOutput, "output", "", "scope policy output path")
	fs.StringVar(&command.profileOutput, "profile-out", "", "policy profile output path")
	fs.StringVar(&command.manifestOutput, "manifest-out", "", "policy manifest output path")
	fs.BoolVar(&command.replace, "replace", false, "replace existing output files")
	if err := fs.Parse(args); err != nil {
		return policyRenderCommand{}, policyFlagError(stderr, &flagOutput, err)
	}
	if err := validatePolicyRenderCommand(fs, command); err != nil {
		return policyRenderCommand{}, err
	}
	command.clients = defaultPolicyClients(clients)
	command.deniedOperations = denied
	return command, nil
}

func validatePolicyRenderCommand(fs *flag.FlagSet, command policyRenderCommand) error {
	if policyRenderOutputsMissing(fs, command) {
		return exitError{code: 64, message: "policy render requires --output, --profile-out, and --manifest-out"}
	}
	overlap, err := policyRenderOutputsOverlap(command)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	if overlap {
		return exitError{code: 64, message: "policy render output paths must be distinct"}
	}
	return nil
}

func policyRenderOutputsMissing(fs *flag.FlagSet, command policyRenderCommand) bool {
	return fs.NArg() != 0 || command.policyOutput == "" || command.profileOutput == "" || command.manifestOutput == ""
}

func policyRenderOutputsOverlap(command policyRenderCommand) (bool, error) {
	seen := make(map[string]bool, 3)
	for _, path := range []string{command.policyOutput, command.profileOutput, command.manifestOutput} {
		identity, err := canonicalOutputPath(path)
		if err != nil {
			return false, fmt.Errorf("resolve policy output path %s: %w", path, err)
		}
		if seen[identity] {
			return true, nil
		}
		seen[identity] = true
	}
	return false, nil
}

func canonicalOutputPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return resolveExistingPathPrefix(filepath.Clean(absolute))
}

func resolveExistingPathPrefix(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, nil
	}
	resolvedParent, err := resolveExistingPathPrefix(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(path)), nil
}

func defaultPolicyClients(clients stringListFlag) stringListFlag {
	if len(clients) == 0 {
		return []string{"agent"}
	}
	return clients
}

type policyArtifactOutput struct {
	path string
	data []byte
}

func policyArtifactOutputs(command policyRenderCommand, artifacts policypreset.Artifacts) []policyArtifactOutput {
	return []policyArtifactOutput{
		{command.profileOutput, artifacts.ProfileJSON},
		{command.manifestOutput, artifacts.ManifestJSON},
		{command.policyOutput, artifacts.PolicyJSON},
	}
}

func writePolicyArtifactOutputs(outputs []policyArtifactOutput, replace bool) error {
	staged, err := stagePolicyArtifactOutputs(outputs)
	if err != nil {
		return err
	}
	defer cleanupPolicyArtifactTransaction(staged)
	err = commitPolicyArtifactOutputs(staged, replace)
	if err != nil {
		return policyArtifactTransactionError(staged, err)
	}
	if err := syncPolicyArtifactDirectories(staged); err != nil {
		return policyArtifactTransactionError(staged, err)
	}
	removePolicyArtifactBackups(staged)
	return nil
}

func commitPolicyArtifactOutputs(staged []*stagedPolicyArtifact, replace bool) error {
	if replace {
		return replacePolicyArtifactOutputs(staged)
	}
	return createPolicyArtifactOutputs(staged)
}

func policyArtifactTransactionError(staged []*stagedPolicyArtifact, commitErr error) error {
	return errors.Join(commitErr, rollbackPolicyArtifactOutputs(staged))
}

type stagedPolicyArtifact struct {
	output    policyArtifactOutput
	temporary string
	backup    string
	info      os.FileInfo
	committed bool
}

func stagePolicyArtifactOutputs(outputs []policyArtifactOutput) ([]*stagedPolicyArtifact, error) {
	staged := make([]*stagedPolicyArtifact, 0, len(outputs))
	for _, output := range outputs {
		artifact, err := stagePolicyArtifact(output)
		if err != nil {
			cleanupPolicyArtifactTransaction(staged)
			return nil, err
		}
		staged = append(staged, artifact)
	}
	return staged, nil
}

func stagePolicyArtifact(output policyArtifactOutput) (*stagedPolicyArtifact, error) {
	directory := filepath.Dir(output.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create policy output directory %s: %w", directory, err)
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(output.path)+".*.stage")
	if err != nil {
		return nil, fmt.Errorf("stage policy output %s: %w", output.path, err)
	}
	temporary := file.Name()
	if err := writeStagedPolicyArtifact(file, output); err != nil {
		_ = os.Remove(temporary)
		return nil, err
	}
	info, err := os.Stat(temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return nil, fmt.Errorf("inspect staged policy output %s: %w", output.path, err)
	}
	return &stagedPolicyArtifact{output: output, temporary: temporary, info: info}, nil
}

func writeStagedPolicyArtifact(file *os.File, output policyArtifactOutput) error {
	steps := []func() error{
		func() error { return stagedPolicyChmod(file, output.path) },
		func() error { return stagedPolicyWrite(file, output) },
		func() error { return finalizeStagedPolicyFile(file, output.path) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			_ = file.Close()
			return err
		}
	}
	return nil
}

func stagedPolicyChmod(file *os.File, path string) error {
	if err := file.Chmod(0o644); err != nil {
		return fmt.Errorf("chmod staged policy output %s: %w", path, err)
	}
	return nil
}

func stagedPolicyWrite(file *os.File, output policyArtifactOutput) error {
	if _, err := file.Write(output.data); err != nil {
		return fmt.Errorf("write staged policy output %s: %w", output.path, err)
	}
	return nil
}

func finalizeStagedPolicyFile(file *os.File, path string) error {
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync staged policy output %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close staged policy output %s: %w", path, err)
	}
	return nil
}

func createPolicyArtifactOutputs(staged []*stagedPolicyArtifact) error {
	for _, artifact := range staged {
		if err := os.Link(artifact.temporary, artifact.output.path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return exitError{code: 64, message: fmt.Sprintf("refusing to replace existing file %s; use --replace", artifact.output.path)}
			}
			return fmt.Errorf("create policy output %s: %w", artifact.output.path, err)
		}
		artifact.committed = true
	}
	return nil
}

func replacePolicyArtifactOutputs(staged []*stagedPolicyArtifact) error {
	for _, artifact := range staged {
		if err := backupPolicyArtifact(artifact); err != nil {
			return err
		}
	}
	for _, artifact := range staged {
		if err := os.Rename(artifact.temporary, artifact.output.path); err != nil {
			return fmt.Errorf("replace policy output %s: %w", artifact.output.path, err)
		}
		artifact.committed = true
	}
	return nil
}

func backupPolicyArtifact(artifact *stagedPolicyArtifact) error {
	info, err := os.Lstat(artifact.output.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect policy output %s: %w", artifact.output.path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("refusing to replace policy output directory %s", artifact.output.path)
	}
	backup, err := unusedPolicyBackupPath(artifact.output.path)
	if err != nil {
		return err
	}
	if err := os.Rename(artifact.output.path, backup); err != nil {
		return fmt.Errorf("backup policy output %s: %w", artifact.output.path, err)
	}
	artifact.backup = backup
	return nil
}

func unusedPolicyBackupPath(path string) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.backup")
	if err != nil {
		return "", fmt.Errorf("reserve backup for policy output %s: %w", path, err)
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("close backup reservation for policy output %s: %w", path, err)
	}
	if err := os.Remove(name); err != nil {
		return "", fmt.Errorf("release backup reservation for policy output %s: %w", path, err)
	}
	return name, nil
}

func rollbackPolicyArtifactOutputs(staged []*stagedPolicyArtifact) error {
	var rollbackErrors []error
	for index := len(staged) - 1; index >= 0; index-- {
		if err := rollbackPolicyArtifact(staged[index]); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if err := syncPolicyArtifactDirectories(staged); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	return errors.Join(rollbackErrors...)
}

func rollbackPolicyArtifact(artifact *stagedPolicyArtifact) error {
	if err := rollbackCommittedPolicyArtifact(artifact); err != nil {
		return err
	}
	return restorePolicyArtifactBackup(artifact)
}

func rollbackCommittedPolicyArtifact(artifact *stagedPolicyArtifact) error {
	if !artifact.committed {
		return nil
	}
	if err := removeCommittedPolicyArtifact(artifact); err != nil {
		return err
	}
	artifact.committed = false
	return nil
}

func restorePolicyArtifactBackup(artifact *stagedPolicyArtifact) error {
	if artifact.backup == "" {
		return nil
	}
	if err := os.Rename(artifact.backup, artifact.output.path); err != nil {
		return fmt.Errorf("restore policy output %s: %w", artifact.output.path, err)
	}
	artifact.backup = ""
	return nil
}

func removeCommittedPolicyArtifact(artifact *stagedPolicyArtifact) error {
	info, err := os.Stat(artifact.output.path)
	if err != nil {
		return fmt.Errorf("inspect committed policy output %s: %w", artifact.output.path, err)
	}
	if !os.SameFile(info, artifact.info) {
		return fmt.Errorf("refusing to roll back policy output %s changed by another process", artifact.output.path)
	}
	if err := os.Remove(artifact.output.path); err != nil {
		return fmt.Errorf("remove committed policy output %s: %w", artifact.output.path, err)
	}
	return nil
}

func removePolicyArtifactBackups(staged []*stagedPolicyArtifact) {
	for _, artifact := range staged {
		if artifact.backup != "" {
			_ = os.Remove(artifact.backup)
			artifact.backup = ""
		}
	}
}

func cleanupPolicyArtifactTransaction(staged []*stagedPolicyArtifact) {
	for _, artifact := range staged {
		if artifact.temporary != "" {
			_ = os.Remove(artifact.temporary)
		}
	}
}

func syncPolicyArtifactDirectories(staged []*stagedPolicyArtifact) error {
	seen := make(map[string]bool, len(staged))
	for _, artifact := range staged {
		directory := filepath.Dir(artifact.output.path)
		if seen[directory] {
			continue
		}
		seen[directory] = true
		handle, err := os.Open(directory) // #nosec G304 -- operator-supplied policy output directory.
		if err != nil {
			return fmt.Errorf("open policy output directory %s: %w", directory, err)
		}
		if err := handle.Sync(); err != nil {
			_ = handle.Close()
			return fmt.Errorf("sync policy output directory %s: %w", directory, err)
		}
		if err := handle.Close(); err != nil {
			return fmt.Errorf("close policy output directory %s: %w", directory, err)
		}
	}
	return nil
}

func runPolicyCheck(stdout, stderr io.Writer, args []string) error {
	var flagOutput bytes.Buffer
	fs := flag.NewFlagSet("hf-broker policy check", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	path := fs.String("file", "", "scope policy file")
	if err := fs.Parse(args); err != nil {
		return policyFlagError(stderr, &flagOutput, err)
	}
	if fs.NArg() != 0 || *path == "" {
		return exitError{code: 64, message: "policy check requires --file"}
	}
	data, err := os.ReadFile(*path) // #nosec G304 -- operator-supplied policy path.
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	if _, err := policy.Parse(data); err != nil {
		return exitError{code: 1, message: err.Error()}
	}
	_, err = fmt.Fprintf(stdout, "Policy is valid: %s\n", *path)
	return err
}

func policyFlagError(stderr io.Writer, output *bytes.Buffer, err error) error {
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.Copy(stderr, output)
		return exitError{code: 0}
	}
	return exitError{code: 64, message: "invalid policy command flags"}
}
