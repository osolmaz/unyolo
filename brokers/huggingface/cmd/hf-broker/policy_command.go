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
	"strings"

	sharedpreset "github.com/osolmaz/brokerkit/authorization/preset"
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
	protectedTargets, err := command.protectedTargets()
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	artifacts, err := policypreset.Render(policypreset.Profile{
		Version: policypreset.ProfileVersion, Preset: command.preset,
		Clients: command.clients, DeniedOperations: command.deniedOperations, ProtectedTargets: protectedTargets,
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
	protectedBuckets stringListFlag
	protectedRepos   stringListFlag
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
	fs.Var(&command.protectedBuckets, "protect-bucket", "exact OWNER/NAME bucket to deny; repeatable")
	fs.Var(&command.protectedRepos, "protect-repo", "exact TYPE:OWNER/NAME repository to deny; repeatable")
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

func (command policyRenderCommand) protectedTargets() ([]policypreset.ProtectedTarget, error) {
	targets := make([]policypreset.ProtectedTarget, 0, len(command.protectedBuckets)+len(command.protectedRepos))
	for _, value := range command.protectedBuckets {
		owner, name, ok := exactOwnerName(value)
		if !ok {
			return nil, errors.New("protect-bucket must be an exact OWNER/NAME")
		}
		targets = append(targets, policypreset.ProtectedTarget{Kind: string(policy.KindBucket), Owner: owner, Name: name})
	}
	for _, value := range command.protectedRepos {
		repoType, identity, ok := strings.Cut(value, ":")
		owner, name, validIdentity := exactOwnerName(identity)
		if !ok || !validIdentity || !validGrantRepoType(repoType) {
			return nil, errors.New("protect-repo must be an exact TYPE:OWNER/NAME")
		}
		targets = append(targets, policypreset.ProtectedTarget{Kind: string(policy.KindRepo), Type: repoType, Owner: owner, Name: name})
	}
	return targets, nil
}

func exactOwnerName(value string) (string, string, bool) {
	owner, name, found := strings.Cut(value, "/")
	return owner, name, found && owner != "" && name != "" && !strings.Contains(name, "/")
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

func policyArtifactOutputs(command policyRenderCommand, artifacts policypreset.Artifacts) []sharedpreset.Output {
	return []sharedpreset.Output{
		{Path: command.profileOutput, Data: artifacts.ProfileJSON, Mode: 0o644},
		{Path: command.manifestOutput, Data: artifacts.ManifestJSON, Mode: 0o644},
		{Path: command.policyOutput, Data: artifacts.PolicyJSON, Mode: 0o644},
	}
}

func writePolicyArtifactOutputs(outputs []sharedpreset.Output, replace bool) error {
	err := sharedpreset.WriteOutputs(outputs, replace)
	var existing *sharedpreset.ExistingOutputError
	if errors.As(err, &existing) {
		return exitError{code: 64, message: err.Error() + "; use --replace"}
	}
	return err
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
