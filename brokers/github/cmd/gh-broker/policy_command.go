package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	sharedpreset "github.com/osolmaz/unyolo/authorization/preset"
	ghpolicy "github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/policypreset"
	unyolosetup "github.com/osolmaz/unyolo/internal/host/setup"
)

const policyUsage = `usage:
  gh-broker policy render --output <scope.json> --profile-out <profile.json> --manifest-out <manifest.json> [flags]
  gh-broker policy check --file <scope.json>`

func runPolicy(stdout, stderr io.Writer, args []string) error {
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

type policyRenderCommand struct {
	preset           string
	clients          unyolosetup.StringListFlag
	deniedOperations unyolosetup.StringListFlag
	policyOutput     string
	profileOutput    string
	manifestOutput   string
	replace          bool
}

func runPolicyRender(stdout, stderr io.Writer, args []string) error {
	command, err := parsePolicyRender(stderr, args)
	if err != nil {
		return err
	}
	clients := command.clients
	if len(clients) == 0 {
		clients = unyolosetup.StringListFlag{"agent"}
	}
	artifacts, err := policypreset.Render(policypreset.Profile{
		Version: policypreset.ProfileVersion, Preset: command.preset,
		Clients: clients, DeniedOperations: command.deniedOperations,
	})
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	outputs := []sharedpreset.Output{
		{Path: command.profileOutput, Data: artifacts.ProfileJSON, Mode: 0o644},
		{Path: command.manifestOutput, Data: artifacts.ManifestJSON, Mode: 0o644},
		{Path: command.policyOutput, Data: artifacts.PolicyJSON, Mode: 0o644},
	}
	if err := sharedpreset.WriteOutputs(outputs, command.replace); err != nil {
		var existing *sharedpreset.ExistingOutputError
		if errors.As(err, &existing) {
			return exitError{code: 64, message: err.Error() + "; use --replace"}
		}
		return err
	}
	_, err = fmt.Fprintf(stdout, "Rendered %s for %d operation(s).\nPolicy: %s\nProfile: %s\nManifest: %s\n", artifacts.Profile.Preset, artifacts.Manifest.OperationCounts.Total, command.policyOutput, command.profileOutput, command.manifestOutput)
	return err
}

func parsePolicyRender(stderr io.Writer, args []string) (policyRenderCommand, error) {
	var command policyRenderCommand
	var output bytes.Buffer
	fs := flag.NewFlagSet("gh-broker policy render", flag.ContinueOnError)
	fs.SetOutput(&output)
	fs.StringVar(&command.preset, "preset", policypreset.RequestAllAgentOperations, "GitHub policy preset")
	fs.Var(&command.clients, "client", "client identity; repeatable")
	fs.Var(&command.deniedOperations, "deny-operation", "exact operation to deny; repeatable")
	fs.StringVar(&command.policyOutput, "output", "", "scope policy output path")
	fs.StringVar(&command.profileOutput, "profile-out", "", "policy profile output path")
	fs.StringVar(&command.manifestOutput, "manifest-out", "", "policy manifest output path")
	fs.BoolVar(&command.replace, "replace", false, "replace existing output files")
	if err := parseCommandFlags(stderr, fs, &output, args, "invalid policy render flags"); err != nil {
		return policyRenderCommand{}, err
	}
	if fs.NArg() != 0 || command.policyOutput == "" || command.profileOutput == "" || command.manifestOutput == "" {
		return policyRenderCommand{}, exitError{code: 64, message: "policy render requires --output, --profile-out, and --manifest-out"}
	}
	return command, nil
}

func runPolicyCheck(stdout, stderr io.Writer, args []string) error {
	var output bytes.Buffer
	fs := flag.NewFlagSet("gh-broker policy check", flag.ContinueOnError)
	fs.SetOutput(&output)
	path := fs.String("file", "", "scope policy file")
	if err := parseCommandFlags(stderr, fs, &output, args, "invalid policy check flags"); err != nil {
		return err
	}
	if fs.NArg() != 0 || *path == "" {
		return exitError{code: 64, message: "policy check requires --file"}
	}
	data, err := os.ReadFile(*path) // #nosec G304 -- operator-supplied policy path.
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	if _, err := ghpolicy.Parse(data); err != nil {
		return exitError{code: 1, message: err.Error()}
	}
	_, err = fmt.Fprintf(stdout, "Policy is valid: %s\n", *path)
	return err
}
