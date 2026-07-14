package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policypreset"
	"github.com/osolmaz/brokerkit/store"
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
	var clients stringListFlag
	var denied stringListFlag
	var flagOutput bytes.Buffer
	fs := flag.NewFlagSet("hf-broker policy render", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	preset := fs.String("preset", policypreset.RequestAllAgentOperations, "Hugging Face policy preset")
	fs.Var(&clients, "client", "client identity; repeatable")
	fs.Var(&denied, "deny-operation", "exact operation to deny; repeatable")
	output := fs.String("output", "", "scope policy output path")
	profileOutput := fs.String("profile-out", "", "policy profile output path")
	manifestOutput := fs.String("manifest-out", "", "policy manifest output path")
	replace := fs.Bool("replace", false, "replace existing output files")
	if err := fs.Parse(args); err != nil {
		return policyFlagError(stderr, &flagOutput, err)
	}
	if fs.NArg() != 0 || *output == "" || *profileOutput == "" || *manifestOutput == "" {
		return exitError{code: 64, message: "policy render requires --output, --profile-out, and --manifest-out"}
	}
	if *output == *profileOutput || *output == *manifestOutput || *profileOutput == *manifestOutput {
		return exitError{code: 64, message: "policy render output paths must be distinct"}
	}
	if len(clients) == 0 {
		clients = []string{"agent"}
	}
	artifacts, err := policypreset.Render(policypreset.Profile{
		Version: policypreset.ProfileVersion, Preset: *preset,
		Clients: clients, DeniedOperations: denied,
	})
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	outputs := []struct {
		path string
		data []byte
	}{{*profileOutput, artifacts.ProfileJSON}, {*output, artifacts.PolicyJSON}, {*manifestOutput, artifacts.ManifestJSON}}
	if !*replace {
		for _, item := range outputs {
			if _, err := os.Stat(item.path); err == nil {
				return exitError{code: 64, message: fmt.Sprintf("refusing to replace existing file %s; use --replace", item.path)}
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("inspect %s: %w", item.path, err)
			}
		}
	}
	for _, item := range outputs {
		if err := store.WriteFileAtomic(item.path, item.data, 0o644); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(stdout, "Rendered %s for %d operation(s).\nPolicy: %s\nProfile: %s\nManifest: %s\n", artifacts.Profile.Preset, artifacts.Manifest.OperationCounts.Total, *output, *profileOutput, *manifestOutput)
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
