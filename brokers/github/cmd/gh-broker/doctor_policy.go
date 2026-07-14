package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/policypreset"
)

type doctorPolicyCommand struct {
	profilePath  string
	manifestPath string
	policyPath   string
	jsonOutput   bool
}

func runDoctorPolicy(stdout, stderr io.Writer, args []string) error {
	command, err := parseDoctorPolicy(stderr, args)
	if err != nil {
		return err
	}
	profile, err := readDoctorPolicyFile("profile", command.profilePath)
	if err != nil {
		return writeInvalidDoctorPolicy(stdout, command.jsonOutput, err)
	}
	manifest, err := readDoctorPolicyFile("manifest", command.manifestPath)
	if err != nil {
		return writeInvalidDoctorPolicy(stdout, command.jsonOutput, err)
	}
	policy, err := readDoctorPolicyFile("scope", command.policyPath)
	if err != nil {
		return writeInvalidDoctorPolicy(stdout, command.jsonOutput, err)
	}
	report := policypreset.Check(profile, manifest, policy)
	if err := writeDoctorPolicyReport(stdout, report, command.jsonOutput); err != nil {
		return err
	}
	return doctorPolicyStatusError(report.Status)
}

func parseDoctorPolicy(stderr io.Writer, args []string) (doctorPolicyCommand, error) {
	var command doctorPolicyCommand
	var output bytes.Buffer
	fs := flag.NewFlagSet("gh-broker doctor policy", flag.ContinueOnError)
	fs.SetOutput(&output)
	fs.StringVar(&command.profilePath, "profile", "", "policy profile path")
	fs.StringVar(&command.manifestPath, "manifest", "", "policy manifest path")
	fs.StringVar(&command.policyPath, "scope", "", "rendered scope policy path")
	fs.BoolVar(&command.jsonOutput, "json", false, "write JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, &output)
			return doctorPolicyCommand{}, exitError{code: 0}
		}
		return doctorPolicyCommand{}, exitError{code: 64, message: "invalid doctor policy flags"}
	}
	if fs.NArg() != 0 || command.profilePath == "" || command.manifestPath == "" || command.policyPath == "" {
		return doctorPolicyCommand{}, exitError{code: 64, message: "doctor policy requires --profile, --manifest, and --scope"}
	}
	return command, nil
}

func readDoctorPolicyFile(label, path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied diagnostic path.
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", label, err)
	}
	return data, nil
}

func writeInvalidDoctorPolicy(stdout io.Writer, jsonOutput bool, cause error) error {
	report := policypreset.DriftReport{Status: policypreset.DriftInvalid, Details: []string{cause.Error()}, AddedOperations: []string{}, RemovedOperations: []string{}, ChangedOperations: []string{}}
	if err := writeDoctorPolicyReport(stdout, report, jsonOutput); err != nil {
		return err
	}
	return doctorPolicyStatusError(report.Status)
}

func writeDoctorPolicyReport(stdout io.Writer, report policypreset.DriftReport, jsonOutput bool) error {
	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	if _, err := fmt.Fprintf(stdout, "Policy status: %s\n", report.Status); err != nil {
		return err
	}
	for _, detail := range report.Details {
		if _, err := fmt.Fprintf(stdout, "- %s\n", detail); err != nil {
			return err
		}
	}
	groups := []struct {
		label      string
		operations []string
	}{
		{"Added operations", report.AddedOperations},
		{"Removed operations", report.RemovedOperations},
		{"Changed operations", report.ChangedOperations},
	}
	for _, group := range groups {
		if len(group.operations) > 0 {
			if _, err := fmt.Fprintf(stdout, "%s: %s\n", group.label, strings.Join(group.operations, ", ")); err != nil {
				return err
			}
		}
	}
	return nil
}

func doctorPolicyStatusError(status policypreset.DriftStatus) error {
	switch status {
	case policypreset.DriftCurrent:
		return nil
	case policypreset.DriftInvalid:
		return exitError{code: 2}
	default:
		return exitError{code: 1}
	}
}
