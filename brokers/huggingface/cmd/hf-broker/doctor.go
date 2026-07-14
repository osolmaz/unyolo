package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/isolation"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policypreset"
)

func runDoctor(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runDoctorIsolation(ctx, stdout, stderr, args)
	}
	switch args[0] {
	case "isolation":
		return runDoctorIsolation(ctx, stdout, stderr, args[1:])
	case "policy":
		return runDoctorPolicy(stdout, stderr, args[1:])
	default:
		return exitError{code: 64, message: "usage: hf-broker doctor [isolation|policy] [flags]"}
	}
}

func runDoctorPolicy(stdout, stderr io.Writer, args []string) error {
	command, err := parseDoctorPolicy(stderr, args)
	if err != nil {
		return err
	}
	artifacts, err := readDoctorPolicyArtifacts(command)
	if err != nil {
		return err
	}
	report := policypreset.Check(artifacts.profile, artifacts.manifest, artifacts.policy)
	if err := writeDoctorPolicyReport(stdout, report, command.jsonOutput); err != nil {
		return err
	}
	return doctorPolicyStatusError(report.Status)
}

type doctorPolicyCommand struct {
	profilePath  string
	manifestPath string
	policyPath   string
	jsonOutput   bool
}

func parseDoctorPolicy(stderr io.Writer, args []string) (doctorPolicyCommand, error) {
	var command doctorPolicyCommand
	var flagOutput bytes.Buffer
	fs := flag.NewFlagSet("hf-broker doctor policy", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	fs.StringVar(&command.profilePath, "profile", "", "policy profile path")
	fs.StringVar(&command.manifestPath, "manifest", "", "policy manifest path")
	fs.StringVar(&command.policyPath, "scope", "", "rendered scope policy path")
	fs.BoolVar(&command.jsonOutput, "json", false, "write JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, &flagOutput)
			return doctorPolicyCommand{}, exitError{code: 0}
		}
		return doctorPolicyCommand{}, exitError{code: 64, message: "invalid doctor policy flags"}
	}
	if fs.NArg() != 0 || command.profilePath == "" || command.manifestPath == "" || command.policyPath == "" {
		return doctorPolicyCommand{}, exitError{code: 64, message: "doctor policy requires --profile, --manifest, and --scope"}
	}
	return command, nil
}

type doctorPolicyArtifacts struct {
	profile  []byte
	manifest []byte
	policy   []byte
}

func readDoctorPolicyArtifacts(command doctorPolicyCommand) (doctorPolicyArtifacts, error) {
	profileData, err := readDoctorPolicyFile("profile", command.profilePath)
	if err != nil {
		return doctorPolicyArtifacts{}, err
	}
	manifestData, err := readDoctorPolicyFile("manifest", command.manifestPath)
	if err != nil {
		return doctorPolicyArtifacts{}, err
	}
	policyData, err := readDoctorPolicyFile("scope", command.policyPath)
	if err != nil {
		return doctorPolicyArtifacts{}, err
	}
	return doctorPolicyArtifacts{profile: profileData, manifest: manifestData, policy: policyData}, nil
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

func readDoctorPolicyFile(label, path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied diagnostic path.
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", label, err)
	}
	return data, nil
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
	operationGroups := []struct {
		label      string
		operations []string
	}{
		{"Added operations", report.AddedOperations},
		{"Removed operations", report.RemovedOperations},
		{"Changed operations", report.ChangedOperations},
	}
	for _, group := range operationGroups {
		if len(group.operations) > 0 {
			if _, err := fmt.Fprintf(stdout, "%s: %s\n", group.label, strings.Join(group.operations, ", ")); err != nil {
				return err
			}
		}
	}
	return nil
}

func runDoctorIsolation(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	cmd, err := parseDoctorIsolation(stderr, args)
	if err != nil {
		return err
	}
	report, err := isolation.Run(ctx, cmd.options)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	if err := writeDoctorReport(stdout, report, cmd.jsonOutput); err != nil {
		return err
	}
	code := isolation.ExitCode(report.Status)
	if code == 0 {
		return nil
	}
	return exitError{code: code}
}

type doctorIsolationCommand struct {
	options    isolation.Options
	jsonOutput bool
}

func parseDoctorIsolation(stderr io.Writer, args []string) (doctorIsolationCommand, error) {
	var agentUID optionalIntFlag
	var flagOutput bytes.Buffer
	fs := flag.NewFlagSet("hf-broker doctor [isolation]", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	agentUser := fs.String("agent-user", "", "agent username to evaluate")
	fs.Var(&agentUID, "agent-uid", "agent UID to evaluate")
	agentPID := fs.Int("agent-pid", 0, "optional running agent process PID")
	brokerPID := fs.Int("broker-pid", 0, "optional running broker process PID")
	tokenFile := fs.String("token-file", "", "optional upstream HF token file path")
	socket := fs.String("socket", "", "optional broker Unix socket path")
	jsonOutput := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, &flagOutput)
			return doctorIsolationCommand{}, exitError{code: 0}
		}
		return doctorIsolationCommand{}, exitError{code: 64, message: "invalid doctor isolation flags"}
	}
	if fs.NArg() != 0 {
		return doctorIsolationCommand{}, exitError{code: 64, message: "doctor isolation does not accept positional arguments"}
	}
	agentPIDValue := doctorAgentPID(*agentUser, agentUID.set, *agentPID, flagProvided(fs, "agent-pid"))
	helperPath, err := os.Executable()
	if err != nil {
		return doctorIsolationCommand{}, fmt.Errorf("resolve executable path: %w", err)
	}
	return doctorIsolationCommand{
		options: isolation.Options{
			AgentUser:   *agentUser,
			AgentUID:    agentUID.value,
			AgentUIDSet: agentUID.set,
			AgentPID:    agentPIDValue,
			BrokerPID:   *brokerPID,
			TokenFile:   *tokenFile,
			Socket:      *socket,
			HelperPath:  helperPath,
		},
		jsonOutput: *jsonOutput,
	}, nil
}

func doctorAgentPID(agentUser string, agentUIDSet bool, agentPID int, agentPIDProvided bool) int {
	if agentUser != "" || agentUIDSet || agentPIDProvided {
		return agentPID
	}
	return os.Getpid()
}

func flagProvided(fs *flag.FlagSet, name string) bool {
	var found bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func writeDoctorReport(stdout io.Writer, report isolation.Report, jsonOutput bool) error {
	if jsonOutput {
		return isolation.WriteJSON(stdout, report)
	}
	return isolation.WriteText(stdout, report)
}

func runDoctorIsolationProbe(stdout, stderr io.Writer, args []string) error {
	fs := flag.NewFlagSet("hf-broker __doctor-isolation-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tokenFile := fs.String("token-file", "", "token file path to probe")
	brokerPID := fs.Int("broker-pid", 0, "broker process PID to probe")
	socket := fs.String("socket", "", "broker Unix socket path to probe")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitError{code: 0}
		}
		return exitError{code: 64, message: err.Error()}
	}
	if fs.NArg() != 0 {
		return exitError{code: 64, message: "probe does not accept positional arguments"}
	}
	return json.NewEncoder(stdout).Encode(isolation.RunProbe(*tokenFile, *brokerPID, *socket))
}

type optionalIntFlag struct {
	value int
	set   bool
}

func (f *optionalIntFlag) Set(value string) error {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	if parsed < 0 {
		return fmt.Errorf("must be non-negative")
	}
	f.value = parsed
	f.set = true
	return nil
}

func (f *optionalIntFlag) String() string {
	if !f.set {
		return ""
	}
	return strconv.Itoa(f.value)
}
