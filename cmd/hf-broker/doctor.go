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

	"github.com/osolmaz/hf-broker/internal/isolation"
)

func runDoctor(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runDoctorIsolation(ctx, stdout, stderr, args)
	}
	switch args[0] {
	case "isolation":
		return runDoctorIsolation(ctx, stdout, stderr, args[1:])
	default:
		return exitError{code: 64, message: "usage: hf-broker doctor [isolation] [flags]"}
	}
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
	helperPath, err := os.Executable()
	if err != nil {
		return doctorIsolationCommand{}, fmt.Errorf("resolve executable path: %w", err)
	}
	return doctorIsolationCommand{
		options: isolation.Options{
			AgentUser:   *agentUser,
			AgentUID:    agentUID.value,
			AgentUIDSet: agentUID.set,
			AgentPID:    *agentPID,
			BrokerPID:   *brokerPID,
			TokenFile:   *tokenFile,
			Socket:      *socket,
			HelperPath:  helperPath,
		},
		jsonOutput: *jsonOutput,
	}, nil
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
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitError{code: 0}
		}
		return exitError{code: 64, message: err.Error()}
	}
	if fs.NArg() != 0 {
		return exitError{code: 64, message: "probe does not accept positional arguments"}
	}
	return json.NewEncoder(stdout).Encode(isolation.RunProbe(*tokenFile, *brokerPID))
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
