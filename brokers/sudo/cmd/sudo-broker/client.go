package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/osolmaz/brokerkit/agent/client"
	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
)

type commandFlags struct {
	targetUser string
	arguments  rawArguments
}

func runCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	commandID, rest, err := leadingCommand("run", args)
	if err != nil {
		return err
	}
	common, operationID, reason, err := parseRunCommandFlags(rest)
	if err != nil {
		return err
	}
	request, err := buildRunSubmitRequest(commandID, common, operationID, reason)
	if err != nil {
		return err
	}
	client, err := loadAgentClient()
	if err != nil {
		return err
	}
	operation, err := submitAndWait(ctx, client, request)
	if err != nil {
		return err
	}
	if err := validateCommandOperation(operation); err != nil {
		return err
	}
	return writeCommandResult(stdout, stderr, operation.Result)
}

func parseRunCommandFlags(args []string) (commandFlags, string, string, error) {
	var common commandFlags
	var operationID, reason string
	flags := flag.NewFlagSet("sudo-broker run", flag.ContinueOnError)
	addCommandFlags(flags, &common)
	flags.StringVar(&operationID, "operation-id", "", "idempotent operation id")
	flags.StringVar(&reason, "reason", "", "operator-visible reason")
	if err := flags.Parse(args); err != nil {
		return commandFlags{}, "", "", err
	}
	if flags.NArg() != 0 || common.targetUser == "" || strings.TrimSpace(reason) == "" {
		return commandFlags{}, "", "", errors.New("run requires --as USER and --reason TEXT")
	}
	if operationID == "" {
		var err error
		operationID, err = randomClientID("command-")
		if err != nil {
			return commandFlags{}, "", "", err
		}
	}
	return common, operationID, strings.TrimSpace(reason), nil
}

func buildRunSubmitRequest(commandID string, common commandFlags, operationID string, reason string) (agentv1.SubmitRequest, error) {
	commandArguments := map[string]json.RawMessage(common.arguments)
	if commandArguments == nil {
		commandArguments = map[string]json.RawMessage{}
	}
	arguments, err := json.Marshal(map[string]any{"command_id": commandID, "arguments": commandArguments})
	if err != nil {
		return agentv1.SubmitRequest{}, err
	}
	target, _ := json.Marshal(map[string]string{"kind": "user", "name": common.targetUser})
	return agentv1.SubmitRequest{IdempotencyKey: operationID, Operation: sudopolicy.OperationExecCommand,
		Target: target, Arguments: arguments, Reason: reason}, nil
}

func submitAndWait(ctx context.Context, client *agentclient.Client, request agentv1.SubmitRequest) (agentv1.Operation, error) {
	operation, err := client.Submit(ctx, request)
	if err != nil {
		return agentv1.Operation{}, err
	}
	return client.Wait(ctx, operation)
}

func validateCommandOperation(operation agentv1.Operation) error {
	if operation.State != agentv1.StateSucceeded {
		if operation.Error != nil {
			return errors.New(operation.Error.Message)
		}
		return fmt.Errorf("command ended in state %s", operation.State)
	}
	return nil
}

func writeCommandResult(stdout, stderr io.Writer, raw json.RawMessage) error {
	var result struct {
		ExitCode     int    `json:"exit_code"`
		StdoutBase64 string `json:"stdout_base64"`
		StderrBase64 string `json:"stderr_base64"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return errors.New("broker returned an invalid command result")
	}
	stdoutBytes, err := base64.StdEncoding.DecodeString(result.StdoutBase64)
	if err != nil {
		return errors.New("broker returned invalid stdout")
	}
	stderrBytes, err := base64.StdEncoding.DecodeString(result.StderrBase64)
	if err != nil {
		return errors.New("broker returned invalid stderr")
	}
	_, _ = stdout.Write(stdoutBytes)
	_, _ = stderr.Write(stderrBytes)
	if result.ExitCode != 0 {
		return exitError{code: result.ExitCode}
	}
	return nil
}

func loadAgentClient() (*agentclient.Client, error) {
	endpointURI := strings.TrimSpace(os.Getenv("SUDO_BROKER_AGENT_ENDPOINT"))
	secret := strings.TrimSpace(os.Getenv("SUDO_BROKER_SHARED_SECRET"))
	if endpointURI == "" || secret == "" {
		return nil, errors.New("SUDO_BROKER_AGENT_ENDPOINT and SUDO_BROKER_SHARED_SECRET must identify a local broker")
	}
	return agentclient.New(agentclient.Options{Endpoint: endpointURI, Credential: secret})
}

func addCommandFlags(flags *flag.FlagSet, values *commandFlags) {
	flags.StringVar(&values.targetUser, "as", "", "target Unix user")
	flags.Var(&values.arguments, "arg-json", "typed slot value NAME=JSON; repeat as needed")
}

func leadingCommand(name string, args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || strings.TrimSpace(args[0]) == "" {
		return "", nil, fmt.Errorf("usage: sudo-broker %s COMMAND_ID --as USER", name)
	}
	return args[0], args[1:], nil
}

type rawArguments map[string]json.RawMessage

func (r *rawArguments) String() string { return "" }

func (r *rawArguments) Set(value string) error {
	name, raw, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(name) != name || name == "" || len(raw) == 0 || !json.Valid([]byte(raw)) {
		return errors.New("argument must use NAME=JSON")
	}
	if *r == nil {
		*r = map[string]json.RawMessage{}
	}
	if _, duplicate := (*r)[name]; duplicate {
		return fmt.Errorf("argument %q was provided more than once", name)
	}
	(*r)[name] = json.RawMessage(raw)
	return nil
}

func randomClientID(prefix string) (string, error) {
	data := make([]byte, 18)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data), nil
}
