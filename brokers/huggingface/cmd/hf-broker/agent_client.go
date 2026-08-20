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
	"time"

	"github.com/osolmaz/unyolo/agent/client"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/internal/config/client"
	"github.com/osolmaz/unyolo/internal/operationcli"
)

const defaultClientWait = 15 * time.Minute

type agentClient struct {
	operations  *agentclient.Client
	grantClient *hfGrantClient
}

func runAgentClient(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer, args []string) error {
	client, err := loadAgentClient(getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	if len(args) >= 2 && isClientOperationCommand(args) {
		return runClientOperation(ctx, client, stdout, stderr, args[1], args[2:])
	}
	if descriptor, consumed, found := matchCLICommand(args); found {
		return runCatalogOperation(ctx, client, stdout, stderr, descriptor, args[consumed:])
	}
	return exitError{code: 64, message: "usage: hf-broker client <catalog operation> --target-json JSON [options] | hf-broker client operation <get|wait> ID | hf-broker client grant ..."}
}

func isClientOperationCommand(args []string) bool {
	return len(args) >= 2 &&
		args[0] == "operation" &&
		(args[1] == "get" || args[1] == "wait" || args[1] == "cancel")
}

func runClientOperation(ctx context.Context, client *agentClient, stdout, stderr io.Writer, action string, args []string) error {
	options, err := parseClientOperationOptions(action, args)
	if err != nil {
		return err
	}
	operation, operationErr := executeClientOperationAction(ctx, client, action, options)
	return reportClientOperation(stdout, stderr, operation, options.jsonOutput, clientOperationIntent(action), options.timeout, operationErr)
}

type clientOperationOptions struct {
	id         string
	timeout    time.Duration
	jsonOutput bool
}

func parseClientOperationOptions(action string, args []string) (clientOperationOptions, error) {
	flags := flag.NewFlagSet("operation "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	timeout := flags.Duration("wait-timeout", defaultClientWait, "maximum wait")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return clientOperationOptions{}, exitError{code: 64, message: "operation ID is required"}
	}
	return clientOperationOptions{id: flags.Arg(0), timeout: *timeout, jsonOutput: *jsonOutput}, nil
}

func executeClientOperationAction(ctx context.Context, client *agentClient, action string, options clientOperationOptions) (agentv1.Operation, error) {
	operation, err := clientOperationInitialState(ctx, client, action, options.id)
	if err != nil {
		return operation, err
	}
	return waitForClientOperationAction(ctx, client, action, operation, options.timeout)
}

func waitForClientOperationAction(ctx context.Context, client *agentClient, action string, operation agentv1.Operation, timeout time.Duration) (agentv1.Operation, error) {
	if !shouldWaitForClientOperation(action, operation.State) {
		return operation, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	updated, waitErr := client.wait(waitCtx, operation)
	if updated.ID != "" {
		operation = updated
	}
	return operation, waitErr
}

func shouldWaitForClientOperation(action string, state agentv1.State) bool {
	return action == "wait" && !state.Terminal()
}

func clientOperationInitialState(ctx context.Context, client *agentClient, action, id string) (agentv1.Operation, error) {
	if action == "cancel" {
		return client.cancel(ctx, id)
	}
	return client.get(ctx, id)
}

func loadAgentClient(getenv func(string) string) (*agentClient, error) {
	configured, err := loadHFClientConfig(getenv)
	if err != nil {
		return nil, err
	}
	httpClient, err := configured.HTTPClient()
	if err != nil {
		return nil, err
	}
	operations, err := agentclient.New(agentclient.Options{Endpoint: configured.AgentEndpoint, Credential: configured.SharedSecret, HTTPClient: httpClient})
	if err != nil {
		return nil, err
	}
	grantClient, err := newHFGrantClientWithHTTP(configured.AgentEndpoint, configured.SharedSecret, httpClient)
	if err != nil {
		return nil, err
	}
	return &agentClient{operations: operations, grantClient: grantClient}, nil
}

func loadHFClientConfig(getenv func(string) string) (clientconfig.Client, error) {
	home := strings.TrimSpace(getenv("HOME"))
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return clientconfig.Client{}, errors.New("HF Broker client home is unavailable")
		}
	}
	wrapped := func(name string) string {
		if name == "HF_BROKER_SHARED_SECRET_FILE" && strings.TrimSpace(getenv(name)) == "" {
			return getenv("MLCLAW_HF_BROKER_AGENT_SECRET_FILE")
		}
		return getenv(name)
	}
	return clientconfig.Resolve(home, "hf-broker", "HF_BROKER", wrapped)
}

func loadAgentSecret(getenv func(string) string) (string, error) {
	if secret := firstEnvironment(getenv, "HF_BROKER_SHARED_SECRET"); secret != "" {
		return secret, nil
	}
	path := firstEnvironment(getenv, "HF_BROKER_SHARED_SECRET_FILE", "MLCLAW_HF_BROKER_AGENT_SECRET_FILE")
	if path == "" {
		return "", errors.New("HF Broker agent credential is not configured")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- agent credential path is explicitly configured.
	if err != nil {
		return "", errors.New("HF Broker agent credential could not be read")
	}
	return strings.TrimSpace(string(data)), nil
}

func firstEnvironment(getenv func(string) string, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func (client *agentClient) submit(ctx context.Context, request agentv1.SubmitRequest) (agentv1.Operation, error) {
	return client.operations.Submit(ctx, request)
}

func (client *agentClient) get(ctx context.Context, id string) (agentv1.Operation, error) {
	return client.operations.Get(ctx, id)
}

func (client *agentClient) cancel(ctx context.Context, id string) (agentv1.Operation, error) {
	return client.operations.Cancel(ctx, id)
}

func (client *agentClient) wait(ctx context.Context, operation agentv1.Operation) (agentv1.Operation, error) {
	updated, err := client.operations.Wait(ctx, operation)
	if updated.ID != "" {
		operation = updated
	}
	if err != nil && ctx.Err() != nil {
		return operation, fmt.Errorf("operation %s is still incomplete", operation.ID)
	}
	return operation, err
}

func writeClientOperationOutput(stdout, stderr io.Writer, operation agentv1.Operation, jsonOutput bool, intent operationcli.Intent, timeout time.Duration) (bool, error) {
	presentation, err := operationcli.Describe(intent, operation, []string{
		"hf-broker", "client", "operation", "wait", "--wait-timeout", operationcli.WaitTimeoutArgument(timeout), operation.ID,
	})
	if err != nil {
		return false, err
	}
	if err := printClientOperation(stdout, operation, jsonOutput); err != nil {
		return false, err
	}
	if _, err := io.WriteString(stderr, presentation.Notice); err != nil {
		return false, err
	}
	return presentation.CommandFailed, nil
}

func clientOperationIntent(action string) operationcli.Intent {
	switch action {
	case "get":
		return operationcli.IntentGet
	case "wait":
		return operationcli.IntentWait
	case "cancel":
		return operationcli.IntentCancel
	default:
		panic("unsupported client operation action")
	}
}

func reportClientOperation(stdout, stderr io.Writer, operation agentv1.Operation, jsonOutput bool, intent operationcli.Intent, timeout time.Duration, operationErr error) error {
	if operation.ID == "" {
		return operationErr
	}
	failed, err := writeClientOperationOutput(stdout, stderr, operation, jsonOutput, intent, timeout)
	if err != nil {
		return err
	}
	if operationErr != nil {
		return operationErr
	}
	if failed {
		return clientOperationFailure(operation)
	}
	return nil
}

func clientOperationFailure(operation agentv1.Operation) error {
	message := "Operation did not succeed"
	if operation.Error != nil {
		message = operation.Error.Message
	}
	return exitError{code: 1, message: fmt.Sprintf("%s: %s (%s)", operation.ID, message, operation.State)}
}

func printClientOperation(stdout io.Writer, operation agentv1.Operation, jsonOutput bool) error {
	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(operation)
	}
	if operation.State == agentv1.StateSucceeded {
		_, err := fmt.Fprintf(stdout, "Succeeded: %s\n%s\n", operation.Presentation.Summary, string(operation.Result))
		return err
	}
	_, err := fmt.Fprintf(stdout, "%s %s\n", operation.ID, operation.State)
	return err
}

func randomClientID() (string, error) {
	var data [18]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return "cli_" + base64.RawURLEncoding.EncodeToString(data[:]), nil
}
