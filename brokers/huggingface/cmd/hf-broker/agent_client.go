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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/clienthttp"
)

const defaultClientWait = 15 * time.Minute

type agentClient struct {
	operations  *agentclient.Client
	baseURL     string
	secret      string
	httpClient  *http.Client
	grantClient *hfGrantClient
}

func runAgentClient(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer, args []string) error {
	client, err := loadAgentClient(getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	if isClientOperationCommand(args) {
		return runClientOperation(ctx, client, stdout, args[1], args[2:])
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

func runClientOperation(ctx context.Context, client *agentClient, stdout io.Writer, action string, args []string) error {
	options, err := parseClientOperationOptions(action, args)
	if err != nil {
		return err
	}
	operation, err := clientOperationInitialState(ctx, client, action, options.id)
	if err != nil {
		return err
	}
	operation, err = waitForClientOperationAction(ctx, client, action, operation, options.timeout)
	if err != nil {
		return err
	}
	return printClientOperation(stdout, operation, options.jsonOutput)
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

func waitForClientOperationAction(ctx context.Context, client *agentClient, action string, operation agentv1.Operation, timeout time.Duration) (agentv1.Operation, error) {
	if action != "wait" || operation.State.Terminal() {
		return operation, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return client.wait(waitCtx, operation)
}

func clientOperationInitialState(ctx context.Context, client *agentClient, action, id string) (agentv1.Operation, error) {
	if action == "cancel" {
		return client.cancel(ctx, id)
	}
	return client.get(ctx, id)
}

func loadAgentClient(getenv func(string) string) (*agentClient, error) {
	endpointURI := firstEnvironment(getenv, "HF_BROKER_AGENT_ENDPOINT")
	secret, err := loadAgentSecret(getenv)
	if err != nil {
		return nil, err
	}
	operations, err := agentclient.New(agentclient.Options{Endpoint: endpointURI, Credential: secret})
	if err != nil {
		return nil, err
	}
	grantClient, err := newHFGrantClient(endpointURI, secret)
	if err != nil {
		return nil, err
	}
	baseURL, httpClient, err := clienthttp.ForEndpoint(endpointURI, nil)
	if err != nil {
		return nil, err
	}
	return &agentClient{operations: operations, baseURL: baseURL, secret: secret,
		httpClient:  httpClient,
		grantClient: grantClient}, nil
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
	if err != nil && ctx.Err() != nil {
		return updated, fmt.Errorf("operation %s is still pending; resume it with hf-broker client operation wait %s", operation.ID, operation.ID)
	}
	return updated, err
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
	if operation.State.Terminal() {
		message := "Operation did not succeed"
		if operation.Error != nil {
			message = operation.Error.Message
		}
		return exitError{code: 1, message: fmt.Sprintf("%s: %s (%s)", operation.ID, message, operation.State)}
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
