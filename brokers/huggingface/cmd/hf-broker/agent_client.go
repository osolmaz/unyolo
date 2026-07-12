package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/protocol/agentwire"
)

const defaultClientWait = 15 * time.Minute

type agentClient struct {
	api    agentwire.ClientInterface
	secret string
}

type repoCreateClientOptions struct {
	repoID         string
	repoType       string
	private        bool
	sdk            string
	reason         string
	idempotencyKey string
	wait           bool
	waitTimeout    time.Duration
	jsonOutput     bool
}

func runAgentClient(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer, args []string) error {
	client, err := loadAgentClient(getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	if len(args) >= 2 && args[0] == "repo" && args[1] == "create" {
		return runClientRepoCreate(ctx, client, stdout, stderr, args[2:])
	}
	if len(args) >= 2 && args[0] == "operation" && (args[1] == "get" || args[1] == "wait") {
		return runClientOperation(ctx, client, stdout, args[1], args[2:])
	}
	return exitError{code: 64, message: "usage: hf-broker client repo create OWNER/NAME [options] | hf-broker client operation <get|wait> ID"}
}

func runClientRepoCreate(ctx context.Context, client *agentClient, stdout, stderr io.Writer, args []string) error {
	opts, err := parseRepoCreateClientOptions(args)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	request, err := repoCreateSubmitRequest(&opts)
	if err != nil {
		return err
	}
	operation, err := client.submit(ctx, request)
	if err != nil {
		return err
	}
	if !opts.jsonOutput {
		_, _ = fmt.Fprintf(stderr, "HF Broker operation %s: %s\n", operation.ID, operation.State)
		if operation.State == agentv1.StatePending {
			_, _ = fmt.Fprintln(stderr, "Approval requested. Approve it in MLClaw; no Hugging Face token is needed.")
		}
	}
	if opts.wait && !operation.State.Terminal() {
		waitCtx, cancel := context.WithTimeout(ctx, opts.waitTimeout)
		defer cancel()
		operation, err = client.wait(waitCtx, operation)
		if err != nil {
			return err
		}
	}
	return printClientOperation(stdout, operation, opts.jsonOutput)
}

func repoCreateSubmitRequest(options *repoCreateClientOptions) (agentv1.SubmitRequest, error) {
	owner, name, ok := strings.Cut(options.repoID, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return agentv1.SubmitRequest{}, exitError{code: 64, message: "repository must be OWNER/NAME"}
	}
	if options.idempotencyKey == "" {
		value, err := randomClientID()
		if err != nil {
			return agentv1.SubmitRequest{}, err
		}
		options.idempotencyKey = value
	}
	target, _ := json.Marshal(map[string]any{"kind": "repo", "type": options.repoType, "owner": owner, "name": name})
	arguments := map[string]any{"private": options.private}
	if options.sdk != "" {
		arguments["sdk"] = options.sdk
	}
	argumentJSON, _ := json.Marshal(arguments)
	return agentv1.SubmitRequest{IdempotencyKey: options.idempotencyKey, Operation: "repo.create", Target: target, Arguments: argumentJSON, Reason: options.reason}, nil
}

func parseRepoCreateClientOptions(args []string) (repoCreateClientOptions, error) {
	options := repoCreateClientOptions{repoType: "dataset", private: true, reason: "Create a Hugging Face repository through HF Broker", wait: true, waitTimeout: defaultClientWait}
	args = takeLeadingRepoID(args, &options)
	flags := flag.NewFlagSet("repo create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.repoType, "type", options.repoType, "model, dataset, or space")
	flags.BoolVar(&options.private, "private", options.private, "create a private repository")
	public := flags.Bool("public", false, "create a public repository")
	flags.StringVar(&options.sdk, "sdk", "", "Space SDK")
	flags.StringVar(&options.reason, "reason", options.reason, "approval reason")
	flags.StringVar(&options.idempotencyKey, "idempotency-key", "", "stable retry key")
	flags.BoolVar(&options.wait, "wait", options.wait, "wait for approval and completion")
	flags.DurationVar(&options.waitTimeout, "wait-timeout", options.waitTimeout, "maximum wait")
	flags.BoolVar(&options.jsonOutput, "json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if err := takeTrailingRepoID(flags.Args(), &options); err != nil {
		return options, err
	}
	if *public {
		options.private = false
	}
	return validateRepoCreateClientOptions(options)
}

func takeLeadingRepoID(args []string, options *repoCreateClientOptions) []string {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		options.repoID = args[0]
		return args[1:]
	}
	return args
}

func takeTrailingRepoID(args []string, options *repoCreateClientOptions) error {
	if options.repoID == "" && len(args) == 1 {
		options.repoID = args[0]
		return nil
	}
	if len(args) != 0 {
		return errors.New("repository OWNER/NAME must be provided once")
	}
	if options.repoID == "" {
		return errors.New("repository OWNER/NAME is required")
	}
	return nil
}

func validateRepoCreateClientOptions(options repoCreateClientOptions) (repoCreateClientOptions, error) {
	if options.repoType != "model" && options.repoType != "dataset" && options.repoType != "space" {
		return options, errors.New("repository type must be model, dataset, or space")
	}
	if options.repoType == "space" && options.sdk == "" {
		options.sdk = "docker"
	}
	if options.repoType != "space" && options.sdk != "" {
		return options, errors.New("--sdk is supported only for Spaces")
	}
	if strings.TrimSpace(options.reason) == "" || options.waitTimeout <= 0 {
		return options, errors.New("reason and a positive wait timeout are required")
	}
	return options, nil
}

func runClientOperation(ctx context.Context, client *agentClient, stdout io.Writer, action string, args []string) error {
	flags := flag.NewFlagSet("operation "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	timeout := flags.Duration("wait-timeout", defaultClientWait, "maximum wait")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return exitError{code: 64, message: "operation ID is required"}
	}
	operation, err := client.get(ctx, flags.Arg(0))
	if err != nil {
		return err
	}
	if action == "wait" && !operation.State.Terminal() {
		waitCtx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		operation, err = client.wait(waitCtx, operation)
		if err != nil {
			return err
		}
	}
	return printClientOperation(stdout, operation, *jsonOutput)
}

func loadAgentClient(getenv func(string) string) (*agentClient, error) {
	baseURL := firstEnvironment(getenv, "HF_BROKER_URL", "MLCLAW_HF_BROKER_URL")
	parsed, err := parseAgentBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	secret, err := loadAgentSecret(getenv)
	if err != nil {
		return nil, err
	}
	if len(secret) < 32 {
		return nil, errors.New("HF Broker agent credential is invalid")
	}
	httpClient := &http.Client{Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	api, err := agentwire.NewClient(strings.TrimRight(parsed.String(), "/"), agentwire.WithHTTPClient(httpClient),
		agentwire.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("Authorization", "Bearer "+secret)
			return nil
		}))
	if err != nil {
		return nil, errors.New("HF Broker URL is invalid")
	}
	return &agentClient{api: api, secret: secret}, nil
}

func parseAgentBaseURL(value string) (*url.URL, error) {
	if value == "" {
		return nil, errors.New("HF Broker URL is not configured")
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("HF Broker URL is invalid")
	}
	return parsed, nil
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
	data, err := json.Marshal(request)
	if err != nil {
		return agentv1.Operation{}, err
	}
	response, err := client.api.SubmitAgentOperationWithBody(ctx, "application/json", bytes.NewReader(data))
	return decodeAgentHTTPResponse(response, err)
}

func (client *agentClient) get(ctx context.Context, id string) (agentv1.Operation, error) {
	response, err := client.api.GetAgentOperation(ctx, id)
	return decodeAgentHTTPResponse(response, err)
}

func (client *agentClient) wait(ctx context.Context, operation agentv1.Operation) (agentv1.Operation, error) {
	for !operation.State.Terminal() {
		after, wait := int(operation.Revision), 30
		response, requestErr := client.api.WaitForAgentOperation(ctx, operation.ID, &agentwire.WaitForAgentOperationParams{AfterRevision: &after, WaitSeconds: &wait})
		next, err := decodeAgentHTTPResponse(response, requestErr)
		if err != nil {
			if ctx.Err() != nil {
				return operation, fmt.Errorf("operation %s is still pending; resume it with hf-broker client operation wait %s", operation.ID, operation.ID)
			}
			return operation, err
		}
		operation = next
	}
	return operation, nil
}

func decodeAgentHTTPResponse(response *http.Response, err error) (agentv1.Operation, error) {
	if err != nil {
		return agentv1.Operation{}, err
	}
	if response == nil {
		return agentv1.Operation{}, errors.New("HF Broker returned no response")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := httpx.ReadLimited(response.Body, 64*1024)
	if err != nil {
		return agentv1.Operation{}, err
	}
	return decodeAgentResponse(response.StatusCode, data)
}

func decodeAgentResponse(status int, data []byte) (agentv1.Operation, error) {
	if status < 200 || status >= 300 {
		var envelope agentv1.ErrorEnvelope
		if strictjson.Decode(data, &envelope, false) == nil && envelope.Error.Message != "" {
			return agentv1.Operation{}, errors.New(envelope.Error.Message)
		}
		return agentv1.Operation{}, fmt.Errorf("HF Broker request failed with HTTP %d", status)
	}
	var operation agentv1.Operation
	if err := strictjson.Decode(data, &operation, false); err != nil || operation.APIVersion != agentv1.APIVersion {
		return agentv1.Operation{}, errors.New("HF Broker returned an invalid operation")
	}
	return operation, nil
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
