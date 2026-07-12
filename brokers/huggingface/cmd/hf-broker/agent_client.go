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
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
)

const defaultClientWait = 15 * time.Minute

type agentClient struct {
	baseURL string
	secret  string
	http    *http.Client
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
	return &agentClient{baseURL: strings.TrimRight(parsed.String(), "/"), secret: secret, http: &http.Client{Timeout: 35 * time.Second}}, nil
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
	return client.request(ctx, http.MethodPost, "/api/agent/v1/operations", request)
}

func (client *agentClient) get(ctx context.Context, id string) (agentv1.Operation, error) {
	return client.request(ctx, http.MethodGet, "/api/agent/v1/operations/"+url.PathEscape(id), nil)
}

func (client *agentClient) wait(ctx context.Context, operation agentv1.Operation) (agentv1.Operation, error) {
	for !operation.State.Terminal() {
		path := "/api/agent/v1/operations/" + url.PathEscape(operation.ID) + "/events?after_revision=" + strconv.FormatInt(operation.Revision, 10) + "&wait_seconds=30"
		next, err := client.request(ctx, http.MethodGet, path, nil)
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

func (client *agentClient) request(ctx context.Context, method, path string, payload any) (agentv1.Operation, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return agentv1.Operation{}, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, body) // #nosec G704 -- the base origin is validated configuration and path is a fixed broker route.
	if err != nil {
		return agentv1.Operation{}, err
	}
	req.Header.Set("Authorization", "Bearer "+client.secret)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(req) // #nosec G704 -- request origin is validated broker configuration.
	if err != nil {
		return agentv1.Operation{}, err
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return agentv1.Operation{}, err
	}
	return decodeAgentResponse(response.StatusCode, data)
}

func decodeAgentResponse(status int, data []byte) (agentv1.Operation, error) {
	if status < 200 || status >= 300 {
		var envelope agentv1.ErrorEnvelope
		if json.Unmarshal(data, &envelope) == nil && envelope.Error.Message != "" {
			return agentv1.Operation{}, errors.New(envelope.Error.Message)
		}
		return agentv1.Operation{}, fmt.Errorf("HF Broker request failed with HTTP %d", status)
	}
	var operation agentv1.Operation
	if err := json.Unmarshal(data, &operation); err != nil || operation.APIVersion != agentv1.APIVersion {
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
	data := make([]byte, 18)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return "cli_" + base64.RawURLEncoding.EncodeToString(data), nil
}
