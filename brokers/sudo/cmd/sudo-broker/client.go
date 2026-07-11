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
)

const maxClientResponseBytes = 2 << 20

type clientConfig struct {
	baseURL string
	secret  string
	client  *http.Client
}

type commandFlags struct {
	targetUser string
	arguments  rawArguments
}

func runRequest(ctx context.Context, args []string, stdout io.Writer) error {
	commandID, rest, err := leadingCommand("request", args)
	if err != nil {
		return err
	}
	var common commandFlags
	var reason string
	var requestID string
	var minutes int
	flags := flag.NewFlagSet("sudo-broker request", flag.ContinueOnError)
	addCommandFlags(flags, &common)
	flags.StringVar(&reason, "reason", "", "operator-visible reason")
	flags.StringVar(&requestID, "request-id", "", "idempotent client request id")
	flags.IntVar(&minutes, "minutes", 0, "requested approval duration")
	if err := flags.Parse(rest); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(reason) == "" {
		return errors.New("request requires --as USER and --reason TEXT")
	}
	if requestID == "" {
		requestID, err = randomClientID("request-")
		if err != nil {
			return err
		}
	}
	payload := map[string]any{"client_request_id": requestID, "command_id": commandID, "target_user": common.targetUser,
		"arguments": map[string]json.RawMessage(common.arguments), "reason": reason, "minutes": minutes}
	response, err := clientCall(ctx, http.MethodPost, "/api/v1/requests", payload)
	if err != nil {
		return err
	}
	return writePrettyJSON(stdout, response)
}

func runCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	commandID, rest, err := leadingCommand("run", args)
	if err != nil {
		return err
	}
	var common commandFlags
	var executionID string
	flags := flag.NewFlagSet("sudo-broker run", flag.ContinueOnError)
	addCommandFlags(flags, &common)
	flags.StringVar(&executionID, "execution-id", "", "idempotent execution id")
	if err := flags.Parse(rest); err != nil {
		return err
	}
	if flags.NArg() != 0 || common.targetUser == "" {
		return errors.New("run requires --as USER")
	}
	if executionID == "" {
		executionID, err = randomClientID("execution-")
		if err != nil {
			return err
		}
	}
	payload := map[string]any{"execution_id": executionID, "command_id": commandID, "target_user": common.targetUser,
		"arguments": map[string]json.RawMessage(common.arguments)}
	response, err := clientCall(ctx, http.MethodPost, "/api/v1/executions", payload)
	if err != nil {
		return err
	}
	var result struct {
		Execution struct {
			ExitCode     int    `json:"exit_code"`
			StdoutBase64 string `json:"stdout_base64"`
			StderrBase64 string `json:"stderr_base64"`
		} `json:"execution"`
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return errors.New("broker returned an invalid execution response")
	}
	stdoutBytes, err := base64.StdEncoding.DecodeString(result.Execution.StdoutBase64)
	if err != nil {
		return errors.New("broker returned invalid stdout")
	}
	stderrBytes, err := base64.StdEncoding.DecodeString(result.Execution.StderrBase64)
	if err != nil {
		return errors.New("broker returned invalid stderr")
	}
	_, _ = stdout.Write(stdoutBytes)
	_, _ = stderr.Write(stderrBytes)
	if result.Execution.ExitCode != 0 {
		return exitError{code: result.Execution.ExitCode}
	}
	return nil
}

func runStatus(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("usage: sudo-broker status REQUEST_ID")
	}
	response, err := clientCall(ctx, http.MethodGet, "/api/v1/requests/"+url.PathEscape(args[0]), nil)
	if err != nil {
		return err
	}
	return writePrettyJSON(stdout, response)
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

func clientCall(ctx context.Context, method string, path string, payload any) ([]byte, error) {
	config, err := loadClientConfig()
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(config.baseURL)
	if err != nil {
		return nil, errors.New("SUDO_BROKER_URL is invalid")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	var body io.Reader = http.NoBody
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+config.secret)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := config.client.Do(request) // #nosec G704 -- client URL is restricted to loopback below.
	if err != nil {
		return nil, errors.New("sudo broker is unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxClientResponseBytes+1))
	if err != nil || len(data) > maxClientResponseBytes {
		return nil, errors.New("sudo broker response is invalid")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var value struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &value) != nil || strings.TrimSpace(value.Message) == "" {
			value.Message = "request failed"
		}
		return nil, fmt.Errorf("sudo broker returned %d: %s", response.StatusCode, value.Message)
	}
	return data, nil
}

func loadClientConfig() (clientConfig, error) {
	baseURL := strings.TrimSpace(os.Getenv("SUDO_BROKER_URL"))
	secret := strings.TrimSpace(os.Getenv("SUDO_BROKER_SHARED_SECRET"))
	if baseURL == "" || secret == "" {
		return clientConfig{}, errors.New("SUDO_BROKER_URL and SUDO_BROKER_SHARED_SECRET are required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return clientConfig{}, errors.New("SUDO_BROKER_URL must be a local HTTP URL")
	}
	if err := validateLoopbackAddress(parsed.Host); err != nil {
		return clientConfig{}, errors.New("SUDO_BROKER_URL must use a loopback address")
	}
	return clientConfig{baseURL: strings.TrimRight(baseURL, "/"), secret: secret, client: &http.Client{Timeout: 30 * time.Second}}, nil
}

func randomClientID(prefix string) (string, error) {
	data := make([]byte, 18)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func writePrettyJSON(writer io.Writer, data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("broker returned invalid JSON")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
