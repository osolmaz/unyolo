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
	"os"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/clienthttp"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/sealedpayload"
	"github.com/osolmaz/brokerkit/sealedstore"
)

const operationWaitDefault = 15 * time.Minute

func runOperations(stdout io.Writer, args []string) error {
	if len(args) == 0 {
		return exitError{code: 64, message: "usage: gh-broker operations <list|describe>"}
	}
	switch args[0] {
	case "list":
		return listOperations(stdout, args[1:])
	case "describe":
		if len(args) != 2 {
			return exitError{code: 64, message: "operation name is required"}
		}
		descriptor, found := opcatalog.ByName(args[1])
		if !found {
			return exitError{code: 64, message: "unknown GitHub operation"}
		}
		return writeJSONOutput(stdout, descriptor)
	default:
		return exitError{code: 64, message: "usage: gh-broker operations <list|describe>"}
	}
}

//nolint:cyclop // Small CLI filter branches remain explicit and deterministic.
func listOperations(stdout io.Writer, args []string) error {
	flags := flag.NewFlagSet("operations list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	family := flags.String("family", "", "operation family")
	risk := flags.String("risk", "", "risk level")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return exitError{code: 64, message: "invalid operations list flags"}
	}
	result := []opcatalog.Descriptor{}
	for _, descriptor := range opcatalog.MustAll() {
		if *family != "" && !strings.HasPrefix(descriptor.Name, strings.TrimSuffix(*family, ".*")+".") {
			continue
		}
		if *risk != "" && string(descriptor.Risk) != *risk {
			continue
		}
		result = append(result, descriptor)
	}
	if *jsonOutput {
		return writeJSONOutput(stdout, result)
	}
	for _, descriptor := range result {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\n", descriptor.Name, descriptor.Risk, descriptor.Summary); err != nil {
			return err
		}
	}
	return nil
}

func runOperation(ctx context.Context, stdout io.Writer, args []string) error {
	if len(args) == 0 {
		return exitError{code: 64, message: "usage: gh-broker operation <submit|get|wait|cancel>"}
	}
	if args[0] == "submit" {
		if len(args) < 2 {
			return exitError{code: 64, message: "operation name is required"}
		}
		descriptor, found := opcatalog.ByName(args[1])
		if !found || !descriptor.AgentFacing {
			return exitError{code: 64, message: "unknown agent-facing GitHub operation"}
		}
		return submitCatalogOperation(ctx, stdout, descriptor, args[2:])
	}
	if args[0] == "get" || args[0] == "wait" || args[0] == "cancel" {
		return runOperationLifecycle(ctx, stdout, args[0], args[1:])
	}
	return exitError{code: 64, message: "usage: gh-broker operation <submit|get|wait|cancel>"}
}

func runGeneratedCLI(ctx context.Context, stdout io.Writer, args []string) (bool, error) {
	descriptor, consumed, found := capability.MatchCLICommand(opcatalog.CapabilityDescriptors(opcatalog.MustAll()), args)
	if !found {
		return false, nil
	}
	providerDescriptor, found := opcatalog.ByName(descriptor.Name)
	if !found {
		return true, errors.New("GitHub operation catalog drifted")
	}
	return true, submitCatalogOperation(ctx, stdout, providerDescriptor, args[consumed:])
}

//nolint:cyclop // Submission validation keeps every caller-controlled input check visible.
func submitCatalogOperation(ctx context.Context, stdout io.Writer, descriptor opcatalog.Descriptor, args []string) error {
	flags := flag.NewFlagSet(descriptor.Name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	targetText := flags.String("target-json", "", "closed target JSON")
	argumentsText := flags.String("arguments-json", "{}", "closed argument JSON")
	sealedFile := flags.String("sealed-file", "", "sealed argument JSON file")
	reason := flags.String("reason", "Run "+descriptor.Name+" through GH Broker", "approval reason")
	key := flags.String("idempotency-key", "", "stable retry key")
	wait := flags.Bool("wait", false, "wait for terminal state")
	waitTimeout := flags.Duration("wait-timeout", operationWaitDefault, "maximum wait")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *targetText == "" {
		return exitError{code: 64, message: "closed --target-json and valid operation flags are required"}
	}
	target, arguments := json.RawMessage(*targetText), json.RawMessage(*argumentsText)
	if err := validateOperationInput(descriptor, target, arguments, *sealedFile); err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	if strings.TrimSpace(*reason) == "" || len(*reason) > 2000 {
		return exitError{code: 64, message: "reason is required"}
	}
	if *key == "" {
		generated, err := operationRequestID()
		if err != nil {
			return err
		}
		*key = generated
	}
	connection, err := loadOperationConnection(os.Getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	if descriptor.Sealed {
		sealed, readErr := readSealedArguments(*sealedFile)
		if readErr != nil {
			return exitError{code: 64, message: readErr.Error()}
		}
		arguments, err = connection.wrapSealedArguments(ctx, descriptor.Name, *key, arguments, sealed)
		if err != nil {
			return err
		}
	}
	client, err := connection.client()
	if err != nil {
		return err
	}
	operation, err := client.Submit(ctx, agentv1.SubmitRequest{IdempotencyKey: *key, Operation: descriptor.Name, Target: target, Arguments: arguments, Reason: *reason})
	if err != nil {
		return err
	}
	if *wait && !operation.State.Terminal() {
		waitCtx, cancel := context.WithTimeout(ctx, *waitTimeout)
		defer cancel()
		operation, err = client.Wait(waitCtx, operation)
		if err != nil && waitCtx.Err() == nil {
			return err
		}
	}
	return writeJSONOutput(stdout, operation)
}

func runOperationLifecycle(ctx context.Context, stdout io.Writer, action string, args []string) error {
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	timeout := flags.Duration("wait-timeout", operationWaitDefault, "maximum wait")
	if flags.Parse(args) != nil || flags.NArg() != 1 {
		return exitError{code: 64, message: "operation ID is required"}
	}
	client, err := loadOperationClient(os.Getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	var operation agentv1.Operation
	if action == "cancel" {
		operation, err = client.Cancel(ctx, flags.Arg(0))
	} else {
		operation, err = client.Get(ctx, flags.Arg(0))
	}
	if err == nil && action == "wait" && !operation.State.Terminal() {
		waitCtx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		operation, err = client.Wait(waitCtx, operation)
	}
	if err != nil {
		return err
	}
	return writeJSONOutput(stdout, operation)
}

func loadOperationClient(getenv func(string) string) (*agentclient.Client, error) {
	connection, err := loadOperationConnection(getenv)
	if err != nil {
		return nil, err
	}
	return connection.client()
}

type operationConnection struct {
	baseURL string
	secret  string
}

func loadOperationConnection(getenv func(string) string) (operationConnection, error) {
	baseURL := strings.TrimSpace(getenv("GH_BROKER_URL"))
	secret := strings.TrimSpace(getenv("GH_BROKER_SHARED_SECRET"))
	if secret == "" {
		path := strings.TrimSpace(getenv("GH_BROKER_SHARED_SECRET_FILE"))
		if path != "" {
			data, err := os.ReadFile(path) // #nosec G304 -- the client credential path is explicit operator configuration.
			if err != nil {
				return operationConnection{}, errors.New("GH Broker client credential could not be read")
			}
			secret = strings.TrimSpace(string(data))
		}
	}
	if baseURL == "" || secret == "" {
		return operationConnection{}, errors.New("GH Broker client URL and credential are not configured")
	}
	return operationConnection{baseURL: baseURL, secret: secret}, nil
}

func (connection operationConnection) client() (*agentclient.Client, error) {
	return agentclient.New(agentclient.Options{BaseURL: connection.baseURL, Credential: connection.secret})
}

func validateOperationInput(descriptor opcatalog.Descriptor, target, public json.RawMessage, sealedFile string) error {
	if descriptor.Sealed {
		if sealedFile == "" {
			return errors.New("sealed operation requires --sealed-file")
		}
		return schemaregistry.ValidatePublicSubmission(descriptor.Name, target, public)
	}
	if sealedFile != "" {
		return errors.New("operation does not accept --sealed-file")
	}
	return schemaregistry.ValidateSubmission(descriptor.Name, target, public)
}

func readSealedArguments(path string) (json.RawMessage, error) {
	file, err := os.Open(path) // #nosec G304 -- the explicit sealed input path is caller controlled.
	if err != nil {
		return nil, errors.New("sealed arguments could not be read")
	}
	defer func() { _ = file.Close() }()
	payload, err := httpx.ReadLimited(file, sealedpayload.MaxPayloadBytes)
	if err != nil || len(payload) == 0 {
		return nil, errors.New("sealed arguments must be bounded JSON")
	}
	var object map[string]any
	if strictjson.Decode(payload, &object, false) != nil || object == nil {
		return nil, errors.New("sealed arguments must be a JSON object")
	}
	return payload, nil
}

func (connection operationConnection) wrapSealedArguments(ctx context.Context, operation, requestKey string, public, sealed json.RawMessage) (json.RawMessage, error) {
	reference, err := connection.uploadSealedPayload(ctx, operation, requestKey, sealed)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"public": public, "sealed_payload": reference})
}

func (connection operationConnection) uploadSealedPayload(ctx context.Context, operation, requestKey string, payload []byte) (sealedstore.Reference, error) {
	base, err := clienthttp.ParseBaseURL(connection.baseURL)
	if err != nil {
		return sealedstore.Reference{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base.String(), "/")+"/api/agent/v1/sealed-payloads", bytes.NewReader(payload))
	if err != nil {
		return sealedstore.Reference{}, errors.New("create sealed payload request")
	}
	request.Header.Set("Authorization", "Bearer "+connection.secret)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Broker-Operation", operation)
	request.Header.Set("X-Broker-Idempotency-Key", requestKey)
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return sealedstore.Reference{}, errors.New("upload sealed payload")
	}
	defer func() { _ = response.Body.Close() }()
	data, readErr := httpx.ReadLimited(response.Body, 1<<20)
	if readErr != nil || response.StatusCode != http.StatusCreated {
		return sealedstore.Reference{}, errors.New("broker rejected sealed payload")
	}
	var reference sealedstore.Reference
	if strictjson.Decode(data, &reference, true) != nil || reference.ID == "" || reference.Purpose != operation || reference.RequestKey != requestKey {
		return sealedstore.Reference{}, errors.New("broker returned an invalid sealed payload reference")
	}
	return reference, nil
}

func operationRequestID() (string, error) {
	var data [18]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return "cli_" + base64.RawURLEncoding.EncodeToString(data[:]), nil
}
func writeJSONOutput(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
