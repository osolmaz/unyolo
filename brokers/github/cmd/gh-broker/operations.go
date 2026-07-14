package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/clienthttp"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/sealedpayload"
	"github.com/osolmaz/brokerkit/sealedstore"
	"github.com/osolmaz/brokerkit/streamstore"
)

const operationWaitDefault = 15 * time.Minute
const maxStreamDownloadBytes int64 = 256 << 20

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
	credentialSlot := flags.String("credential-slot", "", "encrypted credential destination slot")
	streamFile := flags.String("stream-file", "", "bounded binary upload file")
	streamMediaType := flags.String("stream-media-type", "", "binary upload media type")
	reason := flags.String("reason", "Run "+descriptor.Name+" through GH Broker", "approval reason")
	key := flags.String("request-id", "", "stable retry key")
	wait := flags.Bool("wait", false, "wait for terminal state")
	waitTimeout := flags.Duration("wait-timeout", operationWaitDefault, "maximum wait")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *targetText == "" {
		return exitError{code: 64, message: "closed --target-json and valid operation flags are required"}
	}
	target, arguments := json.RawMessage(*targetText), json.RawMessage(*argumentsText)
	if err := validateOperationInput(descriptor, target, arguments, *sealedFile, *credentialSlot, *streamFile, *streamMediaType); err != nil {
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
	if !agentv1.ValidIdempotencyKey(strings.TrimSpace(*key)) {
		return exitError{code: 64, message: "request-id is invalid"}
	}
	*key = strings.TrimSpace(*key)
	connection, err := loadOperationConnection(os.Getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	arguments, err = prepareCLIArguments(ctx, connection, descriptor, *key, arguments, *sealedFile, *credentialSlot, *streamFile, *streamMediaType)
	if err != nil {
		return err
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

func prepareCLIArguments(ctx context.Context, connection operationConnection, descriptor opcatalog.Descriptor, key string, arguments json.RawMessage,
	sealedFile, credentialSlot, streamFile, streamMediaType string) (json.RawMessage, error) {
	switch {
	case streamDirectionForOperation(descriptor.Name) == "upload":
		reference, err := connection.uploadStream(ctx, descriptor.Name, key, streamFile, streamMediaType)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"public": arguments, "stream_input": reference})
	case descriptor.CredentialOutputKind != nil:
		return json.Marshal(map[string]any{"public": arguments, "credential_slot": credentialSlot})
	case descriptor.Sealed:
		return prepareCLISealedArguments(ctx, connection, descriptor.Name, key, arguments, sealedFile)
	default:
		return arguments, nil
	}
}

func prepareCLISealedArguments(ctx context.Context, connection operationConnection, operation, key string, arguments json.RawMessage,
	sealedFile string) (json.RawMessage, error) {
	if sealedFile == "" {
		return json.Marshal(map[string]any{"public": arguments})
	}
	sealed, err := readSealedArguments(sealedFile)
	if err != nil {
		return nil, exitError{code: 64, message: err.Error()}
	}
	return connection.wrapSealedArguments(ctx, operation, key, arguments, sealed)
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

func runStream(ctx context.Context, stdout io.Writer, args []string) error {
	flags := flag.NewFlagSet("stream download", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "destination file")
	if len(args) < 2 || args[0] != "download" || flags.Parse(args[2:]) != nil || flags.NArg() != 0 || *output == "" {
		return exitError{code: 64, message: "usage: gh-broker stream download <id> --output <path>"}
	}
	connection, err := loadOperationConnection(os.Getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	if err := connection.downloadStream(ctx, args[1], *output); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, *output)
	return err
}

//nolint:cyclop // Download integrity and atomic replacement checks remain explicit at the file boundary.
func (connection operationConnection) downloadStream(ctx context.Context, id, output string) error {
	base, err := url.Parse(connection.baseURL)
	if err != nil {
		return err
	}
	// #nosec G704 -- ParseBaseURL accepted an explicit HTTP(S) broker origin and the path is fixed.
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base.String(), "/")+"/api/agent/v1/streams/"+url.PathEscape(id), http.NoBody)
	if err != nil {
		return errors.New("create stream download request")
	}
	request.Header.Set("Authorization", "Bearer "+connection.secret)
	// #nosec G704 -- the validated broker origin is intentional; Secure disables credential-forwarding redirects.
	response, err := connection.streamClient(10 * time.Minute).Do(request)
	if err != nil {
		return errors.New("download stream")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.ContentLength <= 0 || response.ContentLength > maxStreamDownloadBytes {
		return errors.New("broker rejected stream download")
	}
	directory := filepath.Dir(output)
	file, err := os.CreateTemp(directory, ".gh-broker-stream-*")
	if err != nil {
		return errors.New("create stream output")
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return errors.New("secure stream output")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxStreamDownloadBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written != response.ContentLength || written > maxStreamDownloadBytes ||
		hex.EncodeToString(hash.Sum(nil)) != response.Header.Get("X-Broker-Content-SHA256") {
		return errors.New("stream download failed integrity validation")
	}
	if err := os.Rename(temporary, output); err != nil {
		return errors.New("replace stream output")
	}
	return nil
}

func loadOperationClient(getenv func(string) string) (*agentclient.Client, error) {
	connection, err := loadOperationConnection(getenv)
	if err != nil {
		return nil, err
	}
	return connection.client()
}

type operationConnection struct {
	endpoint string
	baseURL  string
	secret   string
	http     *http.Client
}

func loadOperationConnection(getenv func(string) string) (operationConnection, error) {
	endpointURI := strings.TrimSpace(getenv("GH_BROKER_AGENT_ENDPOINT"))
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
	if endpointURI == "" || secret == "" {
		return operationConnection{}, errors.New("GH Broker client endpoint and credential are not configured")
	}
	baseURL, httpClient, err := clienthttp.ForEndpoint(endpointURI, nil)
	if err != nil {
		return operationConnection{}, err
	}
	return operationConnection{endpoint: endpointURI, baseURL: baseURL, secret: secret, http: httpClient}, nil
}

func (connection operationConnection) client() (*agentclient.Client, error) {
	return agentclient.New(agentclient.Options{Endpoint: connection.endpoint, Credential: connection.secret})
}

func (connection operationConnection) streamClient(timeout time.Duration) *http.Client {
	if connection.http == nil {
		client := clienthttp.Secure(nil)
		client.Timeout = timeout
		return client
	}
	client := *connection.http
	client.Timeout = timeout
	return &client
}

//nolint:cyclop // Mutually exclusive sealed, credential, and stream input forms fail closed in one boundary.
func validateOperationInput(descriptor opcatalog.Descriptor, target, public json.RawMessage, sealedFile, credentialSlot, streamFile, streamMediaType string) error {
	if streamDirectionForOperation(descriptor.Name) == "upload" {
		if streamFile == "" || strings.TrimSpace(streamMediaType) == "" || sealedFile != "" || credentialSlot != "" {
			return errors.New("stream upload operation requires --stream-file and --stream-media-type")
		}
		return schemaregistry.ValidateStreamPublic(descriptor.Name, target, public)
	}
	if streamFile != "" || streamMediaType != "" {
		return errors.New("operation does not accept a stream upload")
	}
	if descriptor.CredentialOutputKind != nil {
		if sealedFile != "" || !credentialstore.ValidSlot(credentialSlot) {
			return errors.New("credential output operation requires --credential-slot and does not accept --sealed-file")
		}
		return schemaregistry.ValidatePublicSubmission(descriptor.Name, target, public)
	}
	if descriptor.Sealed {
		return validateSealedOperationInput(descriptor, target, public, sealedFile, credentialSlot)
	}
	if sealedFile != "" || credentialSlot != "" {
		return errors.New("operation does not accept --sealed-file")
	}
	return schemaregistry.ValidateSubmission(descriptor.Name, target, public)
}

func validateSealedOperationInput(descriptor opcatalog.Descriptor, target, public json.RawMessage, sealedFile, credentialSlot string) error {
	required, err := schemaregistry.SealedArgumentsRequired(descriptor.Name)
	if err != nil {
		return err
	}
	if credentialSlot != "" || required && sealedFile == "" {
		return errors.New("sealed operation requires --sealed-file for required protected arguments")
	}
	return schemaregistry.ValidatePublicSubmission(descriptor.Name, target, public)
}

func streamDirectionForOperation(operation string) string {
	bindings := opbinding.ByOperation(operation)
	if len(bindings) != 1 {
		return ""
	}
	return bindings[0].StreamDirection
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
	base, err := url.Parse(connection.baseURL)
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
	response, err := connection.streamClient(30 * time.Second).Do(request)
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

//nolint:cyclop // Upload file, size, response, and reference integrity checks stay together at the boundary.
func (connection operationConnection) uploadStream(ctx context.Context, operation, requestKey, path, mediaType string) (streamstore.Reference, error) {
	bindings := opbinding.ByOperation(operation)
	if len(bindings) != 1 || bindings[0].StreamDirection != "upload" {
		return streamstore.Reference{}, errors.New("GitHub stream upload operation is invalid")
	}
	file, err := os.Open(path) // #nosec G304 -- explicit caller-selected upload file.
	if err != nil {
		return streamstore.Reference{}, errors.New("stream upload file could not be read")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > bindings[0].RequestBytesLimit {
		return streamstore.Reference{}, errors.New("stream upload file exceeds its bounded size")
	}
	base, err := url.Parse(connection.baseURL)
	if err != nil {
		return streamstore.Reference{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base.String(), "/")+"/api/agent/v1/streams", file)
	if err != nil {
		return streamstore.Reference{}, errors.New("create stream upload request")
	}
	request.ContentLength = info.Size()
	request.Header.Set("Authorization", "Bearer "+connection.secret)
	request.Header.Set("Content-Type", mediaType)
	request.Header.Set("X-Broker-Operation", operation)
	request.Header.Set("X-Broker-Idempotency-Key", requestKey)
	response, err := connection.streamClient(10 * time.Minute).Do(request)
	if err != nil {
		return streamstore.Reference{}, errors.New("upload stream")
	}
	defer func() { _ = response.Body.Close() }()
	data, readErr := httpx.ReadLimited(response.Body, 1<<20)
	var reference streamstore.Reference
	if readErr != nil || response.StatusCode != http.StatusCreated || strictjson.Decode(data, &reference, true) != nil ||
		reference.Owner == "" || reference.Purpose != operation || reference.RequestKey != requestKey {
		return streamstore.Reference{}, errors.New("broker rejected stream upload")
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
