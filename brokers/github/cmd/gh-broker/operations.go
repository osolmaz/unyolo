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

type catalogSubmitOptions struct {
	targetText      string
	argumentsText   string
	sealedFile      string
	credentialSlot  string
	streamFile      string
	streamMediaType string
	reason          string
	key             string
	wait            bool
	waitTimeout     time.Duration
}

type operationInputValidator func(opcatalog.Descriptor, json.RawMessage, json.RawMessage, string, string, string, string) error

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
		result = appendMatchingOperation(result, descriptor, *family, *risk)
	}
	if *jsonOutput {
		return writeJSONOutput(stdout, result)
	}
	return writeOperationList(stdout, result)
}

func appendMatchingOperation(result []opcatalog.Descriptor, descriptor opcatalog.Descriptor, family, risk string) []opcatalog.Descriptor {
	if family != "" && !strings.HasPrefix(descriptor.Name, strings.TrimSuffix(family, ".*")+".") {
		return result
	}
	if risk != "" && string(descriptor.Risk) != risk {
		return result
	}
	return append(result, descriptor)
}

func writeOperationList(stdout io.Writer, result []opcatalog.Descriptor) error {
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
	switch args[0] {
	case "submit":
		return runOperationSubmit(ctx, stdout, args[1:])
	case "get", "wait", "cancel":
		return runOperationLifecycle(ctx, stdout, args[0], args[1:])
	default:
		return exitError{code: 64, message: "usage: gh-broker operation <submit|get|wait|cancel>"}
	}
}

func runOperationSubmit(ctx context.Context, stdout io.Writer, args []string) error {
	if len(args) < 1 {
		return exitError{code: 64, message: "operation name is required"}
	}
	descriptor, found := opcatalog.ByName(args[0])
	if !found || !descriptor.AgentFacing {
		return exitError{code: 64, message: "unknown agent-facing GitHub operation"}
	}
	return submitCatalogOperation(ctx, stdout, descriptor, args[1:])
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

func submitCatalogOperation(ctx context.Context, stdout io.Writer, descriptor opcatalog.Descriptor, args []string) error {
	opts, err := parseCatalogSubmitOptions(descriptor, args)
	if err != nil {
		return err
	}
	connection, err := loadOperationConnection(os.Getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	target, arguments := json.RawMessage(opts.targetText), json.RawMessage(opts.argumentsText)
	arguments, err = prepareCLIArguments(ctx, connection, descriptor, opts.key, arguments, opts.sealedFile, opts.credentialSlot, opts.streamFile, opts.streamMediaType)
	if err != nil {
		return err
	}
	client, err := connection.client()
	if err != nil {
		return err
	}
	operation, err := client.Submit(ctx, agentv1.SubmitRequest{IdempotencyKey: opts.key, Operation: descriptor.Name, Target: target, Arguments: arguments, Reason: opts.reason})
	if err != nil {
		return err
	}
	operation, err = waitForSubmittedOperation(ctx, client, operation, opts)
	if err != nil {
		return err
	}
	return writeJSONOutput(stdout, operation)
}

func parseCatalogSubmitOptions(descriptor opcatalog.Descriptor, args []string) (catalogSubmitOptions, error) {
	opts := catalogSubmitOptions{argumentsText: "{}", reason: "Run " + descriptor.Name + " through GH Broker", waitTimeout: operationWaitDefault}
	flags := flag.NewFlagSet(descriptor.Name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.targetText, "target-json", "", "closed target JSON")
	flags.StringVar(&opts.argumentsText, "arguments-json", opts.argumentsText, "closed argument JSON")
	flags.StringVar(&opts.sealedFile, "sealed-file", "", "sealed argument JSON file")
	flags.StringVar(&opts.credentialSlot, "credential-slot", "", "encrypted credential destination slot")
	flags.StringVar(&opts.streamFile, "stream-file", "", "bounded binary upload file")
	flags.StringVar(&opts.streamMediaType, "stream-media-type", "", "binary upload media type")
	flags.StringVar(&opts.reason, "reason", opts.reason, "approval reason")
	flags.StringVar(&opts.key, "request-id", "", "stable retry key")
	flags.BoolVar(&opts.wait, "wait", false, "wait for terminal state")
	flags.DurationVar(&opts.waitTimeout, "wait-timeout", opts.waitTimeout, "maximum wait")
	if flags.Parse(args) != nil || flags.NArg() != 0 || opts.targetText == "" {
		return catalogSubmitOptions{}, exitError{code: 64, message: "closed --target-json and valid operation flags are required"}
	}
	return validateCatalogSubmitOptions(descriptor, opts)
}

func validateCatalogSubmitOptions(descriptor opcatalog.Descriptor, opts catalogSubmitOptions) (catalogSubmitOptions, error) {
	target, arguments := json.RawMessage(opts.targetText), json.RawMessage(opts.argumentsText)
	if err := validateOperationInput(descriptor, target, arguments, opts.sealedFile, opts.credentialSlot, opts.streamFile, opts.streamMediaType); err != nil {
		return catalogSubmitOptions{}, exitError{code: 64, message: err.Error()}
	}
	if strings.TrimSpace(opts.reason) == "" || len(opts.reason) > 2000 {
		return catalogSubmitOptions{}, exitError{code: 64, message: "reason is required"}
	}
	key, err := normalizedOperationRequestID(opts.key)
	if err != nil {
		return catalogSubmitOptions{}, err
	}
	opts.key = key
	return opts, nil
}

func normalizedOperationRequestID(key string) (string, error) {
	if key == "" {
		return operationRequestID()
	}
	key = strings.TrimSpace(key)
	if !agentv1.ValidIdempotencyKey(key) {
		return "", exitError{code: 64, message: "request-id is invalid"}
	}
	return key, nil
}

func waitForSubmittedOperation(ctx context.Context, client *agentclient.Client, operation agentv1.Operation, opts catalogSubmitOptions) (agentv1.Operation, error) {
	if !opts.wait || operation.State.Terminal() {
		return operation, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, opts.waitTimeout)
	defer cancel()
	waited, err := client.Wait(waitCtx, operation)
	if err != nil && waitCtx.Err() == nil {
		return operation, err
	}
	return waited, nil
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
	operation, err := executeOperationLifecycle(ctx, client, action, flags.Arg(0), *timeout)
	if err != nil {
		return err
	}
	return writeJSONOutput(stdout, operation)
}

func executeOperationLifecycle(ctx context.Context, client *agentclient.Client, action, id string, timeout time.Duration) (agentv1.Operation, error) {
	if action == "cancel" {
		return client.Cancel(ctx, id)
	}
	operation, err := client.Get(ctx, id)
	if err != nil || action != "wait" || operation.State.Terminal() {
		return operation, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return client.Wait(waitCtx, operation)
}

func runStream(ctx context.Context, stdout io.Writer, args []string) error {
	id, output, err := parseStreamDownloadArgs(args)
	if err != nil {
		return err
	}
	connection, err := loadOperationConnection(os.Getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	if err := connection.downloadStream(ctx, id, output); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, output)
	return err
}

func parseStreamDownloadArgs(args []string) (string, string, error) {
	flags := flag.NewFlagSet("stream download", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "destination file")
	if len(args) < 2 || args[0] != "download" || flags.Parse(args[2:]) != nil || flags.NArg() != 0 || *output == "" {
		return "", "", exitError{code: 64, message: "usage: gh-broker stream download <id> --output <path>"}
	}
	return args[1], *output, nil
}

func (connection operationConnection) downloadStream(ctx context.Context, id, output string) error {
	response, err := connection.openStreamDownload(ctx, id)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if !validStreamDownloadResponse(response) {
		return errors.New("broker rejected stream download")
	}
	temporary, err := writeStreamDownloadTemp(response, output)
	if err != nil {
		return err
	}
	// #nosec G703 -- temporary is returned by CreateTemp in the output directory.
	defer func() { _ = os.Remove(temporary) }()
	// #nosec G703 -- both paths are the validated output and its sibling CreateTemp result.
	if err := os.Rename(temporary, output); err != nil {
		return errors.New("replace stream output")
	}
	return nil
}

func (connection operationConnection) openStreamDownload(ctx context.Context, id string) (*http.Response, error) {
	base, err := url.Parse(connection.baseURL)
	if err != nil {
		return nil, err
	}
	// #nosec G704 -- ParseBaseURL accepted an explicit HTTP(S) broker origin and the path is fixed.
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base.String(), "/")+"/api/agent/v1/streams/"+url.PathEscape(id), http.NoBody)
	if err != nil {
		return nil, errors.New("create stream download request")
	}
	request.Header.Set("Authorization", "Bearer "+connection.secret)
	// #nosec G704 -- the validated broker origin is intentional; Secure disables credential-forwarding redirects.
	response, err := connection.streamClient(10 * time.Minute).Do(request)
	if err != nil {
		return nil, errors.New("download stream")
	}
	return response, nil
}

func validStreamDownloadResponse(response *http.Response) bool {
	return response.StatusCode == http.StatusOK && response.ContentLength > 0 && response.ContentLength <= maxStreamDownloadBytes
}

func writeStreamDownloadTemp(response *http.Response, output string) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(output), ".gh-broker-stream-*")
	if err != nil {
		return "", errors.New("create stream output")
	}
	temporary := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		// #nosec G703 -- temporary is the name returned by CreateTemp above.
		_ = os.Remove(temporary)
		return "", errors.New("secure stream output")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxStreamDownloadBytes+1))
	closeErr := file.Close()
	if !validStreamDownloadBody(response, hash.Sum(nil), written, copyErr, closeErr) {
		// #nosec G703 -- temporary is the name returned by CreateTemp above.
		_ = os.Remove(temporary)
		return "", errors.New("stream download failed integrity validation")
	}
	return temporary, nil
}

func validStreamDownloadBody(response *http.Response, digest []byte, written int64, copyErr, closeErr error) bool {
	return copyErr == nil && closeErr == nil && written == response.ContentLength && written <= maxStreamDownloadBytes &&
		hex.EncodeToString(digest) == response.Header.Get("X-Broker-Content-SHA256")
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

func validateOperationInput(descriptor opcatalog.Descriptor, target, public json.RawMessage, sealedFile, credentialSlot, streamFile, streamMediaType string) error {
	validator := validatorForOperationInput(descriptor)
	return validator(descriptor, target, public, sealedFile, credentialSlot, streamFile, streamMediaType)
}

func validatorForOperationInput(descriptor opcatalog.Descriptor) operationInputValidator {
	if streamDirectionForOperation(descriptor.Name) == "upload" {
		return validateStreamOperationInput
	}
	if descriptor.CredentialOutputKind != nil {
		return validateCredentialOperationInput
	}
	if descriptor.Sealed {
		return validateSealedOperationInputWrapper
	}
	return validatePlainOperationInput
}

func validateNonStreamFlags(streamFile, streamMediaType string) error {
	if streamFile != "" || streamMediaType != "" {
		return errors.New("operation does not accept a stream upload")
	}
	return nil
}

func validateCredentialOperationInput(descriptor opcatalog.Descriptor, target, public json.RawMessage, sealedFile, credentialSlot, streamFile, streamMediaType string) error {
	if err := validateNonStreamFlags(streamFile, streamMediaType); err != nil {
		return err
	}
	if sealedFile != "" || !credentialstore.ValidSlot(credentialSlot) {
		return errors.New("credential output operation requires --credential-slot and does not accept --sealed-file")
	}
	return schemaregistry.ValidatePublicSubmission(descriptor.Name, target, public)
}

func validateSealedOperationInputWrapper(descriptor opcatalog.Descriptor, target, public json.RawMessage, sealedFile, credentialSlot, streamFile, streamMediaType string) error {
	if err := validateNonStreamFlags(streamFile, streamMediaType); err != nil {
		return err
	}
	return validateSealedOperationInput(descriptor, target, public, sealedFile, credentialSlot)
}

func validatePlainOperationInput(descriptor opcatalog.Descriptor, target, public json.RawMessage, sealedFile, credentialSlot, streamFile, streamMediaType string) error {
	if err := validateNonStreamFlags(streamFile, streamMediaType); err != nil {
		return err
	}
	if sealedFile != "" || credentialSlot != "" {
		return errors.New("operation does not accept --sealed-file")
	}
	return schemaregistry.ValidateSubmission(descriptor.Name, target, public)
}

func validateStreamOperationInput(descriptor opcatalog.Descriptor, target, public json.RawMessage, sealedFile, credentialSlot, streamFile, streamMediaType string) error {
	if streamFile == "" || strings.TrimSpace(streamMediaType) == "" || sealedFile != "" || credentialSlot != "" {
		return errors.New("stream upload operation requires --stream-file and --stream-media-type")
	}
	return schemaregistry.ValidateStreamPublic(descriptor.Name, target, public)
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
	request, err := connection.newUploadRequest(ctx, "/api/agent/v1/sealed-payloads", operation, requestKey, bytes.NewReader(payload), int64(len(payload)), "application/octet-stream")
	if err != nil {
		return sealedstore.Reference{}, errors.New("create sealed payload request")
	}
	response, err := connection.streamClient(30 * time.Second).Do(request)
	if err != nil {
		return sealedstore.Reference{}, errors.New("upload sealed payload")
	}
	defer func() { _ = response.Body.Close() }()
	var reference sealedstore.Reference
	if err := decodeCreatedReference(response, &reference, "broker rejected sealed payload"); err != nil {
		return sealedstore.Reference{}, err
	}
	if reference.ID == "" || reference.Purpose != operation || reference.RequestKey != requestKey {
		return sealedstore.Reference{}, errors.New("broker returned an invalid sealed payload reference")
	}
	return reference, nil
}

func (connection operationConnection) uploadStream(ctx context.Context, operation, requestKey, path, mediaType string) (streamstore.Reference, error) {
	file, size, err := openStreamUploadFile(operation, path)
	if err != nil {
		return streamstore.Reference{}, err
	}
	defer func() { _ = file.Close() }()
	request, err := connection.newUploadRequest(ctx, "/api/agent/v1/streams", operation, requestKey, file, size, mediaType)
	if err != nil {
		return streamstore.Reference{}, errors.New("create stream upload request")
	}
	response, err := connection.streamClient(10 * time.Minute).Do(request)
	if err != nil {
		return streamstore.Reference{}, errors.New("upload stream")
	}
	defer func() { _ = response.Body.Close() }()
	var reference streamstore.Reference
	if err := decodeCreatedReference(response, &reference, "broker rejected stream upload"); err != nil {
		return streamstore.Reference{}, err
	}
	if !validStreamUploadReference(reference, operation, requestKey) {
		return streamstore.Reference{}, errors.New("broker rejected stream upload")
	}
	return reference, nil
}

func openStreamUploadFile(operation, path string) (*os.File, int64, error) {
	limit, err := streamUploadLimit(operation)
	if err != nil {
		return nil, 0, err
	}
	file, err := os.Open(path) // #nosec G304 -- explicit caller-selected upload file.
	if err != nil {
		return nil, 0, errors.New("stream upload file could not be read")
	}
	info, err := file.Stat()
	if err != nil || !validStreamUploadFile(info, limit) {
		_ = file.Close()
		return nil, 0, errors.New("stream upload file exceeds its bounded size")
	}
	return file, info.Size(), nil
}

func streamUploadLimit(operation string) (int64, error) {
	bindings := opbinding.ByOperation(operation)
	if len(bindings) != 1 || bindings[0].StreamDirection != "upload" {
		return 0, errors.New("GitHub stream upload operation is invalid")
	}
	return bindings[0].RequestBytesLimit, nil
}

func validStreamUploadFile(info os.FileInfo, limit int64) bool {
	return info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= limit
}

func validStreamUploadReference(reference streamstore.Reference, operation, requestKey string) bool {
	return reference.Owner != "" && reference.Purpose == operation && reference.RequestKey == requestKey
}

func (connection operationConnection) newUploadRequest(ctx context.Context, path, operation, requestKey string, body io.Reader, size int64, mediaType string) (*http.Request, error) {
	base, err := url.Parse(connection.baseURL)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base.String(), "/")+path, body)
	if err != nil {
		return nil, err
	}
	request.ContentLength = size
	request.Header.Set("Authorization", "Bearer "+connection.secret)
	request.Header.Set("Content-Type", mediaType)
	request.Header.Set("X-Broker-Operation", operation)
	request.Header.Set("X-Broker-Idempotency-Key", requestKey)
	return request, nil
}

func decodeCreatedReference[T any](response *http.Response, reference *T, rejectMessage string) error {
	data, readErr := httpx.ReadLimited(response.Body, 1<<20)
	if readErr != nil || response.StatusCode != http.StatusCreated || strictjson.Decode(data, reference, true) != nil {
		return errors.New(rejectMessage)
	}
	return nil
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
