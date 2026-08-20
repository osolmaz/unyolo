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
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/agent/client"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/unyolo/credential/store"
	"github.com/osolmaz/unyolo/internal/config/client"
	"github.com/osolmaz/unyolo/internal/operationcli"
	"github.com/osolmaz/unyolo/internal/storage/sealed"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/operation/capability"
	"github.com/osolmaz/unyolo/operation/payload"
	"github.com/osolmaz/unyolo/transport/http"
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

type operationDescription struct {
	Operation opcatalog.Descriptor            `json:"operation"`
	Schemas   schemaregistry.EffectiveSchemas `json:"schemas"`
}

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
		schemas, err := schemaregistry.EffectiveSchemasForOperation(descriptor.Name)
		if err != nil {
			return fmt.Errorf("describe GitHub operation: %w", err)
		}
		return writeJSONOutput(stdout, operationDescription{Operation: descriptor, Schemas: schemas})
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

func runOperation(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return exitError{code: 64, message: "usage: gh-broker operation <submit|get|wait|cancel>"}
	}
	switch args[0] {
	case "submit":
		return runOperationSubmit(ctx, stdout, stderr, args[1:])
	case "get", "wait", "cancel":
		return runOperationLifecycle(ctx, stdout, stderr, args[0], args[1:])
	default:
		return exitError{code: 64, message: "usage: gh-broker operation <submit|get|wait|cancel>"}
	}
}

func runOperationSubmit(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	if len(args) < 1 {
		return exitError{code: 64, message: "operation name is required"}
	}
	if isHelpArgument(args[0]) {
		return writeOperationSubmitHelp(stdout, "OPERATION")
	}
	descriptor, found := opcatalog.ByName(args[0])
	if !found || !descriptor.AgentFacing {
		return exitError{code: 64, message: "unknown agent-facing GitHub operation"}
	}
	for _, argument := range args[1:] {
		if isHelpArgument(argument) {
			return writeOperationSubmitHelp(stdout, descriptor.Name)
		}
	}
	return submitCatalogOperation(ctx, stdout, stderr, descriptor, args[1:])
}

func isHelpArgument(argument string) bool {
	return argument == "-h" || argument == "--help"
}

func writeOperationSubmitHelp(stdout io.Writer, operation string) error {
	_, err := fmt.Fprintf(stdout, `Usage:
  gh-broker operation submit %s --target-json JSON [flags]

Inspect the effective schemas before submitting:
  gh-broker operations describe %s

Flags:
  --arguments-json JSON       closed argument JSON (default {})
  --reason TEXT               approval reason
  --request-id ID             stable retry key
  --wait                      wait for a terminal state
  --wait-timeout DURATION     internal wait retry interval (default 15m)
  --sealed-file PATH          sealed argument JSON file
  --credential-slot NAME      encrypted credential destination slot
  --stream-file PATH          bounded binary upload file
  --stream-media-type TYPE    binary upload media type
`, operation, operation)
	return err
}

func runGeneratedCLI(ctx context.Context, stdout, stderr io.Writer, args []string) (bool, error) {
	descriptor, consumed, found := capability.MatchCLICommand(opcatalog.CapabilityDescriptors(opcatalog.MustAll()), args)
	if !found {
		return false, nil
	}
	providerDescriptor, found := opcatalog.ByName(descriptor.Name)
	if !found {
		return true, errors.New("GitHub operation catalog drifted")
	}
	return true, submitCatalogOperation(ctx, stdout, stderr, providerDescriptor, args[consumed:])
}

func submitCatalogOperation(ctx context.Context, stdout, stderr io.Writer, descriptor opcatalog.Descriptor, args []string) error {
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
	operation, waitErr := waitForSubmittedOperation(ctx, client, operation, opts)
	failed, err := writeOperationOutput(stdout, stderr, operation, submitOperationIntent(opts.wait), opts.waitTimeout)
	if err != nil {
		return err
	}
	if waitErr != nil {
		return waitErr
	}
	if failed {
		return exitError{code: 1}
	}
	return nil
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
	flags.DurationVar(&opts.waitTimeout, "wait-timeout", opts.waitTimeout, "internal wait retry interval")
	if flags.Parse(args) != nil || flags.NArg() != 0 || opts.targetText == "" {
		return catalogSubmitOptions{}, exitError{code: 64, message: "closed --target-json and valid operation flags are required"}
	}
	return validateCatalogSubmitOptions(descriptor, opts)
}

func validateCatalogSubmitOptions(descriptor opcatalog.Descriptor, opts catalogSubmitOptions) (catalogSubmitOptions, error) {
	target, arguments := json.RawMessage(opts.targetText), json.RawMessage(opts.argumentsText)
	if err := validateOperationInput(descriptor, target, arguments, opts.sealedFile, opts.credentialSlot, opts.streamFile, opts.streamMediaType); err != nil {
		message := fmt.Sprintf(`%s; request not submitted; do not retry unchanged input; inspect with "gh-broker operations describe %s"`, err, descriptor.Name)
		return catalogSubmitOptions{}, exitError{code: 64, message: message}
	}
	if strings.TrimSpace(opts.reason) == "" || len(opts.reason) > 2000 {
		return catalogSubmitOptions{}, exitError{code: 64, message: "reason is required"}
	}
	if opts.waitTimeout <= 0 {
		return catalogSubmitOptions{}, exitError{code: 64, message: "wait timeout must be positive"}
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
	return client.WaitDurably(ctx, operation, opts.waitTimeout)
}

func prepareCLIArguments(ctx context.Context, connection operationConnection, descriptor opcatalog.Descriptor, key string, arguments json.RawMessage,
	sealedFile, credentialSlot, streamFile, streamMediaType string) (json.RawMessage, error) {
	switch {
	case streamDirectionForOperation(descriptor.Name) == "upload":
		reference, err := connection.uploadStream(ctx, descriptor.Name, key, streamFile, streamMediaType)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"public": arguments, "stream_input": map[string]any{
			"id": reference.ID, "owner": reference.Owner, "purpose": reference.Purpose,
			"request_key": reference.TransferID, "digest": reference.Digest, "size": reference.Size,
			"media_type": reference.MediaType, "expires_at": reference.ExpiresAt,
		}})
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

func runOperationLifecycle(ctx context.Context, stdout, stderr io.Writer, action string, args []string) error {
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	timeout := flags.Duration("wait-timeout", operationWaitDefault, "internal wait retry interval")
	if flags.Parse(args) != nil || flags.NArg() != 1 {
		return exitError{code: 64, message: "operation ID is required"}
	}
	if *timeout <= 0 {
		return exitError{code: 64, message: "wait timeout must be positive"}
	}
	client, err := loadOperationClient(os.Getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	operation, operationErr := executeOperationLifecycle(ctx, client, action, flags.Arg(0), *timeout)
	if operation.ID == "" {
		return operationErr
	}
	failed, err := writeOperationOutput(stdout, stderr, operation, lifecycleOperationIntent(action), *timeout)
	if err != nil {
		return err
	}
	if operationErr != nil {
		return operationErr
	}
	if failed {
		return exitError{code: 1}
	}
	return nil
}

func executeOperationLifecycle(ctx context.Context, client *agentclient.Client, action, id string, timeout time.Duration) (agentv1.Operation, error) {
	if action == "cancel" {
		return client.Cancel(ctx, id)
	}
	operation, err := client.Get(ctx, id)
	if err != nil || action != "wait" || operation.State.Terminal() {
		return operation, err
	}
	return client.WaitDurably(ctx, operation, timeout)
}

func submitOperationIntent(wait bool) operationcli.Intent {
	if wait {
		return operationcli.IntentSubmitWait
	}
	return operationcli.IntentSubmit
}

func lifecycleOperationIntent(action string) operationcli.Intent {
	switch action {
	case "get":
		return operationcli.IntentGet
	case "wait":
		return operationcli.IntentWait
	case "cancel":
		return operationcli.IntentCancel
	default:
		panic("unsupported operation lifecycle action")
	}
}

func writeOperationOutput(stdout, stderr io.Writer, operation agentv1.Operation, intent operationcli.Intent, timeout time.Duration) (bool, error) {
	presentation, err := operationcli.Describe(intent, operation, []string{
		"gh-broker", "operation", "wait", "--wait-timeout", operationcli.WaitTimeoutArgument(timeout), operation.ID,
	})
	if err != nil {
		return false, err
	}
	if err := writeJSONOutput(stdout, operation); err != nil {
		return false, err
	}
	if _, err := io.WriteString(stderr, presentation.Notice); err != nil {
		return false, err
	}
	return presentation.CommandFailed, nil
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
	client, err := connection.client()
	if err != nil {
		return err
	}
	temporary, err := writeStreamDownloadTemp(ctx, client, id, output)
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

func writeStreamDownloadTemp(ctx context.Context, client *agentclient.Client, id, output string) (string, error) {
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
	_, copyErr := client.DownloadStream(ctx, id, file, maxStreamDownloadBytes)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		// #nosec G703 -- temporary is the name returned by CreateTemp above.
		_ = os.Remove(temporary)
		return "", errors.New("stream download failed integrity validation")
	}
	return temporary, nil
}

func loadOperationClient(getenv func(string) string) (*agentclient.Client, error) {
	connection, err := loadOperationConnection(getenv)
	if err != nil {
		return nil, err
	}
	return connection.client()
}

type operationConnection struct {
	endpoint   string
	secret     string
	httpClient *http.Client
}

func loadOperationConnection(getenv func(string) string) (operationConnection, error) {
	home := strings.TrimSpace(getenv("HOME"))
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return operationConnection{}, errors.New("GH Broker client home is unavailable")
		}
	}
	configured, err := clientconfig.Resolve(home, "gh-broker", "GH_BROKER", getenv)
	if err != nil {
		return operationConnection{}, err
	}
	httpClient, err := configured.HTTPClient()
	if err != nil {
		return operationConnection{}, err
	}
	if _, err := agentclient.New(agentclient.Options{Endpoint: configured.AgentEndpoint, Credential: configured.SharedSecret, HTTPClient: httpClient}); err != nil {
		return operationConnection{}, err
	}
	return operationConnection{endpoint: configured.AgentEndpoint, secret: configured.SharedSecret, httpClient: httpClient}, nil
}

func (connection operationConnection) client() (*agentclient.Client, error) {
	return agentclient.New(agentclient.Options{Endpoint: connection.endpoint, Credential: connection.secret, HTTPClient: connection.httpClient})
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
	client, err := connection.client()
	if err != nil {
		return sealedstore.Reference{}, err
	}
	return client.UploadSealedPayload(ctx, operation, requestKey, payload)
}

func (connection operationConnection) uploadStream(ctx context.Context, operation, requestKey, path, mediaType string) (agentv1.StreamReference, error) {
	file, size, limit, err := openStreamUploadFile(operation, path)
	if err != nil {
		return agentv1.StreamReference{}, err
	}
	defer func() { _ = file.Close() }()
	client, err := connection.client()
	if err != nil {
		return agentv1.StreamReference{}, err
	}
	return client.UploadStream(ctx, operation, requestKey, mediaType, file, size, limit)
}

func openStreamUploadFile(operation, path string) (*os.File, int64, int64, error) {
	limit, err := streamUploadLimit(operation)
	if err != nil {
		return nil, 0, 0, err
	}
	file, err := os.Open(path) // #nosec G304 -- explicit caller-selected upload file.
	if err != nil {
		return nil, 0, 0, errors.New("stream upload file could not be read")
	}
	info, err := file.Stat()
	if err != nil || !validStreamUploadFile(info, limit) {
		_ = file.Close()
		return nil, 0, 0, errors.New("stream upload file exceeds its bounded size")
	}
	return file, info.Size(), limit, nil
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
