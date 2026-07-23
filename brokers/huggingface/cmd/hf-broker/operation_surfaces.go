package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/mcpprojection"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/credential/store"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/operation/capability"
)

const (
	maxOperationInputBytes = 1 << 20
	maxBucketStreamBytes   = int64(512 << 20)
)

type operationClientOptions struct {
	target         json.RawMessage
	arguments      json.RawMessage
	attrs          map[string]any
	sealedFile     string
	credentialSlot string
	sourceFile     string
	mediaType      string
	outputFile     string
	reason         string
	idempotencyKey string
	minutes        int
	maxUses        optionalUseFlag
	wait           bool
	waitTimeout    time.Duration
	jsonOutput     bool
}

type mcpCatalogOperationInput struct {
	Target          json.RawMessage `json:"target"`
	Arguments       json.RawMessage `json:"arguments"`
	Attrs           map[string]any  `json:"attrs"`
	SealedArguments json.RawMessage `json:"sealed_arguments"`
	CredentialSlot  string          `json:"credential_slot"`
	Reason          string          `json:"reason"`
	RequestID       string          `json:"request_id"`
}

type operationFlagInputs struct {
	targetJSON    string
	targetFile    string
	argumentsJSON string
	argumentsFile string
	attrsJSON     string
}

func agentFacingDescriptors() []opcatalog.Descriptor {
	return capability.AgentFacing(runtimeBoundDescriptors())
}

func runtimeBoundDescriptors() []opcatalog.Descriptor {
	all := opcatalog.MustAll()
	result := make([]opcatalog.Descriptor, 0, len(all))
	for _, descriptor := range all {
		if operations.AgentRuntimeBound(descriptor) {
			result = append(result, descriptor)
		}
	}
	return result
}

func matchCLICommand(args []string) (opcatalog.Descriptor, int, bool) {
	return capability.MatchCLICommand(runtimeBoundDescriptors(), args)
}

func runCatalogOperation(ctx context.Context, client *agentClient, stdout, stderr io.Writer, descriptor opcatalog.Descriptor, args []string) error {
	options, err := parseOperationClientOptions(descriptor, args)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	if err := prepareBucketObjectWrite(ctx, client, descriptor, &options); err != nil {
		return err
	}
	request, err := buildOperationSubmitRequest(ctx, client, descriptor, options.target, options.arguments, options.sealedFile, nil, options.credentialSlot, options.reason, options.idempotencyKey)
	if err != nil {
		return err
	}
	operation, err := submitAndReportCatalogOperation(ctx, client, stderr, request, options)
	if err != nil {
		return err
	}
	if err := materializeBucketObjectRead(ctx, client, descriptor, operation, options.outputFile); err != nil {
		return err
	}
	return printClientOperation(stdout, operation, options.jsonOutput)
}

func submitAndReportCatalogOperation(ctx context.Context, client *agentClient, stderr io.Writer, request agentv1.SubmitRequest, options operationClientOptions) (agentv1.Operation, error) {
	operation, err := client.submit(ctx, request)
	if err != nil {
		return operation, err
	}
	printOperationStatus(stderr, operation, options.jsonOutput)
	if !options.wait || operation.State.Terminal() {
		return operation, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, options.waitTimeout)
	defer cancel()
	return client.wait(waitCtx, operation)
}

func parseOperationClientOptions(descriptor opcatalog.Descriptor, args []string) (operationClientOptions, error) {
	options := operationClientOptions{
		arguments:   json.RawMessage(`{}`),
		attrs:       map[string]any{},
		reason:      "Run " + descriptor.Name + " through HF Broker",
		wait:        true,
		waitTimeout: defaultClientWait,
	}
	var inputs operationFlagInputs
	flags := flag.NewFlagSet(*descriptor.CLICommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&inputs.targetJSON, "target-json", "", "closed target JSON")
	flags.StringVar(&inputs.targetFile, "target-file", "", "file containing closed target JSON")
	flags.StringVar(&inputs.argumentsJSON, "arguments-json", "", "closed public argument JSON")
	flags.StringVar(&inputs.argumentsFile, "arguments-file", "", "file containing closed public argument JSON")
	flags.StringVar(&inputs.attrsJSON, "attrs-json", "", "window grant attributes JSON")
	flags.StringVar(&options.sealedFile, "sealed-file", "", "file containing secret argument JSON")
	flags.StringVar(&options.credentialSlot, "credential-slot", "", "encrypted destination for generated credentials")
	flags.StringVar(&options.sourceFile, "source", "", "local file for a bounded stream upload")
	flags.StringVar(&options.mediaType, "media-type", "", "stream media type; inferred from source when omitted")
	flags.StringVar(&options.outputFile, "output", "", "write bucket object content to a new local file")
	flags.StringVar(&options.reason, "reason", options.reason, "approval reason")
	flags.StringVar(&options.idempotencyKey, "request-id", "", "stable retry key")
	flags.IntVar(&options.minutes, "minutes", 0, "window duration; omit for policy default")
	flags.Var(&options.maxUses, "max-uses", "window use count or unlimited")
	flags.BoolVar(&options.wait, "wait", true, "wait for approval and completion")
	flags.DurationVar(&options.waitTimeout, "wait-timeout", options.waitTimeout, "maximum wait")
	flags.BoolVar(&options.jsonOutput, "json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, errors.New("operation arguments are invalid")
	}
	if err := readOperationFlagInputs(inputs, &options); err != nil {
		return options, err
	}
	return options, validateOperationClientOptions(descriptor, options)
}

func readOperationFlagInputs(inputs operationFlagInputs, options *operationClientOptions) error {
	var err error
	options.target, err = readJSONOption(inputs.targetJSON, inputs.targetFile, true)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if inputs.argumentsJSON != "" || inputs.argumentsFile != "" {
		options.arguments, err = readJSONOption(inputs.argumentsJSON, inputs.argumentsFile, true)
		if err != nil {
			return fmt.Errorf("arguments: %w", err)
		}
	}
	if inputs.attrsJSON != "" {
		if err := strictjson.Decode([]byte(inputs.attrsJSON), &options.attrs, true); err != nil {
			return errors.New("attrs-json must be a closed JSON object")
		}
	}
	return nil
}

func readJSONOption(inline, path string, required bool) (json.RawMessage, error) {
	if inline != "" && path != "" {
		return nil, errors.New("inline JSON and JSON file are mutually exclusive")
	}
	data, err := readJSONOptionBytes(inline, path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return emptyJSONOption(required)
	}
	return boundedJSONObject(data)
}

func emptyJSONOption(required bool) (json.RawMessage, error) {
	if required {
		return nil, errors.New("JSON value is required")
	}
	return nil, nil
}

func boundedJSONObject(data []byte) (json.RawMessage, error) {
	var object map[string]any
	if len(data) > maxOperationInputBytes || strictjson.Decode(data, &object, true) != nil || object == nil {
		return nil, errors.New("value must be one bounded JSON object")
	}
	return json.RawMessage(data), nil
}

func readJSONOptionBytes(inline, path string) ([]byte, error) {
	if path == "" {
		return []byte(inline), nil
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxOperationInputBytes {
		return nil, errors.New("JSON file is unavailable or too large")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the requester explicitly selects the input file.
	if err != nil {
		return nil, errors.New("JSON file could not be read")
	}
	return data, nil
}

func validateOperationClientOptions(descriptor opcatalog.Descriptor, options operationClientOptions) error {
	if strings.TrimSpace(options.reason) == "" || len(options.reason) > 2000 || options.waitTimeout <= 0 {
		return errors.New("reason must contain at most 2000 characters and wait timeout must be positive")
	}
	if descriptor.Name == "bucket.object.write" {
		if options.sourceFile == "" || options.sealedFile != "" || options.credentialSlot != "" {
			return errors.New("bucket.object.write requires source and does not accept sealed arguments or credential slots")
		}
	} else if options.sourceFile != "" || options.mediaType != "" {
		return errors.New("source and media-type apply only to bucket.object.write")
	}
	if options.outputFile != "" && (descriptor.Name != "bucket.object.read" || !options.wait) {
		return errors.New("output requires a waiting bucket.object.read command")
	}
	if descriptor.AuthorizationMode == opcatalog.ModeWindow {
		return validateWindowOperationClientOptions(options)
	}
	return validateExecutionOperationClientOptions(descriptor, options)
}

func prepareBucketObjectWrite(ctx context.Context, client *agentClient, descriptor opcatalog.Descriptor, options *operationClientOptions) error {
	if descriptor.Name != "bucket.object.write" {
		return nil
	}
	requestID, err := resolveClientRequestID(options.idempotencyKey)
	if err != nil {
		return err
	}
	options.idempotencyKey = requestID
	file, err := os.Open(options.sourceFile) // #nosec G304 -- the requester explicitly selects the upload source.
	if err != nil {
		return errors.New("source file is unavailable")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBucketStreamBytes {
		return errors.New("source file is empty, unavailable, or too large")
	}
	mediaType := options.mediaType
	if mediaType == "" {
		mediaType = mime.TypeByExtension(filepath.Ext(options.sourceFile))
		if mediaType == "" {
			mediaType = "application/octet-stream"
		}
	}
	reference, err := client.operations.UploadStream(ctx, descriptor.Name, requestID, mediaType, file, info.Size(), maxBucketStreamBytes)
	if err != nil {
		return err
	}
	var public map[string]any
	if strictjson.Decode(options.arguments, &public, true) != nil || public == nil {
		return errors.New("bucket object write arguments must be one JSON object")
	}
	wrapped, err := json.Marshal(map[string]any{"public": public, "stream_input": map[string]any{
		"id": reference.ID, "owner": reference.Owner, "purpose": reference.Purpose,
		"transfer_id": reference.RequestKey, "digest": reference.Digest, "size": reference.Size,
		"media_type": reference.MediaType, "expires_at": reference.ExpiresAt,
	}})
	if err != nil {
		return errors.New("could not bind bucket object stream")
	}
	options.arguments = wrapped
	return nil
}

func materializeBucketObjectRead(ctx context.Context, client *agentClient, descriptor opcatalog.Descriptor, operation agentv1.Operation, output string) error {
	if descriptor.Name != "bucket.object.read" || output == "" {
		return nil
	}
	if operation.State != agentv1.StateSucceeded {
		return errors.New("bucket object read did not succeed")
	}
	var result struct {
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Stream   struct {
			ID string `json:"id"`
		} `json:"stream"`
	}
	if strictjson.Decode(operation.Result, &result, false) != nil {
		return errors.New("bucket object read result is invalid")
	}
	return writeNewOutputFile(output, func(destination io.Writer) error {
		if result.Stream.ID != "" {
			_, err := client.operations.DownloadStream(ctx, result.Stream.ID, destination, maxBucketStreamBytes)
			return err
		}
		var content []byte
		switch result.Encoding {
		case "utf-8":
			content = []byte(result.Content)
		case "base64":
			var err error
			content, err = base64.StdEncoding.DecodeString(result.Content)
			if err != nil {
				return errors.New("bucket object read result has invalid base64")
			}
		default:
			return errors.New("bucket object read result has no content stream")
		}
		if int64(len(content)) > maxBucketStreamBytes {
			return errors.New("bucket object read result exceeds its limit")
		}
		_, err := destination.Write(content)
		return err
	})
}

func writeNewOutputFile(path string, write func(io.Writer) error) error {
	directory, name := filepath.Dir(path), filepath.Base(path)
	file, err := os.CreateTemp(directory, "."+name+".partial-*") // #nosec G304 -- the requester explicitly selects the output directory.
	if err != nil {
		return errors.New("output file could not be created")
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if os.Chmod(temporary, 0o600) != nil || write(file) != nil || file.Sync() != nil || file.Close() != nil {
		_ = file.Close()
		return errors.New("output file could not be written")
	}
	if err := os.Link(temporary, path); err != nil {
		return errors.New("output file already exists or could not be installed")
	}
	return nil
}

func validateWindowOperationClientOptions(options operationClientOptions) error {
	if options.sealedFile != "" || options.credentialSlot != "" {
		return errors.New("window operations do not accept sealed arguments or credential slots")
	}
	if options.minutes < 0 {
		return errors.New("minutes must not be negative")
	}
	return nil
}

func validateExecutionOperationClientOptions(descriptor opcatalog.Descriptor, options operationClientOptions) error {
	if options.minutes != 0 || options.maxUses.set || len(options.attrs) != 0 {
		return errors.New("minutes, max-uses, and attrs-json apply only to window operations")
	}
	if err := validateSealedOperationClientOptions(descriptor, options); err != nil {
		return err
	}
	return validateCredentialSelection(descriptor.CredentialOutputKind != nil, options.credentialSlot, options.sealedFile != "",
		"this operation requires a valid credential-slot")
}

func validateSealedOperationClientOptions(descriptor opcatalog.Descriptor, options operationClientOptions) error {
	if !descriptor.Sealed && options.sealedFile != "" {
		return errors.New("this operation does not accept sealed arguments")
	}
	return nil
}

func buildOperationSubmitRequest(ctx context.Context, client *agentClient, descriptor opcatalog.Descriptor, target, arguments json.RawMessage, sealedFile string, sealed json.RawMessage, credentialSlot, reason, idempotencyKey string) (agentv1.SubmitRequest, error) {
	idempotencyKey, err := resolveClientRequestID(idempotencyKey)
	if err != nil {
		return agentv1.SubmitRequest{}, err
	}
	arguments, err = buildOperationArguments(ctx, client, descriptor, arguments, sealedFile, sealed, credentialSlot, idempotencyKey)
	if err != nil {
		return agentv1.SubmitRequest{}, err
	}
	return agentv1.SubmitRequest{IdempotencyKey: idempotencyKey, Operation: descriptor.Name, Target: target, Arguments: arguments, Reason: strings.TrimSpace(reason)}, nil
}

func buildOperationArguments(ctx context.Context, client *agentClient, descriptor opcatalog.Descriptor, arguments json.RawMessage, sealedFile string, sealed json.RawMessage, credentialSlot, idempotencyKey string) (json.RawMessage, error) {
	if descriptor.Sealed {
		sealed, err := readSealedArguments(sealedFile, sealed)
		if err != nil {
			return nil, err
		}
		return client.wrapSealedArguments(ctx, descriptor.Name, idempotencyKey, arguments, sealed, credentialSlot)
	} else if len(sealed) != 0 {
		return nil, errors.New("this operation does not accept sealed arguments")
	}
	return arguments, nil
}

func readSealedArguments(sealedFile string, sealed json.RawMessage) (json.RawMessage, error) {
	if sealedFile == "" {
		return sealed, nil
	}
	value, err := readJSONOption("", sealedFile, true)
	if err != nil {
		return nil, fmt.Errorf("sealed arguments: %w", err)
	}
	return value, nil
}

func (client *agentClient) wrapSealedArguments(ctx context.Context, operation, idempotencyKey string, public, secret json.RawMessage, credentialSlot string) (json.RawMessage, error) {
	wrapper := map[string]any{"public": public}
	if credentialSlot != "" {
		wrapper["credential_slot"] = credentialSlot
	}
	if len(secret) != 0 {
		reference, err := client.operations.UploadSealedPayload(ctx, operation, idempotencyKey, secret)
		if err != nil {
			return nil, err
		}
		wrapper["sealed_payload"] = reference
	}
	return json.Marshal(wrapper)
}

func submitAndMaybeWait(ctx context.Context, client *agentClient, request agentv1.SubmitRequest, wait bool, timeout time.Duration) (agentv1.Operation, error) {
	operation, err := client.submit(ctx, request)
	if err != nil || !wait || operation.State.Terminal() {
		return operation, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	updated, err := client.wait(waitCtx, operation)
	if err != nil && errors.Is(waitCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		return updated, nil
	}
	return updated, err
}

func printOperationStatus(stderr io.Writer, operation agentv1.Operation, jsonOutput bool) {
	if jsonOutput {
		return
	}
	_, _ = fmt.Fprintf(stderr, "HF Broker operation %s: %s\n", operation.ID, operation.State)
	if operation.State == agentv1.StatePending {
		_, _ = fmt.Fprintln(stderr, "Approval requested; no Hugging Face token is needed.")
	}
}

func resolveClientRequestID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		generated, err := randomClientID()
		if err != nil {
			return "", err
		}
		value = generated
	}
	if !agentv1.ValidIdempotencyKey(value) {
		return "", errors.New("request-id is invalid")
	}
	return value, nil
}

func catalogMCPTools() []map[string]any {
	return capability.MCPTools(hfSurfaceOptions())
}

func catalogMCPToolSchema(descriptor opcatalog.Descriptor) map[string]any {
	return capability.MCPToolSchema(descriptor, hfSurfaceOptions())
}

func requiredPropertyNames(schema map[string]any) []string {
	return capability.RequiredPropertyNames(schema)
}

func hfSurfaceOptions() capability.SurfaceOptions {
	return capability.SurfaceOptions{
		Descriptors: runtimeBoundDescriptors(), Schemas: catalogOperationInputSchemas,
		AttributeNames: policy.KnownAttributeNames(),
		MCPToolPrefix:  "hf_", Projections: mcpprojection.ForOperation, WindowSubmitsOperation: true,
		ToolDescription: func(descriptor capability.Descriptor) string {
			return fmt.Sprintf("Run %s through HF Broker policy and approval. Never request a Hugging Face token.", descriptor.Name)
		},
	}
}

func catalogOperationInputSchemas(descriptor opcatalog.Descriptor) (map[string]any, map[string]any, map[string]any) {
	if binding, found := opbinding.ByName(descriptor.Name); found {
		var target, arguments map[string]any
		if json.Unmarshal(binding.TargetSchema, &target) != nil || json.Unmarshal(binding.ArgumentsSchema, &arguments) != nil {
			panic("invalid pinned operation schema: " + descriptor.Name)
		}
		arguments, sealed := catalogSealedArguments(descriptor.Name, arguments)
		setTargetKind(target, descriptor.TargetKind)
		return embeddedOperationSchema(target), embeddedOperationSchema(arguments), embeddedOperationSchema(sealed)
	}
	if custom, found := operations.CustomInputSchemas(descriptor.Name); found {
		setTargetKind(custom.Target, descriptor.TargetKind)
		return custom.Target, custom.Arguments, custom.Sealed
	}
	if descriptor.AuthorizationMode == opcatalog.ModeWindow {
		target := operations.WindowTargetSchema()
		setTargetKind(target, descriptor.TargetKind)
		return target, nil, nil
	}
	panic("missing operation input schema: " + descriptor.Name)
}

func catalogSealedArguments(operation string, arguments map[string]any) (map[string]any, map[string]any) {
	paths := operations.SealedInputPaths(operation)
	if len(paths) == 0 {
		return arguments, nil
	}
	public, sealed := splitSealedArgumentsSchema(arguments, paths)
	if operations.RequiresSealedInput(operation) {
		requireSchemaPaths(sealed, paths)
	}
	return public, sealed
}

func setTargetKind(schema map[string]any, kind string) {
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return
	}
	if kindSchema, ok := properties["kind"].(map[string]any); ok {
		kindSchema["const"] = kind
	}
}

func descriptorByMCPTool(name string) (opcatalog.Descriptor, bool) {
	for _, descriptor := range agentFacingDescriptors() {
		if *descriptor.MCPTool == name {
			return descriptor, true
		}
	}
	return opcatalog.Descriptor{}, false
}

func validateMCPCatalogOperation(descriptor opcatalog.Descriptor, input mcpCatalogOperationInput) error {
	if strings.TrimSpace(input.Reason) == "" || len(input.Reason) > 2000 {
		return errors.New("reason is invalid")
	}
	if err := validateCredentialSelection(descriptor.CredentialOutputKind != nil, input.CredentialSlot, len(input.SealedArguments) != 0,
		"credential_slot is required"); err != nil {
		return err
	}
	return validateMCPSealedOperation(descriptor, input)
}

func validateCredentialSelection(hasOutput bool, slot string, hasSealedInput bool, missingSlotMessage string) error {
	if !hasOutput {
		return validateNoCredentialOutput(slot)
	}
	return validateCredentialOutput(slot, hasSealedInput, missingSlotMessage)
}

func validateNoCredentialOutput(slot string) error {
	if slot != "" {
		return errors.New("this operation does not produce a credential")
	}
	return nil
}

func validateCredentialOutput(slot string, hasSealedInput bool, missingSlotMessage string) error {
	if err := validateCredentialOutputSealedInput(hasSealedInput); err != nil {
		return err
	}
	return validateCredentialOutputSlot(slot, missingSlotMessage)
}

func validateCredentialOutputSealedInput(hasSealedInput bool) error {
	if hasSealedInput {
		return errors.New("credential output operations do not accept sealed input")
	}
	return nil
}

func validateCredentialOutputSlot(slot, missingSlotMessage string) error {
	if !credentialstore.ValidSlot(slot) {
		return errors.New(missingSlotMessage)
	}
	return nil
}

func validateMCPSealedOperation(descriptor opcatalog.Descriptor, input mcpCatalogOperationInput) error {
	if !descriptor.Sealed && len(input.SealedArguments) != 0 {
		return errors.New("this operation does not accept sealed arguments")
	}
	return nil
}
