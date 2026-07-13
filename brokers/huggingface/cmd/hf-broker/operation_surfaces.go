package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/clienthttp"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/sealedstore"
	"github.com/osolmaz/brokerkit/usebudget"
)

const maxOperationInputBytes = 1 << 20

type operationClientOptions struct {
	target         json.RawMessage
	arguments      json.RawMessage
	attrs          map[string]any
	sealedFile     string
	credentialSlot string
	reason         string
	idempotencyKey string
	minutes        int
	maxUses        optionalUseFlag
	wait           bool
	waitTimeout    time.Duration
	jsonOutput     bool
}

type mcpCatalogOperationInput struct {
	Target          json.RawMessage    `json:"target"`
	Arguments       json.RawMessage    `json:"arguments"`
	Attrs           map[string]any     `json:"attrs"`
	SealedArguments json.RawMessage    `json:"sealed_arguments"`
	CredentialSlot  string             `json:"credential_slot"`
	Reason          string             `json:"reason"`
	IdempotencyKey  string             `json:"idempotency_key"`
	Minutes         int                `json:"minutes"`
	MaxUses         usebudget.Optional `json:"max_uses"`
	WaitSeconds     int                `json:"wait_seconds"`
}

func agentFacingDescriptors() []opcatalog.Descriptor {
	return capability.AgentFacing(opcatalog.MustAll())
}

func matchCLICommand(args []string) (opcatalog.Descriptor, int, bool) {
	return capability.MatchCLICommand(opcatalog.MustAll(), args)
}

func runCatalogOperation(ctx context.Context, client *agentClient, stdout, stderr io.Writer, descriptor opcatalog.Descriptor, args []string) error {
	options, err := parseOperationClientOptions(descriptor, args)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	if descriptor.AuthorizationMode == opcatalog.ModeWindow {
		return runCatalogGrant(ctx, client.grantClient, stdout, stderr, descriptor, options)
	}
	request, err := buildOperationSubmitRequest(ctx, client, descriptor, options.target, options.arguments, options.sealedFile, nil, options.credentialSlot, options.reason, options.idempotencyKey)
	if err != nil {
		return err
	}
	operation, err := client.submit(ctx, request)
	if err != nil {
		return err
	}
	printOperationStatus(stderr, operation, options.jsonOutput)
	if options.wait && !operation.State.Terminal() {
		waitCtx, cancel := context.WithTimeout(ctx, options.waitTimeout)
		defer cancel()
		operation, err = client.wait(waitCtx, operation)
		if err != nil {
			return err
		}
	}
	return printClientOperation(stdout, operation, options.jsonOutput)
}

func parseOperationClientOptions(descriptor opcatalog.Descriptor, args []string) (operationClientOptions, error) {
	options := operationClientOptions{
		arguments:   json.RawMessage(`{}`),
		attrs:       map[string]any{},
		reason:      "Run " + descriptor.Name + " through HF Broker",
		wait:        true,
		waitTimeout: defaultClientWait,
	}
	var targetJSON, targetFile, argumentsJSON, argumentsFile, attrsJSON string
	flags := flag.NewFlagSet(*descriptor.CLICommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&targetJSON, "target-json", "", "closed target JSON")
	flags.StringVar(&targetFile, "target-file", "", "file containing closed target JSON")
	flags.StringVar(&argumentsJSON, "arguments-json", "", "closed public argument JSON")
	flags.StringVar(&argumentsFile, "arguments-file", "", "file containing closed public argument JSON")
	flags.StringVar(&attrsJSON, "attrs-json", "", "window grant attributes JSON")
	flags.StringVar(&options.sealedFile, "sealed-file", "", "file containing secret argument JSON")
	flags.StringVar(&options.credentialSlot, "credential-slot", "", "encrypted destination for generated credentials")
	flags.StringVar(&options.reason, "reason", options.reason, "approval reason")
	flags.StringVar(&options.idempotencyKey, "idempotency-key", "", "stable retry key")
	flags.IntVar(&options.minutes, "minutes", 0, "window duration; omit for policy default")
	flags.Var(&options.maxUses, "max-uses", "window use count or unlimited")
	flags.BoolVar(&options.wait, "wait", true, "wait for approval and completion")
	flags.DurationVar(&options.waitTimeout, "wait-timeout", options.waitTimeout, "maximum wait")
	flags.BoolVar(&options.jsonOutput, "json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, errors.New("operation arguments are invalid")
	}
	var err error
	options.target, err = readJSONOption(targetJSON, targetFile, true)
	if err != nil {
		return options, fmt.Errorf("target: %w", err)
	}
	if argumentsJSON != "" || argumentsFile != "" {
		options.arguments, err = readJSONOption(argumentsJSON, argumentsFile, true)
		if err != nil {
			return options, fmt.Errorf("arguments: %w", err)
		}
	}
	if attrsJSON != "" {
		if err := strictjson.Decode([]byte(attrsJSON), &options.attrs, true); err != nil {
			return options, errors.New("attrs-json must be a closed JSON object")
		}
	}
	if err := validateOperationClientOptions(descriptor, options); err != nil {
		return options, err
	}
	return options, nil
}

//nolint:cyclop // Input-source validation is explicit and tracked by the exact HF CRAP baseline.
func readJSONOption(inline, path string, required bool) (json.RawMessage, error) {
	if inline != "" && path != "" {
		return nil, errors.New("inline JSON and JSON file are mutually exclusive")
	}
	var data []byte
	if path != "" {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxOperationInputBytes {
			return nil, errors.New("JSON file is unavailable or too large")
		}
		data, err = os.ReadFile(path) // #nosec G304 -- the requester explicitly selects the input file.
		if err != nil {
			return nil, errors.New("JSON file could not be read")
		}
	} else {
		data = []byte(inline)
	}
	if len(data) == 0 {
		if required {
			return nil, errors.New("JSON value is required")
		}
		return nil, nil
	}
	var object map[string]any
	if len(data) > maxOperationInputBytes || strictjson.Decode(data, &object, true) != nil || object == nil {
		return nil, errors.New("value must be one bounded JSON object")
	}
	return json.RawMessage(data), nil
}

//nolint:cyclop // Descriptor-specific validation is explicit and tracked by the exact HF CRAP baseline.
func validateOperationClientOptions(descriptor opcatalog.Descriptor, options operationClientOptions) error {
	if strings.TrimSpace(options.reason) == "" || len(options.reason) > 2000 || options.waitTimeout <= 0 {
		return errors.New("reason must contain at most 2000 characters and wait timeout must be positive")
	}
	if descriptor.AuthorizationMode == opcatalog.ModeWindow {
		if options.sealedFile != "" || options.credentialSlot != "" {
			return errors.New("window operations do not accept sealed arguments or credential slots")
		}
		if options.minutes < 0 {
			return errors.New("minutes must not be negative")
		}
		return nil
	}
	if options.minutes != 0 || options.maxUses.set || len(options.attrs) != 0 {
		return errors.New("minutes, max-uses, and attrs-json apply only to window operations")
	}
	if !descriptor.Sealed && options.sealedFile != "" {
		return errors.New("this operation does not accept sealed arguments")
	}
	if descriptor.CredentialOutputKind != nil && !credentialstore.ValidSlot(options.credentialSlot) {
		return errors.New("this operation requires a valid credential-slot")
	}
	if descriptor.CredentialOutputKind != nil && options.sealedFile != "" {
		return errors.New("credential output operations do not accept sealed input")
	}
	if descriptor.CredentialOutputKind == nil && options.credentialSlot != "" {
		return errors.New("this operation does not produce a credential")
	}
	return nil
}

func buildOperationSubmitRequest(ctx context.Context, client *agentClient, descriptor opcatalog.Descriptor, target, arguments json.RawMessage, sealedFile string, sealed json.RawMessage, credentialSlot, reason, idempotencyKey string) (agentv1.SubmitRequest, error) {
	if idempotencyKey == "" {
		var err error
		idempotencyKey, err = randomClientID()
		if err != nil {
			return agentv1.SubmitRequest{}, err
		}
	}
	if descriptor.Sealed {
		if sealedFile != "" {
			var err error
			sealed, err = readJSONOption("", sealedFile, true)
			if err != nil {
				return agentv1.SubmitRequest{}, fmt.Errorf("sealed arguments: %w", err)
			}
		}
		wrapped, err := client.wrapSealedArguments(ctx, descriptor.Name, idempotencyKey, arguments, sealed, credentialSlot)
		if err != nil {
			return agentv1.SubmitRequest{}, err
		}
		arguments = wrapped
	} else if len(sealed) != 0 {
		return agentv1.SubmitRequest{}, errors.New("this operation does not accept sealed arguments")
	}
	return agentv1.SubmitRequest{IdempotencyKey: idempotencyKey, Operation: descriptor.Name, Target: target, Arguments: arguments, Reason: strings.TrimSpace(reason)}, nil
}

func (client *agentClient) wrapSealedArguments(ctx context.Context, operation, idempotencyKey string, public, secret json.RawMessage, credentialSlot string) (json.RawMessage, error) {
	wrapper := map[string]any{"public": public}
	if credentialSlot != "" {
		wrapper["credential_slot"] = credentialSlot
	}
	if len(secret) != 0 {
		reference, err := client.uploadSealedPayload(ctx, operation, idempotencyKey, secret)
		if err != nil {
			return nil, err
		}
		wrapper["sealed_payload"] = reference
	}
	return json.Marshal(wrapper)
}

func (client *agentClient) uploadSealedPayload(ctx context.Context, operation, idempotencyKey string, payload []byte) (sealedstore.Reference, error) {
	base, err := clienthttp.ParseBaseURL(client.baseURL)
	if err != nil {
		return sealedstore.Reference{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base.String(), "/")+"/api/agent/v1/sealed-payloads", bytes.NewReader(payload))
	if err != nil {
		return sealedstore.Reference{}, errors.New("create sealed payload request")
	}
	request.Header.Set("Authorization", "Bearer "+client.secret)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Broker-Operation", operation)
	request.Header.Set("X-Broker-Idempotency-Key", idempotencyKey)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return sealedstore.Reference{}, errors.New("upload sealed payload")
	}
	defer func() { _ = response.Body.Close() }()
	data, readErr := httpx.ReadLimited(response.Body, maxOperationInputBytes)
	if readErr != nil || response.StatusCode != http.StatusCreated {
		return sealedstore.Reference{}, errors.New("broker rejected sealed payload")
	}
	var reference sealedstore.Reference
	if strictjson.Decode(data, &reference, true) != nil || reference.ID == "" || reference.Purpose != operation {
		return sealedstore.Reference{}, errors.New("broker returned an invalid sealed payload reference")
	}
	return reference, nil
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

func runCatalogGrant(ctx context.Context, client *hfGrantClient, stdout, stderr io.Writer, descriptor opcatalog.Descriptor, options operationClientOptions) error {
	var target policy.Target
	if err := strictjson.Decode(options.target, &target, true); err != nil {
		return exitError{code: 64, message: "target does not match the closed grant target schema"}
	}
	idempotencyKey := options.idempotencyKey
	if idempotencyKey == "" {
		var err error
		idempotencyKey, err = randomClientID()
		if err != nil {
			return err
		}
	}
	request := hfGrantRequest{Operation: policy.Operation(descriptor.Name), Target: target, Attrs: options.attrs,
		Minutes: options.minutes, Reason: strings.TrimSpace(options.reason), ClientRequestID: idempotencyKey}
	if options.maxUses.set {
		value := options.maxUses.limit
		request.MaxUses = &value
	}
	grant, err := requestHFGrant(ctx, client, request, grantRequestOptions{wait: options.wait, waitTimeout: options.waitTimeout})
	if err != nil {
		return err
	}
	if !options.jsonOutput {
		_, _ = fmt.Fprintf(stderr, "HF Broker grant %s: %s\n", grant.ID, grant.Status)
	}
	return printHFClientGrant(stdout, grant, options.jsonOutput)
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
		Descriptors: opcatalog.MustAll(), Schemas: catalogOperationInputSchemas,
		AttributeNames: policy.KnownAttributeNames(),
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

//nolint:cyclop // Catalog dispatch is explicit and tracked by the exact HF CRAP baseline.
func callMCPCatalogOperation(ctx context.Context, client *agentClient, descriptor opcatalog.Descriptor, raw json.RawMessage) (any, error) {
	var input mcpCatalogOperationInput
	if err := decodeMCPArguments(raw, &input); err != nil {
		return nil, err
	}
	if input.WaitSeconds < 0 || input.WaitSeconds > 900 || strings.TrimSpace(input.Reason) == "" || len(input.Reason) > 2000 {
		return nil, errors.New("reason or wait_seconds is invalid")
	}
	if descriptor.AuthorizationMode == opcatalog.ModeWindow {
		return callMCPWindowOperation(ctx, client.grantClient, descriptor, input)
	}
	if descriptor.CredentialOutputKind != nil && len(input.SealedArguments) != 0 {
		return nil, errors.New("credential output operations do not accept sealed input")
	}
	if descriptor.CredentialOutputKind != nil && !credentialstore.ValidSlot(input.CredentialSlot) {
		return nil, errors.New("credential_slot is required")
	}
	if descriptor.CredentialOutputKind == nil && input.CredentialSlot != "" {
		return nil, errors.New("this operation does not produce a credential")
	}
	if !descriptor.Sealed && len(input.SealedArguments) != 0 {
		return nil, errors.New("this operation does not accept sealed arguments")
	}
	request, err := buildOperationSubmitRequest(ctx, client, descriptor, input.Target, input.Arguments, "", input.SealedArguments, input.CredentialSlot, input.Reason, input.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	operation, err := submitAndMaybeWait(ctx, client, request, input.WaitSeconds > 0, time.Duration(input.WaitSeconds)*time.Second)
	if ctx.Err() != nil && operation.ID != "" {
		return operation, nil
	}
	return operation, err
}

func callMCPWindowOperation(ctx context.Context, client *hfGrantClient, descriptor opcatalog.Descriptor, input mcpCatalogOperationInput) (hfClientGrant, error) {
	if len(input.Arguments) != 0 || len(input.SealedArguments) != 0 || input.CredentialSlot != "" || input.Minutes < 0 {
		return hfClientGrant{}, errors.New("window operation arguments are invalid")
	}
	var target policy.Target
	if strictjson.Decode(input.Target, &target, true) != nil {
		return hfClientGrant{}, errors.New("target does not match the closed grant target schema")
	}
	request := hfGrantRequest{Operation: policy.Operation(descriptor.Name), Target: target, Attrs: input.Attrs,
		Minutes: input.Minutes, Reason: strings.TrimSpace(input.Reason), ClientRequestID: input.IdempotencyKey}
	if input.MaxUses.Specified {
		value := input.MaxUses.Limit
		request.MaxUses = &value
	}
	grant, err := client.Request(ctx, request)
	if err != nil || input.WaitSeconds == 0 || grant.Status != "pending" {
		return grant, err
	}
	return waitForMCPGrant(ctx, client, grant.ID, time.Duration(input.WaitSeconds)*time.Second)
}
