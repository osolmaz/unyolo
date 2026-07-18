package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentmcp"
	"github.com/osolmaz/brokerkit/brokers/github/internal/mcpcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/mcpprojection"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/mcpoperation"
	"github.com/osolmaz/brokerkit/mcpserver"
	"github.com/osolmaz/brokerkit/streamstore"
)

type mcpOperationInput struct {
	Target          json.RawMessage     `json:"target"`
	Arguments       json.RawMessage     `json:"arguments"`
	SealedArguments json.RawMessage     `json:"sealed_arguments"`
	CredentialSlot  string              `json:"credential_slot"`
	StreamInput     *mcpStreamReference `json:"stream_input"`
	RequestID       string              `json:"-"`
}

type mcpStreamReference struct {
	ID         string `json:"id"`
	Owner      string `json:"owner"`
	Purpose    string `json:"purpose"`
	TransferID string `json:"transfer_id"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	MediaType  string `json:"media_type"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (reference mcpStreamReference) canonical() streamstore.Reference {
	return streamstore.Reference{ID: reference.ID, Owner: reference.Owner, Purpose: reference.Purpose,
		RequestKey: reference.TransferID, Digest: reference.Digest, Size: reference.Size,
		MediaType: reference.MediaType, ExpiresAt: reference.ExpiresAt}
}

func runMCP(ctx context.Context, getenv func(string) string, stdin io.Reader, stdout io.Writer, args []string) error {
	if len(args) != 0 {
		return exitError{code: 64, message: "usage: gh-broker mcp"}
	}
	bridge, err := newGitHubMCPBridge(getenv)
	if err != nil {
		return err
	}
	server, err := mcpserver.New(mcpserver.Config{
		Name: "gh-broker", Version: version, ListChanged: true,
		Tools: func(context.Context) ([]map[string]any, error) { return configuredMCPTools(getenv) },
		Call:  bridge.Call,
		Resources: func(context.Context) ([]map[string]any, error) {
			return []map[string]any{{"uri": "github://operations?limit=50", "name": "GitHub operation catalog", "description": "Paged exhaustive GitHub capability catalog", "mimeType": "application/json"}}, nil
		},
		ReadResource: func(_ context.Context, input mcpserver.ResourceRead) (any, error) {
			return readMCPResource(input.URI)
		},
		ErrorValue: func(err error) any { return mcpoperation.ErrorValue(err) },
	})
	if err != nil {
		return err
	}
	return server.Serve(ctx, stdin, stdout)
}

func newGitHubMCPBridge(getenv func(string) string) (*agentmcp.Bridge, error) {
	return agentmcp.New(agentmcp.Config{
		Prefix: "gh_",
		Client: func(context.Context) (*agentclient.Client, error) {
			connection, err := loadOperationConnection(getenv)
			if err != nil {
				return nil, err
			}
			return connection.client()
		},
		Select: func(tool string) (agentmcp.Selection, error) {
			descriptor, err := selectedMCPDescriptor(getenv, tool)
			return agentmcp.Selection{Operation: descriptor.Name, Provider: descriptor}, err
		},
		Prepare: func(ctx context.Context, selection agentmcp.Selection, input *agentmcp.Input) error {
			descriptor, ok := selection.Provider.(opcatalog.Descriptor)
			if !ok {
				return errors.New("invalid GitHub MCP descriptor")
			}
			return prepareGitHubMCPInput(ctx, getenv, descriptor, input)
		},
		Project: mcpprojection.ResultToMCP,
	})
}

func configuredMCPTools(getenv func(string) string) ([]map[string]any, error) {
	return mcpcatalog.Tools(mcpExposure(getenv), mcpEnabled(getenv))
}

func mcpExposure(getenv func(string) string) mcpcatalog.Exposure {
	profile := strings.TrimSpace(getenv("GH_BROKER_MCP_EXPOSURE_PROFILE"))
	exposure := mcpcatalog.Exposure{}
	switch profile {
	case "default":
		exposure = mcpcatalog.DefaultExposure()
	case "complete":
		exposure.Complete = true
	}
	exposure.Exact = append(exposure.Exact, splitCSV(getenv("GH_BROKER_MCP_EXACT_OPERATIONS"))...)
	exposure.Families = splitCSV(getenv("GH_BROKER_MCP_FAMILIES"))
	return exposure
}

func mcpEnabled(getenv func(string) string) mcpcatalog.Enabled {
	return mcpcatalog.Enabled{Client: csvSet(getenv("GH_BROKER_MCP_CLIENT_OPERATIONS")), Policy: csvSet(getenv("GH_BROKER_MCP_POLICY_OPERATIONS")), Runtime: csvSet(getenv("GH_BROKER_MCP_RUNTIME_OPERATIONS"))}
}

func splitCSV(value string) []string {
	result := []string{}
	for _, one := range strings.Split(value, ",") {
		if one = strings.TrimSpace(one); one != "" {
			result = append(result, one)
		}
	}
	return result
}
func csvSet(value string) map[string]bool {
	result := map[string]bool{}
	for _, one := range splitCSV(value) {
		result[one] = true
	}
	return result
}

func selectedMCPDescriptor(getenv func(string) string, tool string) (opcatalog.Descriptor, error) {
	selected, err := mcpcatalog.Selected(mcpExposure(getenv), mcpEnabled(getenv))
	if err != nil {
		return opcatalog.Descriptor{}, err
	}
	for _, value := range selected {
		if value.MCPTool != nil && *value.MCPTool == tool {
			return value, nil
		}
	}
	return opcatalog.Descriptor{}, errors.New("tool is not advertised for this client and deployment")
}

func prepareGitHubMCPInput(ctx context.Context, getenv func(string) string, descriptor opcatalog.Descriptor, shared *agentmcp.Input) error {
	input := mcpOperationInput{
		Target: shared.Target, Arguments: shared.Arguments, SealedArguments: shared.SealedArguments,
		CredentialSlot: shared.CredentialSlot, RequestID: shared.RequestID,
	}
	if len(shared.StreamInput) != 0 {
		var reference mcpStreamReference
		if strictjson.Decode(shared.StreamInput, &reference, true) != nil {
			return errors.New("stream_input is invalid")
		}
		input.StreamInput = &reference
	}
	canonical, err := mcpprojection.ArgumentsToCanonical(descriptor.Descriptor, input.Arguments)
	if err != nil {
		return err
	}
	input.Arguments = canonical
	connection, err := loadOperationConnection(getenv)
	if err != nil {
		return err
	}
	if err := prepareMCPArguments(ctx, descriptor, &input, connection); err != nil {
		return err
	}
	shared.Target, shared.Arguments = input.Target, input.Arguments
	return nil
}

func prepareMCPArguments(ctx context.Context, descriptor opcatalog.Descriptor, input *mcpOperationInput, connection operationConnection) error {
	switch {
	case streamDirectionForOperation(descriptor.Name) == "upload":
		return prepareMCPStreamArguments(descriptor, input)
	case descriptor.CredentialOutputKind != nil:
		return prepareMCPCredentialArguments(descriptor, input)
	case descriptor.Sealed:
		return prepareMCPSealedArguments(ctx, descriptor, input, connection)
	default:
		if len(input.SealedArguments) != 0 || input.CredentialSlot != "" || input.StreamInput != nil {
			return errors.New("operation does not accept sealed_arguments")
		}
		return schemaregistry.ValidateSubmission(descriptor.Name, input.Target, input.Arguments)
	}
}

func prepareMCPStreamArguments(descriptor opcatalog.Descriptor, input *mcpOperationInput) error {
	if input.StreamInput == nil || len(input.SealedArguments) != 0 || input.CredentialSlot != "" {
		return errors.New("stream_input is required")
	}
	if err := schemaregistry.ValidateStreamPublic(descriptor.Name, input.Target, input.Arguments); err != nil {
		return err
	}
	encoded, err := json.Marshal(map[string]any{"public": input.Arguments, "stream_input": input.StreamInput.canonical()})
	input.Arguments = encoded
	return err
}

func prepareMCPCredentialArguments(descriptor opcatalog.Descriptor, input *mcpOperationInput) error {
	if len(input.SealedArguments) != 0 || !credentialstore.ValidSlot(input.CredentialSlot) {
		return errors.New("credential_slot is required and sealed_arguments are not accepted")
	}
	if err := schemaregistry.ValidatePublicSubmission(descriptor.Name, input.Target, input.Arguments); err != nil {
		return err
	}
	encoded, err := json.Marshal(map[string]any{"public": input.Arguments, "credential_slot": input.CredentialSlot})
	input.Arguments = encoded
	return err
}

func prepareMCPSealedArguments(ctx context.Context, descriptor opcatalog.Descriptor, input *mcpOperationInput, connection operationConnection) error {
	if err := schemaregistry.ValidatePublicSubmission(descriptor.Name, input.Target, input.Arguments); err != nil {
		return err
	}
	required, err := schemaregistry.SealedArgumentsRequired(descriptor.Name)
	if err != nil {
		return err
	}
	if required && len(input.SealedArguments) == 0 {
		return errors.New("sealed_arguments are required")
	}
	if len(input.SealedArguments) == 0 {
		input.Arguments, err = json.Marshal(map[string]any{"public": input.Arguments})
		return err
	}
	if err := schemaregistry.ValidateSealedArguments(descriptor.Name, input.SealedArguments); err != nil {
		return err
	}
	input.Arguments, err = connection.wrapSealedArguments(ctx, descriptor.Name, input.RequestID, input.Arguments, input.SealedArguments)
	return err
}

func readMCPResource(uri string) (map[string]any, error) {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "github" || parsed.Host != "operations" {
		return nil, errors.New("unknown resource URI")
	}
	limit := 50
	if text := parsed.Query().Get("limit"); text != "" {
		limit, err = strconv.Atoi(text)
		if err != nil {
			return nil, errors.New("invalid resource limit")
		}
	}
	page, err := mcpcatalog.Discover(parsed.Query().Get("cursor"), limit)
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(page)
	return map[string]any{"contents": []map[string]any{{"uri": uri, "mimeType": "application/json", "text": string(data)}}}, nil
}
