package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/credentialstore"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

type credentialOutputClient interface {
	boundClient
	ExecuteBoundResult(context.Context, string, json.RawMessage, json.RawMessage) (json.RawMessage, error)
}

type credentialSlotStore interface {
	Put(string, string, []byte) (credentialstore.Metadata, error)
}

type credentialOutputAdapter struct {
	*sealedBoundAdapter
	client credentialOutputClient
	store  credentialSlotStore
	kind   string
}

func NewCredentialOutputAdapters(client credentialOutputClient, payloads sealedPayloadStore, slots credentialSlotStore) ([]Adapter, error) {
	if client == nil || payloads == nil || slots == nil {
		return nil, errors.New("Hugging Face credential output dependencies are required")
	}
	var adapters []Adapter
	for _, descriptor := range opcatalog.MustAll() {
		if descriptor.CredentialOutputKind == nil {
			continue
		}
		binding, bound := opbinding.ByName(descriptor.Name)
		if !bound || !descriptor.Sealed || descriptor.AuthorizationMode != opcatalog.ModeExecution {
			return nil, fmt.Errorf("credential output operation %q is not registered", descriptor.Name)
		}
		base := &sealedBoundAdapter{descriptor: descriptor, binding: binding, client: client, store: payloads}
		adapters = append(adapters, &credentialOutputAdapter{sealedBoundAdapter: base, client: client, store: slots, kind: *descriptor.CredentialOutputKind})
	}
	return adapters, nil
}

func (a *credentialOutputAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	var arguments sealedBoundArguments
	if decodeClosed(argumentsRaw, &arguments, maxArgumentsBytes) != nil || !credentialstore.ValidSlot(arguments.CredentialSlot) || arguments.SealedPayload != nil {
		return Input{}, errors.New("credential output operation requires one valid destination slot")
	}
	arguments.CredentialSlot = ""
	baseRaw, _ := canonical(arguments)
	input, err := a.sealedBoundAdapter.Decode(targetRaw, baseRaw)
	if err != nil {
		return Input{}, err
	}
	arguments.CredentialSlot = decodeCredentialSlot(argumentsRaw)
	input.Arguments, err = canonical(arguments)
	return input, err
}

func (a *credentialOutputAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	slot := decodeCredentialSlot(input.Arguments)
	arguments := withoutCredentialSlot(input.Arguments)
	input.Arguments = arguments
	plan, err := a.sealedBoundAdapter.Resolve(ctx, input)
	if err != nil {
		return Plan{}, err
	}
	var wrapped sealedBoundArguments
	_ = decodeClosed(plan.Arguments, &wrapped, maxArgumentsBytes)
	wrapped.CredentialSlot = slot
	plan.Arguments, _ = canonical(wrapped)
	plan.Presentation.Summary += fmt.Sprintf(" into broker credential slot %s", slot)
	if plan.Policy.Attrs == nil {
		plan.Policy.Attrs = map[string]any{}
	}
	plan.Policy.Attrs["credential_slot"] = slot
	plan.Policy.Attrs["credential_kind"] = a.kind
	return plan, nil
}

func (a *credentialOutputAdapter) Authorize(plan Plan) hfpolicy.Request {
	slot := decodeCredentialSlot(plan.Arguments)
	withoutSlot := plan
	withoutSlot.Arguments = withoutCredentialSlot(plan.Arguments)
	request := a.sealedBoundAdapter.Authorize(withoutSlot)
	if request.Attrs == nil {
		request.Attrs = map[string]any{}
	}
	request.Attrs["credential_slot"] = slot
	request.Attrs["credential_kind"] = a.kind
	return request
}

func (a *credentialOutputAdapter) Present(plan Plan) agentv1.Presentation { return plan.Presentation }

func (a *credentialOutputAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	slot := decodeCredentialSlot(plan.Arguments)
	if !credentialstore.ValidSlot(slot) {
		return Outcome{}, errors.New("credential output plan has an invalid destination slot")
	}
	withoutSlot := plan
	withoutSlot.Arguments = withoutCredentialSlot(plan.Arguments)
	merged, err := a.prepareExecution(ctx, withoutSlot)
	if err != nil {
		return Outcome{}, err
	}
	response, err := a.client.ExecuteBoundResult(ctx, a.descriptor.Name, plan.Target, merged)
	if err != nil {
		return Outcome{}, err
	}
	defer zero(response)
	secret, metadata, err := extractCredentialOutput(a.descriptor.Name, response)
	if err != nil {
		return Outcome{}, err
	}
	defer zero(secret)
	stored, err := a.store.Put(slot, a.kind, secret)
	if err != nil {
		return Outcome{}, errors.New("upstream_result_unknown")
	}
	result, _ := canonical(map[string]any{"stored": true, "slot": stored.Slot, "kind": stored.Kind, "upstream": metadata})
	return Outcome{Proven: true, Result: result}, nil
}

// Generated credentials cannot be reconstructed from a later metadata read.
// A crash before the encrypted slot write therefore remains ambiguous.
func (a *credentialOutputAdapter) Reconcile(context.Context, Plan) (Outcome, error) {
	return Outcome{Proven: false}, nil
}

func decodeCredentialSlot(raw json.RawMessage) string {
	var arguments sealedBoundArguments
	if decodeClosed(raw, &arguments, maxArgumentsBytes) != nil {
		return ""
	}
	return arguments.CredentialSlot
}

func withoutCredentialSlot(raw json.RawMessage) json.RawMessage {
	var arguments sealedBoundArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	arguments.CredentialSlot = ""
	encoded, _ := canonical(arguments)
	return encoded
}

func extractCredentialOutput(operation string, raw json.RawMessage) ([]byte, map[string]any, error) {
	if operation == "provisioning.resource.credentials.rotate" {
		var response struct {
			Status   string `json:"status"`
			ID       string `json:"id"`
			Complete struct {
				AccessConfiguration map[string]any `json:"access_configuration"`
			} `json:"complete"`
		}
		if strictjson.Decode(raw, &response, true) != nil || response.Status != "complete" || response.ID == "" || response.Complete.AccessConfiguration == nil {
			return nil, nil, errors.New("upstream credential result is invalid")
		}
		secret, err := canonical(response.Complete.AccessConfiguration)
		return secret, map[string]any{"resource_id": response.ID}, err
	}
	var response struct {
		Token     string `json:"token"`
		TokenInfo struct {
			ID          string   `json:"_id"`
			DisplayName string   `json:"displayName"`
			CreatedAt   string   `json:"createdAt"`
			Last4       string   `json:"last4,omitempty"`
			Permissions []string `json:"permissions,omitempty"`
		} `json:"tokenInfo"`
	}
	if strictjson.Decode(raw, &response, true) != nil || response.Token == "" || response.TokenInfo.ID == "" || response.TokenInfo.DisplayName == "" || response.TokenInfo.CreatedAt == "" {
		return nil, nil, errors.New("upstream credential result is invalid")
	}
	metadata := map[string]any{"token_id": response.TokenInfo.ID, "display_name": response.TokenInfo.DisplayName, "created_at": response.TokenInfo.CreatedAt}
	if response.TokenInfo.Last4 != "" {
		metadata["last4"] = response.TokenInfo.Last4
	}
	return []byte(response.Token), metadata, nil
}
