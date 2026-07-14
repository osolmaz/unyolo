// Package agentv1wire translates generated Agent V1 wire models and domain types.
package agentv1wire

import (
	"encoding/json"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/internal/optional"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/protocol/agentwire"
)

func SubmitToWire(input agentv1.SubmitRequest) (agentwire.SubmitRequest, error) {
	target, err := decodeObject(input.Target)
	if err != nil {
		return agentwire.SubmitRequest{}, err
	}
	arguments, err := decodeObject(input.Arguments)
	if err != nil {
		return agentwire.SubmitRequest{}, err
	}
	return agentwire.SubmitRequest{IdempotencyKey: input.IdempotencyKey, Operation: input.Operation, Target: target, Arguments: arguments, Reason: input.Reason}, nil
}

func SubmitFromWire(input agentwire.SubmitRequest) (agentv1.SubmitRequest, error) {
	target, err := json.Marshal(input.Target)
	if err != nil {
		return agentv1.SubmitRequest{}, err
	}
	arguments, err := json.Marshal(input.Arguments)
	if err != nil {
		return agentv1.SubmitRequest{}, err
	}
	return agentv1.SubmitRequest{IdempotencyKey: input.IdempotencyKey, Operation: input.Operation, Target: target, Arguments: arguments, Reason: input.Reason}, nil
}

func OperationToWire(input agentv1.Operation) (agentwire.Operation, error) {
	target, err := decodeObject(input.Target)
	if err != nil {
		return agentwire.Operation{}, err
	}
	arguments, err := decodeObject(input.Arguments)
	if err != nil {
		return agentwire.Operation{}, err
	}
	result := agentwire.Operation{ApiVersion: agentwire.OperationApiVersionBrokerkitIoagentv1, Id: input.ID, Broker: input.Broker,
		ClientId: input.ClientID, IdempotencyKey: input.IdempotencyKey, Operation: input.Operation, Target: target, Arguments: arguments,
		Reason: input.Reason, State: agentwire.State(input.State), Revision: int(input.Revision), ApprovalId: optional.NonZero(input.ApprovalID),
		CreatedAt: input.CreatedAt, UpdatedAt: input.UpdatedAt, TerminalAt: input.TerminalAt,
		PlanDigest:   optional.NonZero(input.PlanDigest),
		Presentation: agentwire.Presentation{Title: input.Presentation.Title, Summary: optional.NonZero(input.Presentation.Summary)}}
	if len(input.Result) > 0 {
		value, err := decodeObject(input.Result)
		if err != nil {
			return agentwire.Operation{}, err
		}
		result.Result = &value
	}
	if input.Error != nil {
		result.Error = &agentwire.OperationError{Code: input.Error.Code, Message: input.Error.Message}
	}
	return result, nil
}

func OperationFromWire(input agentwire.Operation) (agentv1.Operation, error) {
	target, err := json.Marshal(input.Target)
	if err != nil {
		return agentv1.Operation{}, err
	}
	arguments, err := json.Marshal(input.Arguments)
	if err != nil {
		return agentv1.Operation{}, err
	}
	result := agentv1.Operation{APIVersion: string(input.ApiVersion), ID: input.Id, Broker: input.Broker, ClientID: input.ClientId,
		IdempotencyKey: input.IdempotencyKey, Operation: input.Operation, Target: target, Arguments: arguments, Reason: input.Reason,
		State: agentv1.State(input.State), Revision: int64(input.Revision), ApprovalID: optional.Value(input.ApprovalId), CreatedAt: input.CreatedAt,
		UpdatedAt: input.UpdatedAt, TerminalAt: input.TerminalAt, PlanDigest: optional.Value(input.PlanDigest),
		Presentation: agentv1.Presentation{Title: input.Presentation.Title, Summary: optional.Value(input.Presentation.Summary)}}
	if input.Result != nil {
		result.Result, err = json.Marshal(*input.Result)
		if err != nil {
			return agentv1.Operation{}, err
		}
	}
	if input.Error != nil {
		result.Error = &agentv1.OperationError{Code: input.Error.Code, Message: input.Error.Message}
	}
	return result, nil
}

func OperationPageToWire(input agentv1.OperationPage) agentwire.OperationPage {
	operations := make([]agentwire.OperationSummary, 0, len(input.Operations))
	for _, operation := range input.Operations {
		operations = append(operations, operationSummaryToWire(operation))
	}
	return agentwire.OperationPage{
		ApiVersion: agentwire.OperationPageApiVersionBrokerkitIoagentv1,
		Operations: operations, NextCursor: input.NextCursor,
	}
}

func OperationPageFromWire(input agentwire.OperationPage) agentv1.OperationPage {
	operations := make([]agentv1.OperationSummary, 0, len(input.Operations))
	for _, operation := range input.Operations {
		operations = append(operations, operationSummaryFromWire(operation))
	}
	return agentv1.OperationPage{APIVersion: string(input.ApiVersion), Operations: operations, NextCursor: input.NextCursor}
}

func operationSummaryToWire(input agentv1.OperationSummary) agentwire.OperationSummary {
	return agentwire.OperationSummary{
		ApiVersion: agentwire.OperationSummaryApiVersionBrokerkitIoagentv1,
		Id:         input.ID, Broker: input.Broker, ClientId: input.ClientID, IdempotencyKey: input.IdempotencyKey,
		Operation: input.Operation, State: agentwire.State(input.State), Revision: int(input.Revision),
		CreatedAt: input.CreatedAt, UpdatedAt: input.UpdatedAt, TerminalAt: input.TerminalAt,
		Presentation: agentwire.Presentation{Title: input.Presentation.Title, Summary: optional.NonZero(input.Presentation.Summary)},
	}
}

func operationSummaryFromWire(input agentwire.OperationSummary) agentv1.OperationSummary {
	return agentv1.OperationSummary{
		APIVersion: string(input.ApiVersion), ID: input.Id, Broker: input.Broker, ClientID: input.ClientId,
		IdempotencyKey: input.IdempotencyKey, Operation: input.Operation, State: agentv1.State(input.State),
		Revision: int64(input.Revision), CreatedAt: input.CreatedAt, UpdatedAt: input.UpdatedAt,
		TerminalAt:   input.TerminalAt,
		Presentation: agentv1.Presentation{Title: input.Presentation.Title, Summary: optional.Value(input.Presentation.Summary)},
	}
}

func decodeObject(raw []byte) (map[string]interface{}, error) {
	value := map[string]interface{}{}
	if err := strictjson.Decode(raw, &value, false); err != nil {
		return nil, err
	}
	return value, nil
}
