// Package operations owns sudo-broker's provider-specific Agent V1 adapter.
package operations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	sudoplan "github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/operationruntime"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

const maxInputBytes = 32 * 1024

var (
	errExecutionRejected = errors.New("sudo helper rejected execution")
	errResultUnknown     = errors.New("sudo helper result is unknown")
)

type commandTarget struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type commandArguments struct {
	CommandID string                     `json:"command_id"`
	Arguments map[string]json.RawMessage `json:"arguments"`
}

// Input is the canonical requester-owned command input.
type Input struct {
	Target      json.RawMessage
	Arguments   json.RawMessage
	TargetUser  string
	CommandID   string
	CommandArgs map[string]json.RawMessage
}

// Plan is sudo-broker's resolved provider plan. Execution is populated from
// the immutable plan store and reservation fields are bound immediately before
// dispatch to the privileged helper.
type Plan struct {
	ExecutionID    string
	Target         json.RawMessage
	Arguments      json.RawMessage
	Resolved       catalog.Resolved
	Authorization  corepolicy.Request
	Command        sudoplan.Plan
	GrantID        string
	ReservationID  string
	GrantExpiresAt time.Time
}

type Adapter = operationruntime.Adapter[Input, Plan, corepolicy.Request]
type Runtime = operationruntime.Runtime[Input, Plan, corepolicy.Request]
type RuntimeOptions = operationruntime.Options[Input, Plan, corepolicy.Request]
type Preparation = operationruntime.Preparation[Plan, corepolicy.Request]

// Registry is sudo-broker's validated operation adapter registry.
type Registry struct {
	*operationruntime.Registry[Input, Plan, corepolicy.Request]
}

// NewRegistry constructs the complete sudo operation registry.
func NewRegistry(snapshot *catalog.Snapshot, helper *executorclient.Client) (*Registry, error) {
	if snapshot == nil || helper == nil {
		return nil, errors.New("sudo operation dependencies are required")
	}
	adapter := commandAdapter{snapshot: snapshot, helper: helper}
	registry, err := operationruntime.NewRegistry(operationruntime.RegistryOptions{
		Provider: "sudo",
		Descriptor: func(name string) (capability.Descriptor, bool) {
			if name != sudopolicy.OperationExecCommand {
				return capability.Descriptor{}, false
			}
			return commandDescriptor(), true
		},
	}, adapter)
	if err != nil {
		return nil, err
	}
	if err := registry.ValidateCoverage("sudo", []capability.Descriptor{commandDescriptor()}); err != nil {
		return nil, err
	}
	return &Registry{Registry: registry}, nil
}

// LoadStored reconstructs a provider plan from a validated immutable command
// plan and verifies that its original Agent V1 payload still resolves to the
// same catalog entry.
func LoadStored(operation agentv1.Operation, command sudoplan.Plan, snapshot *catalog.Snapshot) (Plan, error) {
	adapter := commandAdapter{snapshot: snapshot}
	input, err := adapter.Decode(operation.Target, operation.Arguments)
	if err != nil {
		return Plan{}, err
	}
	resolved, err := snapshot.Resolve(input.CommandID, input.TargetUser, input.CommandArgs)
	if err != nil || !storedPlanMatches(operation, command, resolved) {
		return Plan{}, errors.New("stored sudo operation does not match its immutable plan")
	}
	return Plan{ExecutionID: operation.ID, Target: cloneRaw(operation.Target), Arguments: cloneRaw(operation.Arguments),
		Resolved: resolved, Authorization: sudopolicy.Request(operation.ClientID, resolved), Command: command}, nil
}

func storedPlanMatches(operation agentv1.Operation, command sudoplan.Plan, resolved catalog.Resolved) bool {
	return command.RequestID == operation.ID &&
		command.ClientID == operation.ClientID &&
		command.Operation == operation.Operation &&
		command.CommandID == resolved.CommandID &&
		command.TargetUser == resolved.TargetUser &&
		command.CatalogDigest == resolved.CatalogDigest &&
		equalSlots(command.SlotValues, resolved.SlotValues)
}

type commandAdapter struct {
	snapshot *catalog.Snapshot
	helper   *executorclient.Client
}

func (commandAdapter) Descriptor() capability.Descriptor { return commandDescriptor() }
func (commandAdapter) RequiresApproval() bool            { return true }

func (commandAdapter) Decode(targetData, argumentData json.RawMessage) (Input, error) {
	target, err := decodeCommandTarget(targetData)
	if err != nil {
		return Input{}, err
	}
	arguments, err := decodeCommandArguments(argumentData)
	if err != nil {
		return Input{}, err
	}
	return Input{Target: cloneRaw(targetData), Arguments: cloneRaw(argumentData), TargetUser: strings.TrimSpace(target.Name),
		CommandID: strings.TrimSpace(arguments.CommandID), CommandArgs: cloneArguments(arguments.Arguments)}, nil
}

func decodeCommandTarget(data json.RawMessage) (commandTarget, error) {
	var target commandTarget
	if len(data) == 0 || len(data) > maxInputBytes || strictjson.Decode(data, &target, true) != nil ||
		target.Kind != sudopolicy.TargetUser || strings.TrimSpace(target.Name) == "" {
		return commandTarget{}, errors.New("command target must contain an exact Unix user")
	}
	return target, nil
}

func decodeCommandArguments(data json.RawMessage) (commandArguments, error) {
	var arguments commandArguments
	if len(data) == 0 || len(data) > maxInputBytes || strictjson.Decode(data, &arguments, true) != nil ||
		strings.TrimSpace(arguments.CommandID) == "" || arguments.Arguments == nil {
		return commandArguments{}, errors.New("invalid command arguments")
	}
	return arguments, nil
}

func (a commandAdapter) Resolve(_ context.Context, input Input) (Plan, error) {
	resolved, err := a.snapshot.Resolve(input.CommandID, input.TargetUser, input.CommandArgs)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Target: cloneRaw(input.Target), Arguments: cloneRaw(input.Arguments), Resolved: resolved,
		Authorization: sudopolicy.Request("", resolved)}, nil
}

func (commandAdapter) Authorize(value Plan) corepolicy.Request { return value.Authorization }

func (commandAdapter) Present(value Plan) agentv1.Presentation {
	return agentv1.Presentation{Title: "Run approved Unix command",
		Summary: fmt.Sprintf("Run %s once as %s", value.Resolved.CommandID, value.Resolved.TargetUser)}
}

func (commandAdapter) BindReservation(value Plan, grant grants.Grant) (Plan, error) {
	if grant.ID == "" || grant.Revision < 1 || grant.ExpiresAt.IsZero() || grant.ClientRequestID != value.ExecutionID {
		return Plan{}, errors.New("sudo execution reservation is invalid")
	}
	value.GrantID = grant.ID
	value.ReservationID = fmt.Sprintf("%s:r%d", grant.ID, grant.Revision)
	value.GrantExpiresAt = grant.ExpiresAt.UTC()
	return value, nil
}

func (a commandAdapter) Execute(ctx context.Context, value Plan) (operationruntime.Outcome, error) {
	if err := validateExecutionAuthority(value); err != nil {
		return operationruntime.Outcome{}, err
	}
	response, err := a.helper.Execute(ctx, value.ExecutionID, value.Command, value.GrantID, value.ReservationID, value.GrantExpiresAt)
	if err != nil {
		return helperDispatchFailure(err)
	}
	return outcomeFromHelperResponse(response)
}

func validateExecutionAuthority(value Plan) error {
	if value.ExecutionID == "" || value.GrantID == "" || value.ReservationID == "" || value.GrantExpiresAt.IsZero() {
		return errors.New("sudo execution authority is incomplete")
	}
	return nil
}

func helperDispatchFailure(err error) (operationruntime.Outcome, error) {
	if executorclient.WasDispatched(err) {
		return operationruntime.Outcome{}, &operationruntime.PossiblePartialError{Err: err}
	}
	return operationruntime.Outcome{}, err
}

func outcomeFromHelperResponse(response executorprotocol.Response) (operationruntime.Outcome, error) {
	if completedStarted(response) {
		encoded, marshalErr := json.Marshal(executionView(response))
		return operationruntime.Outcome{Proven: marshalErr == nil, Result: encoded}, marshalErr
	}
	if definitiveHelperRejection(response) {
		return operationruntime.Outcome{}, fmt.Errorf("%w: %s", errExecutionRejected, response.ErrorCode)
	}
	return operationruntime.Outcome{}, &operationruntime.PossiblePartialError{Err: fmt.Errorf("%w: %s", errResultUnknown, response.ErrorCode)}
}

func completedStarted(response executorprotocol.Response) bool {
	return response.Status == executorprotocol.StatusCompleted && response.Outcome != nil && response.Outcome.Started
}

func definitiveHelperRejection(response executorprotocol.Response) bool {
	return response.Status == executorprotocol.StatusRejected ||
		response.Status == executorprotocol.StatusCompleted && response.Outcome != nil
}

func (commandAdapter) Reconcile(context.Context, Plan) (operationruntime.Outcome, error) {
	return operationruntime.Outcome{}, errResultUnknown
}

// DefinitiveFailure reports whether the helper proved that execution did not
// cross its dispatch boundary.
func DefinitiveFailure(err error) bool {
	return err != nil && !operationruntime.IsPossiblePartial(err)
}

// ExecutionFailure maps helper details to the stable Agent V1 error surface.
func ExecutionFailure(executionErr, _ error) operationruntime.Failure {
	if errors.Is(executionErr, errExecutionRejected) {
		return operationruntime.Failure{Code: "execution_rejected", Message: "Command did not start", ReleaseApproval: true}
	}
	if executionErr != nil && !operationruntime.IsPossiblePartial(executionErr) {
		return operationruntime.Failure{Code: "helper_unavailable", Message: "Privileged helper is unavailable", ReleaseApproval: true}
	}
	return operationruntime.Failure{Code: "execution_result_unknown", Message: "Command result is unknown; it was not retried"}
}

func commandDescriptor() capability.Descriptor {
	mcpTool, cliCommand := "sudo_exec_command", "sudo-broker run"
	return capability.Descriptor{Name: sudopolicy.OperationExecCommand, OperationRevision: 1, Summary: "Run one cataloged command as a Unix user",
		Disposition: "EX", AuthorizationMode: capability.ModeExecution, ExplicitOnly: true, Implementation: capability.StatusImplemented,
		Risk: capability.RiskCritical, DefaultPolicyEffect: capability.DefaultEffectRequest, TargetKind: sudopolicy.TargetUser,
		MaxUses: 1, RequestTTLSeconds: 24 * 60 * 60, ApprovalTTLSeconds: 24 * 60 * 60, AgentFacing: true,
		MCPTool: &mcpTool, CLICommand: &cliCommand, ExecutorKind: "privileged-helper"}
}

func executionView(response executorprotocol.Response) map[string]any {
	outcome := response.Outcome
	return map[string]any{
		"id": response.ExecutionID, "started": outcome.Started, "exit_code": outcome.ExitCode, "signal": outcome.Signal,
		"timed_out": outcome.TimedOut, "truncated": outcome.Truncated, "duration_ns": outcome.Duration.Nanoseconds(),
		"stdout_base64": base64.StdEncoding.EncodeToString(outcome.Stdout), "stderr_base64": base64.StdEncoding.EncodeToString(outcome.Stderr),
	}
}

func cloneRaw(value json.RawMessage) json.RawMessage { return append(json.RawMessage(nil), value...) }

func cloneArguments(values map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(values))
	for name, value := range values {
		result[name] = cloneRaw(value)
	}
	return result
}

func equalSlots(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, value := range left {
		if right[name] != value {
			return false
		}
	}
	return true
}
