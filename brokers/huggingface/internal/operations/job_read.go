package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
)

type jobReadClient interface {
	ListJobs(context.Context, string, hubclient.JobListOptions) (hubclient.JobPage, error)
	ReadJob(context.Context, string, string) (hubclient.JobSummary, error)
}

type jobReadAdapter struct {
	descriptor opcatalog.Descriptor
	client     jobReadClient
	now        func() time.Time
}

type jobTarget struct {
	Kind  hfpolicy.TargetKind `json:"kind"`
	Owner string              `json:"owner"`
	Name  string              `json:"name"`
}

type jobListArguments struct {
	Stages []string          `json:"stages,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
	Cursor string            `json:"cursor,omitempty"`
}

type jobResultIdentity struct {
	Provider  string `json:"provider"`
	Namespace string `json:"namespace"`
	JobID     string `json:"job_id"`
}

type jobReadResult struct {
	Identity      jobResultIdentity `json:"identity"`
	State         string            `json:"state"`
	ProviderStage string            `json:"provider_stage"`
	CreatedAt     string            `json:"created_at"`
	StartedAt     string            `json:"started_at,omitempty"`
	FinishedAt    string            `json:"finished_at,omitempty"`
	Flavor        string            `json:"flavor"`
	ObservedAt    string            `json:"observed_at"`
}

type jobListResult struct {
	Namespace  string          `json:"namespace"`
	Jobs       []jobReadResult `json:"jobs"`
	NextCursor string          `json:"next_cursor,omitempty"`
	ObservedAt string          `json:"observed_at"`
}

// NewJobReadAdapters returns the existing safe job.list and job.read
// operations backed by the official Hub Jobs API.
func NewJobReadAdapters(client jobReadClient, now func() time.Time) ([]Adapter, error) {
	if client == nil || now == nil {
		return nil, errors.New("hugging face job read client and clock are required")
	}
	return adaptersForNames([]string{"job.list", "job.read"}, func(descriptor opcatalog.Descriptor) Adapter {
		return &jobReadAdapter{descriptor: descriptor, client: client, now: now}
	})
}

func (a *jobReadAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *jobReadAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	return decodeInput(targetRaw, argumentsRaw, func(raw json.RawMessage) (jobTarget, error) {
		return decodeValidated(raw, maxTargetBytes, func(target jobTarget) bool {
			if target.Kind != hfpolicy.TargetKind("job") || !hubclient.ValidNamespaceSegment(target.Owner) {
				return false
			}
			if a.descriptor.Name == "job.list" {
				return target.Name == "*"
			}
			return hubclient.ValidJobID(target.Name)
		}, "job target must contain an exact owner and either * for list or one exact job ID")
	}, func(_ jobTarget, raw json.RawMessage) (any, error) {
		if a.descriptor.Name == "job.read" {
			return decodeEmptyArguments(raw, "job read arguments must be empty")
		}
		return decodeValidated(raw, maxArgumentsBytes, validJobListArguments, "job list arguments are invalid")
	})
}

func validJobListArguments(arguments jobListArguments) bool {
	return hubclient.ValidJobListOptions(hubclient.JobListOptions{
		Stages: arguments.Stages, Labels: arguments.Labels, Cursor: arguments.Cursor,
	})
}

func decodeJobTarget(raw json.RawMessage) (jobTarget, error) {
	var target jobTarget
	err := decodeClosed(raw, &target, maxTargetBytes)
	return target, err
}

func (a *jobReadAdapter) Resolve(_ context.Context, input Input) (Plan, error) {
	target, err := decodeJobTarget(input.Target)
	if err != nil {
		return Plan{}, errors.New("job target is invalid")
	}
	presentation, request := a.presentationAndPolicy(target)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: json.RawMessage(`{}`), Presentation: presentation, Policy: request}, nil
}

func (a *jobReadAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, a.reconstruct(plan))
}

func (a *jobReadAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, a.reconstruct(plan))
}

func (a *jobReadAdapter) BindReservation(plan Plan, reservation grants.UseReservation) (Plan, error) {
	return bindReadReservation(plan, reservation)
}

func (a *jobReadAdapter) reconstruct(plan Plan) reconstructedPlan {
	target, err := decodeJobTarget(plan.Target)
	if err != nil {
		return reconstructedPlan{}
	}
	presentation, request := a.presentationAndPolicy(target)
	return reconstructedPlan{presentation: presentation, request: request}
}

func (a *jobReadAdapter) presentationAndPolicy(target jobTarget) (agentv1.Presentation, hfpolicy.Request) {
	policyTarget := hfpolicy.Target{Kind: target.Kind, Owner: target.Owner, Name: target.Name}
	if a.descriptor.Name == "job.list" {
		return agentv1.Presentation{Title: "List Hugging Face Jobs", Summary: fmt.Sprintf("List Jobs owned by %s", target.Owner)},
			hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: policyTarget}
	}
	return agentv1.Presentation{Title: "Read Hugging Face Job", Summary: fmt.Sprintf("Read Job %s owned by %s", target.Name, target.Owner)},
		hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: policyTarget}
}

func (a *jobReadAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	var target jobTarget
	if err := decodeClosed(plan.Target, &target, maxTargetBytes); err != nil {
		return Outcome{}, errors.New("job read plan is invalid")
	}
	observed := a.now().UTC().Format(time.RFC3339Nano)
	var result any
	if a.descriptor.Name == "job.list" {
		var arguments jobListArguments
		if err := decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes); err != nil {
			return Outcome{}, errors.New("job list plan is invalid")
		}
		page, err := a.client.ListJobs(ctx, target.Owner, hubclient.JobListOptions{
			Stages: arguments.Stages, Labels: arguments.Labels, Cursor: arguments.Cursor,
		})
		if err != nil {
			return Outcome{}, err
		}
		jobs := make([]jobReadResult, len(page.Jobs))
		for index, job := range page.Jobs {
			jobs[index] = safeJobResult(job, observed)
		}
		result = jobListResult{Namespace: target.Owner, Jobs: jobs, NextCursor: page.NextCursor, ObservedAt: observed}
	} else {
		job, err := a.client.ReadJob(ctx, target.Owner, target.Name)
		if err != nil {
			return Outcome{}, err
		}
		result = safeJobResult(job, observed)
	}
	encoded, err := canonical(result)
	return Outcome{Proven: true, Result: encoded}, err
}

func (a *jobReadAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	return a.Execute(ctx, plan)
}

func safeJobResult(job hubclient.JobSummary, observed string) jobReadResult {
	return jobReadResult{
		Identity: jobResultIdentity{Provider: "huggingface", Namespace: job.Owner, JobID: job.ID},
		State:    safeJobState(job.Stage), ProviderStage: job.Stage, CreatedAt: job.CreatedAt, StartedAt: job.StartedAt,
		FinishedAt: job.FinishedAt, Flavor: job.Flavor, ObservedAt: observed,
	}
}

func safeJobState(stage string) string {
	switch stage {
	case "SCHEDULING":
		return "pending"
	case "RUNNING":
		return "running"
	case "COMPLETED":
		return "completed"
	case "ERROR":
		return "failed"
	case "CANCELED", "DELETED":
		return "canceled"
	default:
		return "unknown"
	}
}
