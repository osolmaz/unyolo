package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type bucketClient interface {
	WhoAmI(context.Context) (hubclient.Identity, error)
	BucketInfo(context.Context, hubclient.BucketRef) (hubclient.BucketInfo, error)
	ApplyBucketBatch(context.Context, hubclient.BucketRef, []hubclient.BucketBatchOperation) error
	MoveBucket(context.Context, hubclient.BucketRef, hubclient.BucketRef) error
}

type bucketAdapter struct {
	descriptor opcatalog.Descriptor
	client     bucketClient
}

type bucketTarget struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type bucketBatchArguments struct {
	Operations []hubclient.BucketBatchOperation `json:"operations"`
}

type bucketDeleteArguments struct {
	Path string `json:"path"`
}

type bucketMoveArguments struct {
	ToNamespace string `json:"to_namespace"`
	ToName      string `json:"to_name"`
}

type bucketPreconditions struct {
	CredentialIdentity string `json:"credential_identity"`
	SourceDigest       string `json:"source_digest"`
	DestinationAbsent  bool   `json:"destination_absent,omitempty"`
}

var bucketAdapterNames = []string{"bucket.batch.apply", "bucket.move", "bucket.object.delete", "bucket.sync.apply"}

func NewBucketAdapters(client bucketClient) ([]Adapter, error) {
	return adaptersForClient(client == nil, "Hugging Face bucket client is required", bucketAdapterNames, func(descriptor opcatalog.Descriptor) Adapter {
		return &bucketAdapter{descriptor: descriptor, client: client}
	})
}

func (a *bucketAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *bucketAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	var target bucketTarget
	if err := decodeClosed(targetRaw, &target, maxTargetBytes); err != nil || !validBucketTarget(target) {
		return Input{}, errors.New("bucket target must contain an exact namespace and name")
	}
	arguments, err := a.decodeArguments(argumentsRaw)
	if err != nil {
		return Input{}, err
	}
	canonicalTarget, _ := canonical(target)
	canonicalArguments, _ := canonical(arguments)
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
}

//nolint:cyclop // Operation-kind decoding is explicit and tracked by the exact HF CRAP baseline.
func (a *bucketAdapter) decodeArguments(raw json.RawMessage) (any, error) {
	switch a.descriptor.Name {
	case "bucket.batch.apply", "bucket.sync.apply":
		var value bucketBatchArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || hubclient.ValidateBucketBatchOperations(value.Operations) != nil {
			return nil, errors.New("bucket batch arguments are invalid")
		}
		return value, nil
	case "bucket.object.delete":
		var value bucketDeleteArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || hubclient.ValidateBucketBatchOperations(deleteBucketOperation(value.Path)) != nil {
			return nil, errors.New("bucket object deletion arguments are invalid")
		}
		return value, nil
	case "bucket.move":
		var value bucketMoveArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || (hubclient.BucketRef{Namespace: value.ToNamespace, Name: value.ToName}).Validate() != nil {
			return nil, errors.New("bucket move destination is invalid")
		}
		return value, nil
	default:
		return nil, errors.New("bucket operation is not implemented")
	}
}

func (a *bucketAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	target, err := decodeBucketTarget(input.Target)
	if err != nil {
		return Plan{}, err
	}
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return Plan{}, err
	}
	info, err := a.client.BucketInfo(ctx, target.ref())
	if err != nil {
		return Plan{}, err
	}
	preconditions := bucketPreconditions{CredentialIdentity: identity.Name, SourceDigest: bucketInfoDigest(info)}
	if a.descriptor.Name == "bucket.move" {
		destination, destinationErr := decodeBucketMove(input.Arguments)
		if destinationErr != nil {
			return Plan{}, destinationErr
		}
		if destination.ref() == target.ref() {
			return Plan{}, errors.New("bucket move destination must differ from its source")
		}
		if _, destinationErr = a.client.BucketInfo(ctx, destination.ref()); !hubclient.IsNotFound(destinationErr) {
			if destinationErr != nil {
				return Plan{}, destinationErr
			}
			return Plan{}, errors.New("operation target already exists")
		}
		preconditions.DestinationAbsent = true
	}
	encoded, _ := canonical(preconditions)
	presentation, request := a.presentationAndPolicy(target, input.Arguments)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encoded, Presentation: presentation, Policy: request}, nil
}

func (a *bucketAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, reconstructPlan(plan.Target, plan.Arguments, decodeBucketTarget, a.presentationAndPolicy))
}

func (a *bucketAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, reconstructPlan(plan.Target, plan.Arguments, decodeBucketTarget, a.presentationAndPolicy))
}

func (a *bucketAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, preconditions, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	if err := a.checkPreconditions(ctx, target, plan.Arguments, preconditions); err != nil {
		return Outcome{}, err
	}
	switch a.descriptor.Name {
	case "bucket.batch.apply", "bucket.sync.apply":
		var arguments bucketBatchArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.ApplyBucketBatch(ctx, target.ref(), arguments.Operations)
	case "bucket.object.delete":
		var arguments bucketDeleteArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.ApplyBucketBatch(ctx, target.ref(), deleteBucketOperation(arguments.Path))
	case "bucket.move":
		var destination bucketMoveArguments
		_ = decodeClosed(plan.Arguments, &destination, maxArgumentsBytes)
		err = a.client.MoveBucket(ctx, target.ref(), hubclient.BucketRef{Namespace: destination.ToNamespace, Name: destination.ToName})
	}
	if err != nil {
		return Outcome{}, err
	}
	result, _ := canonical(map[string]any{"operation": a.descriptor.Name, "updated": true})
	return Outcome{Proven: true, Result: result}, nil
}

func (a *bucketAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	if a.descriptor.Name != "bucket.move" {
		return Outcome{Proven: false}, nil
	}
	target, _, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	destination, err := decodeBucketMove(plan.Arguments)
	if err != nil {
		return Outcome{}, err
	}
	_, sourceErr := a.client.BucketInfo(ctx, target.ref())
	_, destinationErr := a.client.BucketInfo(ctx, destination.ref())
	if sourceErr != nil && !hubclient.IsNotFound(sourceErr) {
		return Outcome{}, sourceErr
	}
	if destinationErr != nil && !hubclient.IsNotFound(destinationErr) {
		return Outcome{}, destinationErr
	}
	proven := hubclient.IsNotFound(sourceErr) && destinationErr == nil
	return Outcome{Proven: proven, Result: json.RawMessage(`{"moved":true}`)}, nil
}

func (a *bucketAdapter) decodePlan(plan Plan) (bucketTarget, bucketPreconditions, error) {
	return decodePlanState(plan, decodeBucketTarget, maxTargetBytes,
		func(value bucketPreconditions) bool {
			return value.CredentialIdentity != "" && value.SourceDigest != ""
		},
		"operation plan preconditions are invalid")
}

func (a *bucketAdapter) checkPreconditions(ctx context.Context, target bucketTarget, raw json.RawMessage, expected bucketPreconditions) error {
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return err
	}
	info, err := a.client.BucketInfo(ctx, target.ref())
	if err != nil {
		return err
	}
	if identity.Name != expected.CredentialIdentity || bucketInfoDigest(info) != expected.SourceDigest {
		return errors.New("operation_precondition_failed")
	}
	if expected.DestinationAbsent {
		destination, decodeErr := decodeBucketMove(raw)
		if decodeErr != nil {
			return decodeErr
		}
		if _, destinationErr := a.client.BucketInfo(ctx, destination.ref()); !hubclient.IsNotFound(destinationErr) {
			if destinationErr != nil {
				return destinationErr
			}
			return errors.New("operation_precondition_failed")
		}
	}
	return nil
}

func (a *bucketAdapter) presentationAndPolicy(target bucketTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{Kind: hfpolicy.KindBucket, Owner: target.Namespace, Name: target.Name}, Attrs: map[string]any{}}
	summary := fmt.Sprintf("%s on bucket %s/%s", a.descriptor.Name, target.Namespace, target.Name)
	if a.descriptor.Name == "bucket.move" {
		var destination bucketMoveArguments
		if decodeClosed(raw, &destination, maxArgumentsBytes) == nil {
			request.Attrs["to_namespace"] = destination.ToNamespace
			request.Attrs["to_name"] = destination.ToName
			summary = fmt.Sprintf("Move bucket %s/%s to %s/%s", target.Namespace, target.Name, destination.ToNamespace, destination.ToName)
		}
	}
	return agentv1.Presentation{Title: a.descriptor.Name, Summary: summary}, request
}

func validBucketTarget(target bucketTarget) bool {
	return target.Kind == "bucket" && target.ref().Validate() == nil
}

func decodeBucketTarget(raw json.RawMessage) (bucketTarget, error) {
	return decodeValidated(raw, maxTargetBytes, validBucketTarget, "bucket target is invalid")
}

func decodeBucketMove(raw json.RawMessage) (bucketMoveArguments, error) {
	var destination bucketMoveArguments
	if err := decodeClosed(raw, &destination, maxArgumentsBytes); err != nil || destination.ref().Validate() != nil {
		return bucketMoveArguments{}, errors.New("bucket move destination is invalid")
	}
	return destination, nil
}

func (target bucketTarget) ref() hubclient.BucketRef {
	return hubclient.BucketRef{Namespace: target.Namespace, Name: target.Name}
}

func (destination bucketMoveArguments) ref() hubclient.BucketRef {
	return hubclient.BucketRef{Namespace: destination.ToNamespace, Name: destination.ToName}
}

func bucketInfoDigest(info hubclient.BucketInfo) string {
	return digestValue(info)
}

func deleteBucketOperation(path string) []hubclient.BucketBatchOperation {
	return []hubclient.BucketBatchOperation{{Type: "deleteFile", Path: path}}
}
