package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/osolmaz/brokerkit/agent/v1"
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

func (a *bucketAdapter) decodeArguments(raw json.RawMessage) (any, error) {
	return decodeNamedArguments(a.descriptor.Name, bucketArgumentDecoders, raw, "bucket operation is not implemented")
}

var bucketArgumentDecoders = map[string]func(json.RawMessage) (any, error){
	"bucket.batch.apply":   decodeBucketBatchArguments,
	"bucket.sync.apply":    decodeBucketBatchArguments,
	"bucket.object.delete": decodeBucketDeleteArguments,
	"bucket.move":          decodeBucketMoveArguments,
}

func decodeBucketBatchArguments(raw json.RawMessage) (any, error) {
	var value bucketBatchArguments
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || hubclient.ValidateBucketBatchOperations(value.Operations) != nil {
		return nil, errors.New("bucket batch arguments are invalid")
	}
	return value, nil
}

func decodeBucketDeleteArguments(raw json.RawMessage) (any, error) {
	var value bucketDeleteArguments
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || hubclient.ValidateBucketBatchOperations(deleteBucketOperation(value.Path)) != nil {
		return nil, errors.New("bucket object deletion arguments are invalid")
	}
	return value, nil
}

func decodeBucketMoveArguments(raw json.RawMessage) (any, error) {
	var value bucketMoveArguments
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || (hubclient.BucketRef{Namespace: value.ToNamespace, Name: value.ToName}).Validate() != nil {
		return nil, errors.New("bucket move destination is invalid")
	}
	return value, nil
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
		return a.resolveBucketMove(ctx, input, target, preconditions)
	}
	encoded, _ := canonical(preconditions)
	presentation, request := a.presentationAndPolicy(target, input.Arguments)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encoded, Presentation: presentation, Policy: request}, nil
}

func (a *bucketAdapter) resolveBucketMove(ctx context.Context, input Input, target bucketTarget, preconditions bucketPreconditions) (Plan, error) {
	destination, err := decodeBucketMove(input.Arguments)
	if err != nil {
		return Plan{}, err
	}
	if destination.ref() == target.ref() {
		return Plan{}, errors.New("bucket move destination must differ from its source")
	}
	if err := a.checkBucketDestinationAbsent(ctx, destination.ref()); err != nil {
		return Plan{}, err
	}
	preconditions.DestinationAbsent = true
	encoded, _ := canonical(preconditions)
	presentation, request := a.presentationAndPolicy(target, input.Arguments)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encoded, Presentation: presentation, Policy: request}, nil
}

func (a *bucketAdapter) checkBucketDestinationAbsent(ctx context.Context, ref hubclient.BucketRef) error {
	_, err := a.client.BucketInfo(ctx, ref)
	if hubclient.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("operation target already exists")
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
	if err := bucketMoveObservationError(sourceErr, destinationErr); err != nil {
		return Outcome{}, err
	}
	proven := hubclient.IsNotFound(sourceErr) && destinationErr == nil
	return Outcome{Proven: proven, Result: json.RawMessage(`{"moved":true}`)}, nil
}

func bucketMoveObservationError(sourceErr, destinationErr error) error {
	if sourceErr != nil && !hubclient.IsNotFound(sourceErr) {
		return sourceErr
	}
	if destinationErr != nil && !hubclient.IsNotFound(destinationErr) {
		return destinationErr
	}
	return nil
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
	if !expected.DestinationAbsent {
		return nil
	}
	return a.checkBucketMovePrecondition(ctx, raw)
}

func (a *bucketAdapter) checkBucketMovePrecondition(ctx context.Context, raw json.RawMessage) error {
	destination, err := decodeBucketMove(raw)
	if err != nil {
		return err
	}
	_, err = a.client.BucketInfo(ctx, destination.ref())
	if hubclient.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("operation_precondition_failed")
}

func (a *bucketAdapter) presentationAndPolicy(target bucketTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{
		Kind: hfpolicy.KindBucket, Owner: target.Namespace, Name: target.Name, Keys: bucketOperationKeys(a.descriptor.Name, raw),
	}, Attrs: map[string]any{}}
	summary := fmt.Sprintf("%s on bucket %s/%s", a.descriptor.Name, target.Namespace, target.Name)
	if a.descriptor.Name == "bucket.move" {
		var destination bucketMoveArguments
		if decodeClosed(raw, &destination, maxArgumentsBytes) == nil {
			request.Attrs["destination"] = destination.ToNamespace + "/" + destination.ToName
			summary = fmt.Sprintf("Move bucket %s/%s to %s/%s", target.Namespace, target.Name, destination.ToNamespace, destination.ToName)
		}
	}
	return agentv1.Presentation{Title: a.descriptor.Name, Summary: summary}, request
}

func bucketOperationKeys(operation string, raw json.RawMessage) []string {
	if operation == "bucket.object.delete" {
		var arguments bucketDeleteArguments
		if decodeClosed(raw, &arguments, maxArgumentsBytes) == nil {
			return []string{arguments.Path}
		}
		return nil
	}
	if operation != "bucket.batch.apply" && operation != "bucket.sync.apply" {
		return nil
	}
	var arguments bucketBatchArguments
	if decodeClosed(raw, &arguments, maxArgumentsBytes) != nil {
		return nil
	}
	keys := make([]string, len(arguments.Operations))
	for index := range arguments.Operations {
		keys[index] = arguments.Operations[index].Path
	}
	return keys
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
