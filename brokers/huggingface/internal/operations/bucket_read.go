package operations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/authorization/grants"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type bucketReadClient interface {
	BucketInfo(context.Context, hubclient.BucketRef) (hubclient.BucketInfo, error)
	ListBuckets(context.Context, string, string, int) ([]hubclient.BucketInfo, error)
	ListBucketTree(context.Context, hubclient.BucketRef, string, bool, int) ([]hubclient.BucketTreeEntry, error)
	BucketObjectInfo(context.Context, hubclient.BucketRef, string) (hubclient.BucketTreeEntry, error)
	ReadBucketObject(context.Context, hubclient.BucketRef, string) (hubclient.BucketObject, error)
}

type bucketReadAdapter struct {
	descriptor opcatalog.Descriptor
	client     bucketReadClient
	authorize  RepositoryAuthorization
}

type bucketListArguments struct {
	Search string `json:"search,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type bucketObjectListArguments struct {
	Prefix    string `json:"prefix,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

type bucketObjectReadArguments struct {
	Path string `json:"path"`
}

func NewBucketReadAdapters(client bucketReadClient, authorize RepositoryAuthorization) ([]Adapter, error) {
	if client == nil || authorize == nil {
		return nil, errors.New("Hugging Face bucket read client is required")
	}
	return adaptersForNames([]string{"bucket.list", "bucket.metadata.read", "bucket.object.list", "bucket.object.read"}, func(descriptor opcatalog.Descriptor) Adapter {
		return &bucketReadAdapter{descriptor: descriptor, client: client, authorize: authorize}
	})
}

func (a *bucketReadAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *bucketReadAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	decodeTarget := decodeBucketTarget
	if a.descriptor.Name == "bucket.list" {
		decodeTarget = decodeBucketListTarget
	}
	return decodeInput(targetRaw, argumentsRaw, decodeTarget, func(_ bucketTarget, raw json.RawMessage) (any, error) {
		return a.decodeArguments(raw)
	})
}

func decodeBucketListTarget(raw json.RawMessage) (bucketTarget, error) {
	return decodeValidated(raw, maxTargetBytes, func(target bucketTarget) bool {
		return validBucketTarget(target) || target.Kind == "bucket" && target.Name == "*" &&
			hubclient.ValidNamespaceSegment(target.Namespace)
	}, "bucket list target must contain an exact namespace and an exact name or *")
}

func (a *bucketReadAdapter) decodeArguments(raw json.RawMessage) (any, error) {
	switch a.descriptor.Name {
	case "bucket.list":
		value, err := decodeValidated(raw, maxArgumentsBytes, func(value bucketListArguments) bool {
			return value.Limit >= 0 && value.Limit <= 100 && len(value.Search) <= 128 && !strings.ContainsRune(value.Search, 0)
		}, "bucket list arguments are invalid")
		if value.Limit == 0 {
			value.Limit = 100
		}
		return value, err
	case "bucket.metadata.read":
		return decodeEmptyArguments(raw, "bucket metadata arguments must be empty")
	case "bucket.object.list":
		value, err := decodeValidated(raw, maxArgumentsBytes, validBucketObjectListArguments, "bucket object list arguments are invalid")
		if value.Limit == 0 {
			value.Limit = 100
		}
		return value, err
	case "bucket.object.read":
		return decodeValidatedArguments(raw, func(value bucketObjectReadArguments) bool {
			return validBucketObjectPath(value.Path)
		}, "bucket object read arguments are invalid")
	default:
		return nil, errors.New("bucket read operation is not implemented")
	}
}

func validBucketObjectListArguments(value bucketObjectListArguments) bool {
	prefix := strings.TrimSuffix(value.Prefix, "/")
	return value.Limit >= 0 && value.Limit <= 1000 &&
		(value.Prefix == "" || validBucketObjectPath(prefix))
}

func validBucketObjectPath(value string) bool {
	if value == "" || len(value) > 1024 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.ContainsAny(value, "\\\x00") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (a *bucketReadAdapter) Resolve(_ context.Context, input Input) (Plan, error) {
	target, err := a.decodePlanTarget(input.Target)
	if err != nil {
		return Plan{}, err
	}
	presentation, request := a.presentationAndPolicy(target, input.Arguments)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision,
		Target: input.Target, Arguments: input.Arguments, Preconditions: json.RawMessage(`{}`),
		Presentation: presentation, Policy: request}, nil
}

func (a *bucketReadAdapter) decodePlanTarget(raw json.RawMessage) (bucketTarget, error) {
	if a.descriptor.Name == "bucket.list" {
		return decodeBucketListTarget(raw)
	}
	return decodeBucketTarget(raw)
}

func (a *bucketReadAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, a.reconstruct(plan))
}

func (a *bucketReadAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, a.reconstruct(plan))
}

func (a *bucketReadAdapter) BindReservation(plan Plan, grant grants.Grant) (Plan, error) {
	plan.ReservedGrant = &grant
	return plan, nil
}

func (a *bucketReadAdapter) reconstruct(plan Plan) reconstructedPlan {
	target, err := a.decodePlanTarget(plan.Target)
	if err != nil {
		return reconstructedPlan{}
	}
	presentation, request := a.presentationAndPolicy(target, plan.Arguments)
	return reconstructedPlan{presentation: presentation, request: request}
}

func (a *bucketReadAdapter) presentationAndPolicy(target bucketTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{
		Kind: hfpolicy.KindBucket, Owner: target.Namespace, Name: target.Name,
	}}
	summary := fmt.Sprintf("%s on bucket %s/%s", a.descriptor.Name, target.Namespace, target.Name)
	switch a.descriptor.Name {
	case "bucket.object.list":
		var arguments bucketObjectListArguments
		if decodeClosed(raw, &arguments, maxArgumentsBytes) == nil && arguments.Prefix != "" {
			request.Target.Keys = []string{strings.TrimSuffix(arguments.Prefix, "/")}
		}
	case "bucket.object.read":
		var arguments bucketObjectReadArguments
		if decodeClosed(raw, &arguments, maxArgumentsBytes) == nil {
			request.Target.Keys = []string{arguments.Path}
			summary = fmt.Sprintf("Read %s from bucket %s/%s", arguments.Path, target.Namespace, target.Name)
		}
	}
	return agentv1.Presentation{Title: "Read Hugging Face bucket", Summary: summary}, request
}

func (a *bucketReadAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, err := a.decodePlanTarget(plan.Target)
	if err != nil {
		return Outcome{}, err
	}
	result, err := a.executeResult(ctx, plan, target)
	if err != nil {
		return Outcome{}, err
	}
	encoded, err := canonical(result)
	return Outcome{Proven: err == nil, Result: encoded}, err
}

func (a *bucketReadAdapter) executeResult(ctx context.Context, plan Plan, target bucketTarget) (any, error) {
	switch a.descriptor.Name {
	case "bucket.list":
		return a.readBucketList(ctx, plan, target)
	case "bucket.metadata.read":
		info, err := a.client.BucketInfo(ctx, target.ref())
		return projectBucketInfo(info), err
	case "bucket.object.list":
		return a.readObjectList(ctx, plan, target)
	case "bucket.object.read":
		return a.readObject(ctx, plan, target)
	default:
		return nil, errors.New("bucket read operation is not implemented")
	}
}

func (a *bucketReadAdapter) readBucketList(ctx context.Context, plan Plan, target bucketTarget) (any, error) {
	var arguments bucketListArguments
	if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
		return nil, errors.New("bucket list plan is invalid")
	}
	var values []hubclient.BucketInfo
	var err error
	if target.Name == "*" {
		values, err = a.client.ListBuckets(ctx, target.Namespace, arguments.Search, arguments.Limit)
	} else {
		var value hubclient.BucketInfo
		value, err = a.client.BucketInfo(ctx, target.ref())
		values = []hubclient.BucketInfo{value}
	}
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		parts := strings.Split(value.ID, "/")
		if len(parts) != 2 || !a.authorize(plan.Policy.Client, hfpolicy.Operation("bucket.list"),
			hfpolicy.Target{Kind: hfpolicy.KindBucket, Owner: parts[0], Name: parts[1]}, plan.ReservedGrant) {
			continue
		}
		result = append(result, projectBucketInfo(value))
	}
	return map[string]any{"buckets": result}, nil
}

func (a *bucketReadAdapter) readObjectList(ctx context.Context, plan Plan, target bucketTarget) (any, error) {
	var arguments bucketObjectListArguments
	if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
		return nil, errors.New("bucket object list plan is invalid")
	}
	values, err := a.client.ListBucketTree(ctx, target.ref(), arguments.Prefix, arguments.Recursive, arguments.Limit)
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		candidate := hfpolicy.Target{Kind: hfpolicy.KindBucket, Owner: target.Namespace, Name: target.Name, Keys: []string{value.Path}}
		if !a.authorize(plan.Policy.Client, hfpolicy.OpBucketObjectList, candidate, plan.ReservedGrant) {
			continue
		}
		result = append(result, projectBucketEntry(value))
	}
	return map[string]any{"bucket": target.Namespace + "/" + target.Name, "prefix": arguments.Prefix, "entries": result}, nil
}

func (a *bucketReadAdapter) readObject(ctx context.Context, plan Plan, target bucketTarget) (any, error) {
	var arguments bucketObjectReadArguments
	if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
		return nil, errors.New("bucket object read plan is invalid")
	}
	metadata, err := a.client.BucketObjectInfo(ctx, target.ref(), arguments.Path)
	if err != nil {
		return nil, err
	}
	object, err := a.client.ReadBucketObject(ctx, target.ref(), arguments.Path)
	if err != nil {
		return nil, err
	}
	encoding, content := "base64", base64.StdEncoding.EncodeToString(object.Content)
	if utf8.Valid(object.Content) {
		encoding, content = "utf-8", string(object.Content)
	}
	return map[string]any{"bucket": target.Namespace + "/" + target.Name, "path": object.Path,
		"size": metadata.Size, "xet_hash": metadata.XetHash, "content_type": object.ContentType,
		"encoding": encoding, "content": content}, nil
}

func (a *bucketReadAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	return a.Execute(ctx, plan)
}

func projectBucketInfo(info hubclient.BucketInfo) map[string]any {
	return map[string]any{"id": info.ID, "private": info.Private, "created_at": info.CreatedAt,
		"updated_at": info.UpdatedAt, "size": info.Size, "total_files": info.TotalFiles}
}

func projectBucketEntry(entry hubclient.BucketTreeEntry) map[string]any {
	result := map[string]any{"type": entry.Type, "path": entry.Path}
	if entry.Type == "file" {
		result["size"], result["xet_hash"] = entry.Size, entry.XetHash
	}
	if entry.MTime != "" {
		result["mtime"] = entry.MTime
	}
	if entry.UploadedAt != "" {
		result["uploaded_at"] = entry.UploadedAt
	}
	return result
}
