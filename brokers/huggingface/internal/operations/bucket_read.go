package operations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/authorization/grants"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/internal/storage/stream"
)

const (
	maxInlineBucketObjectBytes = int64(256 << 10)
	maxStreamBucketObjectBytes = int64(512 << 20)
)

type bucketReadClient interface {
	BucketInfo(context.Context, hubclient.BucketRef) (hubclient.BucketInfo, error)
	ListBuckets(context.Context, string, string, int) ([]hubclient.BucketInfo, error)
	ListBucketTree(context.Context, hubclient.BucketRef, string, bool, int) ([]hubclient.BucketTreeEntry, error)
	BucketObjectInfo(context.Context, hubclient.BucketRef, string) (hubclient.BucketTreeEntry, error)
	ReadBucketObject(context.Context, hubclient.BucketRef, string) (hubclient.BucketObject, error)
	OpenBucketObject(context.Context, hubclient.BucketRef, string) (hubclient.BucketObjectReader, error)
}

type bucketReadStreamStore interface {
	Put(string, string, string, string, io.Reader, int64, time.Time) (streamstore.Reference, error)
	Delete(streamstore.Reference) error
}

type bucketReadAdapter struct {
	descriptor opcatalog.Descriptor
	client     bucketReadClient
	authorize  RepositoryAuthorization
	streams    bucketReadStreamStore
	now        func() time.Time
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

func NewBucketReadAdapters(client bucketReadClient, authorize RepositoryAuthorization, streams bucketReadStreamStore, now func() time.Time) ([]Adapter, error) {
	if client == nil || authorize == nil || streams == nil {
		return nil, errors.New("bucket read dependencies are required")
	}
	if now == nil {
		now = time.Now
	}
	return adaptersForNames([]string{"bucket.list", "bucket.metadata.read", "bucket.object.list", "bucket.object.read"},
		newBucketReadAdapterFactory(client, authorize, streams, now))
}

func newBucketReadAdapterFactory(client bucketReadClient, authorize RepositoryAuthorization, streams bucketReadStreamStore,
	now func() time.Time) func(opcatalog.Descriptor) Adapter {
	return func(descriptor opcatalog.Descriptor) Adapter {
		return &bucketReadAdapter{descriptor: descriptor, client: client, authorize: authorize, streams: streams, now: now}
	}
}

func (a *bucketReadAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *bucketReadAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	if a.descriptor.Name == "bucket.list" {
		return decodeInput(targetRaw, argumentsRaw, decodeBucketListTarget, a.decodeInputArguments)
	}
	return decodeInput(targetRaw, argumentsRaw, decodeBucketTarget, a.decodeInputArguments)
}

func (a *bucketReadAdapter) decodeInputArguments(_ bucketTarget, raw json.RawMessage) (any, error) {
	return a.decodeArguments(raw)
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
		return decodeBucketListArguments(raw)
	case "bucket.metadata.read":
		return decodeEmptyArguments(raw, "bucket metadata arguments must be empty")
	case "bucket.object.list":
		return decodeBucketObjectListArguments(raw)
	case "bucket.object.read":
		return decodeBucketObjectReadArguments(raw)
	default:
		return nil, errors.New("bucket read operation is not implemented")
	}
}

func decodeBucketListArguments(raw json.RawMessage) (bucketListArguments, error) {
	value, err := decodeValidated(raw, maxArgumentsBytes, func(value bucketListArguments) bool {
		return value.Limit >= 0 && value.Limit <= 100 && len(value.Search) <= 128 && !strings.ContainsRune(value.Search, 0)
	}, "bucket list arguments are invalid")
	if value.Limit == 0 {
		value.Limit = 100
	}
	return value, err
}

func decodeBucketObjectListArguments(raw json.RawMessage) (bucketObjectListArguments, error) {
	value, err := decodeValidated(raw, maxArgumentsBytes, validBucketObjectListArguments, "bucket object list arguments are invalid")
	if value.Limit == 0 {
		value.Limit = 100
	}
	return value, err
}

func decodeBucketObjectReadArguments(raw json.RawMessage) (any, error) {
	return decodeValidatedArguments(raw, func(value bucketObjectReadArguments) bool {
		return validBucketObjectPath(value.Path)
	}, "bucket object read arguments are invalid")
}

func validBucketObjectListArguments(value bucketObjectListArguments) bool {
	prefix := strings.TrimSuffix(value.Prefix, "/")
	return value.Limit >= 0 && value.Limit <= 1000 &&
		(value.Prefix == "" || validBucketObjectPath(prefix))
}

func validBucketObjectPath(value string) bool {
	return validBucketObjectPathShape(value) && validBucketObjectPathParts(value)
}

func validBucketObjectPathShape(value string) bool {
	return value != "" && len(value) <= 1024 && !strings.HasPrefix(value, "/") &&
		!strings.HasSuffix(value, "/") && !strings.ContainsAny(value, "\\\x00")
}

func validBucketObjectPathParts(value string) bool {
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
	return bindReadReservation(plan, grant)
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
	if metadata.Size > maxInlineBucketObjectBytes {
		return a.readObjectStream(ctx, plan, target, metadata)
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

func (a *bucketReadAdapter) readObjectStream(ctx context.Context, plan Plan, target bucketTarget, metadata hubclient.BucketTreeEntry) (any, error) {
	if err := validateBucketObjectStreamRequest(plan.Policy.Client, metadata.Size); err != nil {
		return nil, err
	}
	reader, err := a.client.OpenBucketObject(ctx, target.ref(), metadata.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Body.Close() }()
	if reader.Size >= 0 && reader.Size != metadata.Size {
		return nil, errors.New("bucket object size changed before streaming")
	}
	reference, err := a.storeBucketObjectStream(plan.Policy.Client, target, metadata, reader)
	if err != nil {
		return nil, err
	}
	return map[string]any{"bucket": target.Namespace + "/" + target.Name, "path": metadata.Path,
		"size": metadata.Size, "xet_hash": metadata.XetHash, "content_type": reader.ContentType,
		"stream": bucketStreamReference{ID: reference.ID, Owner: reference.Owner, Purpose: reference.Purpose,
			TransferID: reference.RequestKey, Digest: reference.Digest, Size: reference.Size,
			MediaType: reference.MediaType, ExpiresAt: reference.ExpiresAt}}, nil
}

func validateBucketObjectStreamRequest(client string, size int64) error {
	if size <= 0 || size > maxStreamBucketObjectBytes || client == "" {
		return errors.New("bucket object is too large for a bounded stream")
	}
	return nil
}

func (a *bucketReadAdapter) storeBucketObjectStream(client string, target bucketTarget, metadata hubclient.BucketTreeEntry,
	reader hubclient.BucketObjectReader) (streamstore.Reference, error) {
	requestKey := "bucket-read-" + digestValue(map[string]any{"client": client,
		"bucket": target.Namespace + "/" + target.Name, "path": metadata.Path, "xet_hash": metadata.XetHash})
	reference, err := a.streams.Put(client, a.descriptor.Name, requestKey, reader.ContentType,
		reader.Body, metadata.Size, a.now().Add(15*time.Minute))
	if err != nil {
		return streamstore.Reference{}, err
	}
	if reference.Size != metadata.Size {
		_ = a.streams.Delete(reference)
		return streamstore.Reference{}, errors.New("bucket object size changed while streaming")
	}
	return reference, nil
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
