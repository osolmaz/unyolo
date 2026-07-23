package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/xetuploader"
	"github.com/osolmaz/brokerkit/internal/storage/stream"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

type bucketWriteClient interface {
	WhoAmI(context.Context) (hubclient.Identity, error)
	BucketInfo(context.Context, hubclient.BucketRef) (hubclient.BucketInfo, error)
	BucketObjectInfo(context.Context, hubclient.BucketRef, string) (hubclient.BucketTreeEntry, error)
	ApplyBucketBatch(context.Context, hubclient.BucketRef, []hubclient.BucketBatchOperation) error
}

type bucketXetUploader interface {
	Upload(context.Context, hubclient.BucketRef, *os.File, int64) (xetuploader.Result, error)
}

type bucketStreamStore interface {
	Validate(streamstore.Reference) error
	OpenStream(streamstore.Reference) (*os.File, error)
	Retire(streamstore.Reference, time.Time) error
}

type bucketObjectWriteAdapter struct {
	descriptor opcatalog.Descriptor
	client     bucketWriteClient
	uploader   bucketXetUploader
	streams    bucketStreamStore
	now        func() time.Time
}

type bucketObjectWritePublic struct {
	Path      string `json:"path"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

type bucketObjectWriteArguments struct {
	Public      json.RawMessage        `json:"public"`
	StreamInput *bucketStreamReference `json:"stream_input"`
}

type bucketStreamReference struct {
	ID         string `json:"id"`
	Owner      string `json:"owner"`
	Purpose    string `json:"purpose"`
	TransferID string `json:"transfer_id"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	MediaType  string `json:"media_type"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (reference bucketStreamReference) canonical() streamstore.Reference {
	return streamstore.Reference{ID: reference.ID, Owner: reference.Owner, Purpose: reference.Purpose,
		RequestKey: reference.TransferID, Digest: reference.Digest, Size: reference.Size,
		MediaType: reference.MediaType, ExpiresAt: reference.ExpiresAt}
}

type bucketObjectWritePreconditions struct {
	CredentialIdentity string                `json:"credential_identity"`
	BucketDigest       string                `json:"bucket_digest"`
	ExistingAbsent     bool                  `json:"existing_absent"`
	ExistingDigest     string                `json:"existing_digest,omitempty"`
	Stream             streamstore.Reference `json:"stream"`
}

func NewBucketObjectWriteAdapter(client bucketWriteClient, uploader bucketXetUploader, streams bucketStreamStore, now func() time.Time) (Adapter, error) {
	if client == nil || uploader == nil || streams == nil {
		return nil, errors.New("bucket object write dependencies are required")
	}
	descriptor, found := opcatalog.ByName("bucket.object.write")
	if !found {
		return nil, errors.New("bucket.object.write is absent from the catalog")
	}
	if now == nil {
		now = time.Now
	}
	return &bucketObjectWriteAdapter{descriptor: descriptor, client: client, uploader: uploader, streams: streams, now: now}, nil
}

func (a *bucketObjectWriteAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *bucketObjectWriteAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	target, err := decodeBucketTarget(targetRaw)
	if err != nil {
		return Input{}, err
	}
	arguments, public, err := decodeBucketObjectWriteArguments(argumentsRaw)
	if err != nil || !validBucketObjectPath(public.Path) {
		return Input{}, errors.New("bucket object write arguments are invalid")
	}
	canonicalTarget, _ := canonical(target)
	canonicalArguments, _ := canonical(arguments)
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
}

func decodeBucketObjectWriteArguments(raw json.RawMessage) (bucketObjectWriteArguments, bucketObjectWritePublic, error) {
	var arguments bucketObjectWriteArguments
	var public bucketObjectWritePublic
	if strictjson.Decode(raw, &arguments, true) != nil || arguments.StreamInput == nil || len(arguments.Public) == 0 ||
		strictjson.Decode(arguments.Public, &public, true) != nil {
		return arguments, public, errors.New("bucket object write arguments are invalid")
	}
	canonicalPublic, err := canonical(public)
	if err != nil {
		return arguments, public, err
	}
	arguments.Public = canonicalPublic
	return arguments, public, nil
}

func (a *bucketObjectWriteAdapter) ValidateClient(input Input, client, requestKey string) error {
	arguments, _, err := decodeBucketObjectWriteArguments(input.Arguments)
	if err != nil {
		return err
	}
	reference := arguments.StreamInput.canonical()
	if reference.Owner != client || reference.Purpose != a.descriptor.Name || reference.RequestKey != requestKey {
		return errors.New("stream input does not belong to this client, operation, and request")
	}
	return a.streams.Validate(reference)
}

func (a *bucketObjectWriteAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	target, err := decodeBucketTarget(input.Target)
	if err != nil {
		return Plan{}, err
	}
	arguments, public, err := decodeBucketObjectWriteArguments(input.Arguments)
	if err != nil {
		return Plan{}, err
	}
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return Plan{}, err
	}
	bucket, err := a.client.BucketInfo(ctx, target.ref())
	if err != nil {
		return Plan{}, err
	}
	preconditions := bucketObjectWritePreconditions{
		CredentialIdentity: identity.Name, BucketDigest: bucketInfoDigest(bucket), Stream: arguments.StreamInput.canonical(),
	}
	if err := a.resolveExistingPrecondition(ctx, target, public, &preconditions); err != nil {
		return Plan{}, err
	}
	encoded, _ := canonical(preconditions)
	presentation, request := bucketWritePresentationAndPolicy(target, public)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision,
		Target: input.Target, Arguments: input.Arguments, Preconditions: encoded,
		Presentation: presentation, Policy: request}, nil
}

func (a *bucketObjectWriteAdapter) resolveExistingPrecondition(ctx context.Context, target bucketTarget,
	public bucketObjectWritePublic, preconditions *bucketObjectWritePreconditions) error {
	existing, err := a.client.BucketObjectInfo(ctx, target.ref(), public.Path)
	if hubclient.IsNotFound(err) {
		preconditions.ExistingAbsent = true
		return nil
	}
	if err != nil {
		return err
	}
	if !public.Overwrite {
		return errors.New("operation target already exists and overwrite was not approved")
	}
	preconditions.ExistingDigest = digestValue(existing)
	return nil
}

func (a *bucketObjectWriteAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, a.reconstruct(plan))
}

func (a *bucketObjectWriteAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, a.reconstruct(plan))
}

func (a *bucketObjectWriteAdapter) reconstruct(plan Plan) reconstructedPlan {
	target, err := decodeBucketTarget(plan.Target)
	if err != nil {
		return reconstructedPlan{}
	}
	_, public, err := decodeBucketObjectWriteArguments(plan.Arguments)
	if err != nil {
		return reconstructedPlan{}
	}
	presentation, request := bucketWritePresentationAndPolicy(target, public)
	return reconstructedPlan{presentation: presentation, request: request}
}

func bucketWritePresentationAndPolicy(target bucketTarget, public bucketObjectWritePublic) (agentv1.Presentation, hfpolicy.Request) {
	action := "Write"
	if public.Overwrite {
		action = "Overwrite"
	}
	return agentv1.Presentation{Title: "Write Hugging Face bucket object", Summary: fmt.Sprintf("%s %s in bucket %s/%s", action, public.Path, target.Namespace, target.Name)},
		hfpolicy.Request{Operation: hfpolicy.OpBucketObjectWrite, Target: hfpolicy.Target{
			Kind: hfpolicy.KindBucket, Owner: target.Namespace, Name: target.Name, Keys: []string{public.Path},
		}}
}

func (a *bucketObjectWriteAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, public, preconditions, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	if err := a.checkPreconditions(ctx, target, public, preconditions); err != nil {
		return Outcome{}, err
	}
	upload, err := a.uploadStream(ctx, target, preconditions.Stream)
	if err != nil {
		return Outcome{}, err
	}
	return a.commitUpload(ctx, target, public, preconditions, upload)
}

func (a *bucketObjectWriteAdapter) uploadStream(ctx context.Context, target bucketTarget, reference streamstore.Reference) (xetuploader.Result, error) {
	file, err := a.streams.OpenStream(reference)
	if err != nil {
		return xetuploader.Result{}, err
	}
	defer func() { _ = file.Close() }()
	return a.uploader.Upload(ctx, target.ref(), file, reference.Size)
}

func (a *bucketObjectWriteAdapter) commitUpload(ctx context.Context, target bucketTarget, public bucketObjectWritePublic,
	preconditions bucketObjectWritePreconditions, upload xetuploader.Result) (Outcome, error) {
	operation := hubclient.BucketBatchOperation{Type: "addFile", Path: public.Path, XetHash: upload.Hash,
		MTime: a.now().UTC().UnixMilli(), ContentType: preconditions.Stream.MediaType}
	batchErr := a.client.ApplyBucketBatch(ctx, target.ref(), []hubclient.BucketBatchOperation{operation})
	observed, readErr := a.client.BucketObjectInfo(ctx, target.ref(), public.Path)
	if bucketUploadMatches(observed, readErr, public.Path, upload) {
		return a.successfulUpload(target, public, preconditions, upload)
	}
	return failedBucketUpload(batchErr)
}

func failedBucketUpload(batchErr error) (Outcome, error) {
	if definitiveBucketWriteError(batchErr) {
		return Outcome{}, batchErr
	}
	return possiblePartialBucketUpload(batchErr)
}

func possiblePartialBucketUpload(batchErr error) (Outcome, error) {
	if batchErr == nil {
		batchErr = errors.New("bucket object readback did not match the uploaded content")
	}
	return Outcome{}, &PossiblePartialError{Err: batchErr}
}

func bucketUploadMatches(observed hubclient.BucketTreeEntry, err error, path string, upload xetuploader.Result) bool {
	return err == nil && observed.Path == path && observed.XetHash == upload.Hash && observed.Size == upload.Size
}

func (a *bucketObjectWriteAdapter) successfulUpload(target bucketTarget, public bucketObjectWritePublic,
	preconditions bucketObjectWritePreconditions, upload xetuploader.Result) (Outcome, error) {
	_ = a.streams.Retire(preconditions.Stream, a.now().Add(15*time.Minute))
	result, err := canonical(map[string]any{"bucket": target.Namespace + "/" + target.Name, "path": public.Path,
		"size": upload.Size, "xet_hash": upload.Hash, "content_type": preconditions.Stream.MediaType, "overwritten": !preconditions.ExistingAbsent})
	return Outcome{Proven: err == nil, Result: result}, err
}

func definitiveBucketWriteError(err error) bool {
	var upstream *hubclient.Error
	return errors.As(err, &upstream) && upstream.Definitive()
}

func (a *bucketObjectWriteAdapter) decodePlan(plan Plan) (bucketTarget, bucketObjectWritePublic, bucketObjectWritePreconditions, error) {
	target, err := decodeBucketTarget(plan.Target)
	if err != nil {
		return target, bucketObjectWritePublic{}, bucketObjectWritePreconditions{}, err
	}
	_, public, err := decodeBucketObjectWriteArguments(plan.Arguments)
	if err != nil {
		return target, public, bucketObjectWritePreconditions{}, err
	}
	var preconditions bucketObjectWritePreconditions
	if decodeClosed(plan.Preconditions, &preconditions, maxArgumentsBytes) != nil || !validBucketWritePreconditions(preconditions) {
		return target, public, preconditions, errors.New("bucket object write plan preconditions are invalid")
	}
	return target, public, preconditions, nil
}

func validBucketWritePreconditions(value bucketObjectWritePreconditions) bool {
	return value.CredentialIdentity != "" && value.BucketDigest != "" && value.Stream.ID != "" &&
		value.ExistingAbsent != (value.ExistingDigest != "")
}

func (a *bucketObjectWriteAdapter) checkPreconditions(ctx context.Context, target bucketTarget, public bucketObjectWritePublic, expected bucketObjectWritePreconditions) error {
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return err
	}
	bucket, err := a.client.BucketInfo(ctx, target.ref())
	if err != nil {
		return err
	}
	if identity.Name != expected.CredentialIdentity || bucketInfoDigest(bucket) != expected.BucketDigest || a.streams.Validate(expected.Stream) != nil {
		return errors.New("operation_precondition_failed")
	}
	existing, err := a.client.BucketObjectInfo(ctx, target.ref(), public.Path)
	return checkExistingBucketObject(expected, existing, err)
}

func checkExistingBucketObject(expected bucketObjectWritePreconditions, existing hubclient.BucketTreeEntry, err error) error {
	if expected.ExistingAbsent {
		return checkAbsentBucketObject(err)
	}
	if err != nil {
		return err
	}
	if digestValue(existing) != expected.ExistingDigest {
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func checkAbsentBucketObject(err error) error {
	if hubclient.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("operation_precondition_failed")
}

func (a *bucketObjectWriteAdapter) Reconcile(context.Context, Plan) (Outcome, error) {
	return Outcome{Proven: false}, nil
}
