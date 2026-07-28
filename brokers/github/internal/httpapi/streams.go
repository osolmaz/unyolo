package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/operation/payload"
)

type streamUpload struct {
	client     string
	operation  string
	requestKey string
	mediaType  string
	limit      int64
	expiresAt  time.Time
}

func (s *Server) uploadStream(c echo.Context) error {
	client, ok := s.authenticateAgentUpload(c.Response(), c.Request())
	if !ok {
		return nil
	}
	upload, err := streamUploadFromRequest(client, c.Request())
	if err != nil {
		return rejectStreamInput(c, "A bounded stream upload operation is required")
	}
	if upload.mediaType == "" || upload.mediaType == "application/json" {
		return rejectStreamInput(c, "A binary content type is required")
	}
	reference, err := s.streamStore.Put(upload.client, upload.operation, upload.requestKey, upload.mediaType, c.Request().Body, upload.limit, upload.expiresAt)
	if err != nil {
		return rejectStreamInput(c, "The stream is empty or exceeds its limit")
	}
	return c.JSON(http.StatusCreated, agentv1.StreamReference{
		ID: reference.ID, Owner: reference.Owner, Purpose: reference.Purpose, TransferID: reference.RequestKey,
		Digest: reference.Digest, Size: reference.Size, MediaType: reference.MediaType, ExpiresAt: reference.ExpiresAt,
	})
}

func streamUploadFromRequest(client string, request *http.Request) (streamUpload, error) {
	operation := strings.TrimSpace(request.Header.Get("X-Broker-Operation"))
	requestKey := strings.TrimSpace(request.Header.Get("X-Broker-Idempotency-Key"))
	descriptor, found := opcatalog.ByName(operation)
	bindings := opbinding.ByOperation(operation)
	if !validStreamUploadDescriptor(descriptor, found, bindings) || !sealedpayload.ValidRequestKey(requestKey) ||
		request.ContentLength <= 0 || request.ContentLength > bindings[0].RequestBytesLimit {
		return streamUpload{}, errors.New("stream upload is invalid")
	}
	return streamUpload{
		client: client, operation: operation, requestKey: requestKey, mediaType: requestMediaType(request),
		limit: bindings[0].RequestBytesLimit, expiresAt: streamUploadExpiresAt(descriptor),
	}, nil
}

func validStreamUploadDescriptor(descriptor opcatalog.Descriptor, found bool, bindings []opbinding.Binding) bool {
	return found && descriptor.AgentFacing && descriptor.ExecutorKind == "bounded-stream" &&
		len(bindings) == 1 && bindings[0].StreamDirection == "upload"
}

func requestMediaType(request *http.Request) string {
	return strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])
}

func streamUploadExpiresAt(descriptor opcatalog.Descriptor) time.Time {
	return time.Now().Add(time.Duration(descriptor.RequestTTLSeconds+descriptor.ApprovalTTLSeconds+300) * time.Second)
}

func rejectStreamInput(c echo.Context, message string) error {
	writeSealedPayloadFailure(c.Response(), http.StatusBadRequest, "stream_input_invalid", message)
	return nil
}

func (s *Server) downloadStream(c echo.Context) error {
	client, ok := s.authenticateAgentUpload(c.Response(), c.Request())
	if !ok {
		return nil
	}
	file, reference, err := s.streamStore.OpenOwned(client, c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "stream is unavailable")
	}
	defer func() { _ = file.Close() }()
	c.Response().Header().Set("Content-Type", reference.MediaType)
	c.Response().Header().Set("Content-Length", strconv.FormatInt(reference.Size, 10))
	c.Response().Header().Set("X-Broker-Content-SHA256", reference.Digest)
	c.Response().WriteHeader(http.StatusOK)
	written, err := io.Copy(c.Response(), file)
	if err != nil || written != reference.Size {
		return errors.New("stream response interrupted")
	}
	return s.streamStore.Delete(reference)
}
