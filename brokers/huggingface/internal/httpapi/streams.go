package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
)

const maxBucketObjectStreamBytes = int64(512 << 20)

type streamUpload struct {
	client, operation, requestKey, mediaType string
	limit                                    int64
	expiresAt                                time.Time
}

func (s *Server) uploadStream(c echo.Context) error {
	client, ok := s.authenticateAPI(c.Response(), c.Request())
	if !ok {
		return nil
	}
	upload, err := hfStreamUploadFromRequest(client, c.Request(), s.utcNow())
	if err != nil {
		writeJSendFail(c.Response(), http.StatusBadRequest, "stream_input_invalid", "A bounded bucket object stream is required")
		return nil
	}
	reference, err := s.streamStore.Put(upload.client, upload.operation, upload.requestKey, upload.mediaType,
		c.Request().Body, upload.limit, upload.expiresAt)
	if err != nil {
		writeJSendFail(c.Response(), http.StatusBadRequest, "stream_input_invalid", "The stream is empty or exceeds its limit")
		return nil
	}
	return c.JSON(http.StatusCreated, reference)
}

func hfStreamUploadFromRequest(client string, request *http.Request, now time.Time) (streamUpload, error) {
	operation := strings.TrimSpace(request.Header.Get("X-Broker-Operation"))
	requestKey := strings.TrimSpace(request.Header.Get("X-Broker-Idempotency-Key"))
	mediaType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])
	descriptor, found := opcatalog.ByName(operation)
	if !found || operation != "bucket.object.write" || !descriptor.AgentFacing || descriptor.ExecutorKind != "bounded-stream" ||
		!agentv1.ValidIdempotencyKey(requestKey) || mediaType == "" || mediaType == "application/json" || len(mediaType) > 255 ||
		request.ContentLength <= 0 || request.ContentLength > maxBucketObjectStreamBytes {
		return streamUpload{}, errors.New("stream upload is invalid")
	}
	return streamUpload{client: client, operation: operation, requestKey: requestKey, mediaType: mediaType,
		limit:     maxBucketObjectStreamBytes,
		expiresAt: now.Add(time.Duration(descriptor.RequestTTLSeconds+descriptor.ApprovalTTLSeconds+3600) * time.Second)}, nil
}

func (s *Server) downloadStream(c echo.Context) error {
	client, ok := s.authenticateAPI(c.Response(), c.Request())
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

func (s *Server) startStreamSweeper(ctx context.Context) {
	if s.streamStore == nil {
		return
	}
	_, _ = s.streamStore.SweepExpired(s.utcNow())
	s.backgroundWorkers.Add(1)
	go func() {
		defer s.backgroundWorkers.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = s.streamStore.SweepExpired(s.utcNow())
			}
		}
	}()
}
