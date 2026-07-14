package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/sealedpayload"
)

func (s *Server) uploadStream(c echo.Context) error {
	client, ok := s.authenticateAgentUpload(c.Response(), c.Request())
	if !ok {
		return nil
	}
	operation := strings.TrimSpace(c.Request().Header.Get("X-Broker-Operation"))
	requestKey := strings.TrimSpace(c.Request().Header.Get("X-Broker-Idempotency-Key"))
	descriptor, found := opcatalog.ByName(operation)
	bindings := opbinding.ByOperation(operation)
	if !found || !descriptor.AgentFacing || descriptor.ExecutorKind != "bounded-stream" || len(bindings) != 1 || bindings[0].StreamDirection != "upload" ||
		!sealedpayload.ValidRequestKey(requestKey) || c.Request().ContentLength <= 0 || c.Request().ContentLength > bindings[0].RequestBytesLimit {
		writeSealedPayloadFailure(c.Response(), http.StatusBadRequest, "stream_input_invalid", "A bounded stream upload operation is required")
		return nil
	}
	mediaType := strings.TrimSpace(strings.Split(c.Request().Header.Get("Content-Type"), ";")[0])
	if mediaType == "" || mediaType == "application/json" {
		writeSealedPayloadFailure(c.Response(), http.StatusBadRequest, "stream_input_invalid", "A binary content type is required")
		return nil
	}
	reference, err := s.streamStore.Put(client, operation, requestKey, mediaType, c.Request().Body, bindings[0].RequestBytesLimit,
		time.Now().Add(time.Duration(descriptor.RequestTTLSeconds+descriptor.ApprovalTTLSeconds+300)*time.Second))
	if err != nil {
		writeSealedPayloadFailure(c.Response(), http.StatusBadRequest, "stream_input_invalid", "The stream is empty or exceeds its limit")
		return nil
	}
	return c.JSON(http.StatusCreated, reference)
}

func (s *Server) downloadStream(c echo.Context) error {
	client, ok := s.authenticateAgentUpload(c.Response(), c.Request())
	if !ok {
		return nil
	}
	file, reference, err := s.streamStore.Consume(client, c.Param("id"))
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
	return nil
}
