package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
)

const maxSealedPayloadBytes = 1 << 20

//nolint:cyclop // Sealed-payload boundary checks are explicit and tracked by the exact HF CRAP baseline.
func (s *Server) uploadSealedPayload(c echo.Context) error {
	request := c.Request()
	client, ok := s.authenticateAPI(c.Response(), request)
	if !ok {
		return nil
	}
	operation := strings.TrimSpace(request.Header.Get("X-Broker-Operation"))
	descriptor, found := opcatalog.ByName(operation)
	if !found || !descriptor.Sealed || !descriptor.AgentFacing || descriptor.AuthorizationMode != opcatalog.ModeExecution {
		writeJSendFail(c.Response(), http.StatusBadRequest, "sealed_purpose_invalid", "A sealed operation is required")
		return nil
	}
	if request.Header.Get("Content-Type") != "application/octet-stream" || request.ContentLength == 0 || request.ContentLength > maxSealedPayloadBytes {
		writeJSendFail(c.Response(), http.StatusBadRequest, "sealed_payload_invalid", "Sealed payload must be bounded binary content")
		return nil
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maxSealedPayloadBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maxSealedPayloadBytes {
		writeJSendFail(c.Response(), http.StatusBadRequest, "sealed_payload_invalid", "Sealed payload must be bounded binary content")
		return nil //nolint:nilerr // The bounded failure response is already committed.
	}
	expires := time.Now().Add(time.Duration(descriptor.RequestTTLSeconds+descriptor.ApprovalTTLSeconds+300) * time.Second)
	reference, err := s.sealedStore.Put(client, operation, payload, expires)
	for index := range payload {
		payload[index] = 0
	}
	if err != nil {
		writeJSendFail(c.Response(), http.StatusInternalServerError, "sealed_payload_unavailable", "Could not seal operation payload")
		return nil //nolint:nilerr // The redacted failure response is already committed.
	}
	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().WriteHeader(http.StatusCreated)
	return json.NewEncoder(c.Response()).Encode(reference)
}
