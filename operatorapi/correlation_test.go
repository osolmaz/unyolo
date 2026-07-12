package operatorapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerFailsClosedWhenCorrelationEntropyFails(t *testing.T) {
	h := &handler{newID: func() (string, error) { return "", errors.New("entropy unavailable") }}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("X-Correlation-ID") != "unavailable" ||
		!strings.Contains(response.Body.String(), "temporarily_unavailable") {
		t.Fatalf("response = %d, %v, %s", response.Code, response.Header(), response.Body.String())
	}
}

func TestSecureCorrelationID(t *testing.T) {
	first, err := secureCorrelationID()
	if err != nil || len(first) != 22 {
		t.Fatalf("secureCorrelationID() = %q, %v", first, err)
	}
	second, err := secureCorrelationID()
	if err != nil || second == first {
		t.Fatalf("second secureCorrelationID() = %q, %v", second, err)
	}
}
