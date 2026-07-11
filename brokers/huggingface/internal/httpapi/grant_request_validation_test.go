package httpapi

import (
	"net/http"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

func TestGrantRequestRequiresClientRequestID(t *testing.T) {
	request := apiGrantRequestBody{
		Operation: policy.OpGitPushForce,
		Target: policy.Target{
			Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo",
			Refs: []string{"refs/heads/main"},
		},
	}
	for _, value := range []string{"", " \t\n"} {
		request.ClientRequestID = value
		status, reason, message := validateAPIGrantRequestShape(request)
		if status != http.StatusBadRequest || reason != "validation_failed" || message != "client_request_id is required" {
			t.Fatalf("validateAPIGrantRequestShape(%q) = %d %q %q", value, status, reason, message)
		}
	}
	request.ClientRequestID = "push-main-01"
	if status, reason, message := validateAPIGrantRequestShape(request); status != 0 || reason != "" || message != "" {
		t.Fatalf("validateAPIGrantRequestShape(valid) = %d %q %q", status, reason, message)
	}
}
