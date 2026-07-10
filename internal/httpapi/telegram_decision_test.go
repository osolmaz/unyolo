package httpapi

import (
	"errors"
	"testing"

	bknotify "github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/hf-broker/internal/grants"
)

func TestTelegramDecisionResult(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		answer string
		retry  bool
	}{
		{name: "success", answer: "Grant approved"},
		{name: "missing", err: grants.ErrNotFound, answer: "Grant not found"},
		{name: "bad token", err: grants.ErrInvalidDecisionToken, answer: "Grant decision token did not match"},
		{name: "terminal", err: grants.ErrNotPending, answer: "Grant is no longer pending"},
		{name: "storage failure", err: errors.New("write failed"), retry: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := telegramDecisionResult(tt.err, "Grant approved")
			if got.Answer != tt.answer || got.Retry != tt.retry {
				t.Fatalf("telegramDecisionResult() = %+v, want answer %q retry %t", got, tt.answer, tt.retry)
			}
		})
	}
}

func TestTelegramActor(t *testing.T) {
	if got := telegramActor(bknotify.Decision{OperatorTag: "onur", OperatorID: 42}); got != "telegram:@onur" {
		t.Fatalf("telegramActor(username) = %q", got)
	}
	if got := telegramActor(bknotify.Decision{OperatorID: 42}); got != "telegram:42" {
		t.Fatalf("telegramActor(id) = %q", got)
	}
}
