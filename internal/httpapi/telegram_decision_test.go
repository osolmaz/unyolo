package httpapi

import (
	"errors"
	"testing"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
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
		{name: "token", err: grants.ErrInvalidDecisionToken, answer: "Grant decision token did not match"},
		{name: "terminal", err: grants.ErrNotPending, answer: "Grant is no longer pending"},
		{name: "storage", err: errors.New("write failed"), retry: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := telegramDecisionResult(test.err, "Grant approved")
			if got.Answer != test.answer || got.Retry != test.retry {
				t.Fatalf("telegramDecisionResult() = %+v", got)
			}
		})
	}
}

func TestTelegramActor(t *testing.T) {
	tests := []struct {
		decision notify.Decision
		want     string
	}{
		{decision: notify.Decision{OperatorTag: "operator", OperatorID: 42}, want: "telegram:@operator"},
		{decision: notify.Decision{OperatorID: 42}, want: "telegram:42"},
		{decision: notify.Decision{Approver: "service"}, want: "service"},
		{want: "telegram"},
	}
	for _, test := range tests {
		if got := telegramActor(test.decision); got != test.want {
			t.Fatalf("telegramActor(%+v) = %q, want %q", test.decision, got, test.want)
		}
	}
}
