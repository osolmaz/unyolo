package approval

import (
	"context"
	"errors"
	"testing"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
)

type fakeDecider struct{ approveErr, denyErr error }

func (f fakeDecider) Approve(context.Context, string, string, string, notify.MessageRef) (grants.Grant, error) {
	return grants.Grant{}, f.approveErr
}
func (f fakeDecider) Deny(context.Context, string, string, string, notify.MessageRef) (grants.Grant, error) {
	return grants.Grant{}, f.denyErr
}

func TestHandleDecision(t *testing.T) {
	decision := notify.Decision{Action: notify.ActionApprove, OperatorTag: "alice"}
	if got := HandleDecision(t.Context(), fakeDecider{}, decision); got.Answer != "Grant approved" || got.Retry {
		t.Fatalf("HandleDecision() = %+v", got)
	}
	decision.Action = notify.ActionDeny
	if got := HandleDecision(t.Context(), fakeDecider{denyErr: grants.ErrNotPending}, decision); got.Answer != "Grant is no longer pending" {
		t.Fatalf("HandleDecision() = %+v", got)
	}
	if got := HandleDecision(t.Context(), fakeDecider{denyErr: errors.New("disk")}, decision); !got.Retry {
		t.Fatalf("HandleDecision() = %+v, want retry", got)
	}
}

func TestHandleDecisionFailures(t *testing.T) {
	if got := HandleDecision(t.Context(), nil, notify.Decision{}); !got.Retry {
		t.Fatalf("HandleDecision(nil) = %+v, want retry", got)
	}
	if got := HandleDecision(t.Context(), fakeDecider{}, notify.Decision{Action: "unknown"}); got.Answer != "Grant decision ignored" || got.Retry {
		t.Fatalf("HandleDecision(unknown) = %+v", got)
	}
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "not found", err: grants.ErrNotFound, want: "Grant not found"},
		{name: "invalid token", err: grants.ErrInvalidDecisionToken, want: "Grant decision token did not match"},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision := notify.Decision{Action: notify.ActionApprove}
			got := HandleDecision(t.Context(), fakeDecider{approveErr: test.err}, decision)
			if got.Answer != test.want || got.Retry {
				t.Fatalf("HandleDecision() = %+v, want answer %q", got, test.want)
			}
		})
	}
}

func TestActor(t *testing.T) {
	for _, test := range []struct {
		decision notify.Decision
		want     string
	}{
		{notify.Decision{OperatorID: 42, OperatorTag: "alice"}, "telegram:42"},
		{notify.Decision{OperatorTag: "alice"}, "telegram:@alice"},
		{notify.Decision{OperatorID: 42}, "telegram:42"},
		{notify.Decision{Approver: "fallback"}, "fallback"},
		{notify.Decision{}, "telegram"},
	} {
		if got := Actor(test.decision); got != test.want {
			t.Fatalf("Actor() = %q, want %q", got, test.want)
		}
	}
}
