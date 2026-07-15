package approval

import (
	"context"
	"errors"
	"testing"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
)

type fakeDecider struct {
	grant               grants.Grant
	approveErr, denyErr error
}

func (f fakeDecider) Approve(context.Context, string, string, string, notify.MessageRef) (grants.Grant, error) {
	return f.grant, f.approveErr
}
func (f fakeDecider) Deny(context.Context, string, string, string, notify.MessageRef) (grants.Grant, error) {
	return f.grant, f.denyErr
}

func TestHandleDecision(t *testing.T) {
	decision := notify.Decision{Action: notify.ActionApprove, OperatorTag: "alice"}
	if got := HandleDecision(t.Context(), fakeDecider{}, decision); got.Answer != "Grant approved" || got.MessageStatus != "Approved. Access is active." || got.Retry {
		t.Fatalf("HandleDecision() = %+v", got)
	}
	decision.Action = notify.ActionDeny
	if got := HandleDecision(t.Context(), fakeDecider{grant: grants.Grant{Status: grants.StatusConsumed}, denyErr: grants.ErrNotPending}, decision); got.Answer != "Grant already used" || got.MessageStatus != "Used. Access is now closed." {
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
		name              string
		err               error
		want              string
		retry             bool
		wantMessageStatus bool
	}{
		{name: "not found", err: grants.ErrNotFound, want: "Grant not found", wantMessageStatus: true},
		{name: "invalid token", err: grants.ErrInvalidDecisionToken, want: "Grant decision token did not match"},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision := notify.Decision{Action: notify.ActionApprove}
			got := HandleDecision(t.Context(), fakeDecider{approveErr: test.err}, decision)
			if got.Answer != test.want || got.Retry != test.retry || (test.wantMessageStatus && got.MessageStatus == "") {
				t.Fatalf("HandleDecision() = %+v, want answer %q", got, test.want)
			}
		})
	}
}

func TestTerminalResult(t *testing.T) {
	tests := []struct {
		status grants.Status
		answer string
	}{
		{grants.StatusActive, "Grant already approved"},
		{grants.StatusDenied, "Grant already denied"},
		{grants.StatusExpired, "Grant already expired"},
		{grants.StatusConsumed, "Grant already used"},
		{grants.StatusRevoked, "Grant already revoked"},
		{grants.StatusCanceled, "Grant already canceled"},
		{grants.StatusPending, "Grant is no longer pending"},
	}
	for _, test := range tests {
		got := terminalResult(test.status)
		if got.Answer != test.answer || got.MessageStatus == "" || got.Retry {
			t.Fatalf("terminalResult(%q) = %+v", test.status, got)
		}
	}
}

func TestStatusUpdateMessage(t *testing.T) {
	tests := []struct {
		name   string
		update grants.StatusUpdate
		want   string
	}{
		{
			name:   "retained reservation",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateRetainedReservation},
			want:   "Result is ambiguous. Access is closed until an operator reviews the retained use.",
		},
		{
			name:   "used active grant",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateUsed, Grant: grants.Grant{Status: grants.StatusActive}},
			want:   "Used. Access remains active until its limit or expiry.",
		},
		{
			name:   "used closed grant",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateUsedExpired, Grant: grants.Grant{Status: grants.StatusConsumed}},
			want:   "Used. Access is now closed.",
		},
		{
			name:   "status change",
			update: grants.StatusUpdate{Status: grants.StatusDenied},
			want:   "Denied. Access was not granted.",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := StatusUpdateMessage(test.update); got != test.want {
				t.Fatalf("StatusUpdateMessage() = %q, want %q", got, test.want)
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
