package approval

import (
	"context"
	"errors"
	"testing"

	"github.com/osolmaz/brokerkit/approval/notifier"
	"github.com/osolmaz/brokerkit/authorization/grants"
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
	if got := HandleDecision(t.Context(), fakeDecider{}, decision); got.Answer != notify.AnswerApproved || got.MessageStatus.Kind != notify.StatusActive || got.Retry {
		t.Fatalf("HandleDecision() = %+v", got)
	}
	decision.Action = notify.ActionDeny
	if got := HandleDecision(t.Context(), fakeDecider{grant: grants.Grant{Status: grants.StatusConsumed}, denyErr: grants.ErrNotPending}, decision); got.Answer != notify.AnswerAlreadyConsumed || got.MessageStatus.Kind != notify.StatusConsumed {
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
	if got := HandleDecision(t.Context(), fakeDecider{}, notify.Decision{Action: "unknown"}); got.Answer != notify.AnswerIgnored || got.Retry {
		t.Fatalf("HandleDecision(unknown) = %+v", got)
	}
	for _, test := range []struct {
		name              string
		err               error
		want              notify.Answer
		retry             bool
		wantMessageStatus bool
	}{
		{name: "not found", err: grants.ErrNotFound, want: notify.AnswerNotFound, wantMessageStatus: true},
		{name: "invalid token", err: grants.ErrInvalidDecisionToken, want: notify.AnswerSuperseded},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision := notify.Decision{Action: notify.ActionApprove}
			got := HandleDecision(t.Context(), fakeDecider{approveErr: test.err}, decision)
			if got.Answer != test.want || got.Retry != test.retry || (test.wantMessageStatus && got.MessageStatus.Kind == "") {
				t.Fatalf("HandleDecision() = %+v, want answer %q", got, test.want)
			}
		})
	}
}

func TestTerminalResult(t *testing.T) {
	tests := []struct {
		status grants.Status
		answer notify.Answer
	}{
		{grants.StatusActive, notify.AnswerAlreadyApproved},
		{grants.StatusDenied, notify.AnswerAlreadyDenied},
		{grants.StatusExpired, notify.AnswerAlreadyExpired},
		{grants.StatusConsumed, notify.AnswerAlreadyConsumed},
		{grants.StatusRevoked, notify.AnswerAlreadyRevoked},
		{grants.StatusCanceled, notify.AnswerAlreadyCanceled},
		{grants.StatusPending, notify.AnswerClosed},
	}
	for _, test := range tests {
		got := terminalResult(grants.Grant{Status: test.status})
		if got.Answer != test.answer || got.MessageStatus.Kind == "" || got.Retry {
			t.Fatalf("terminalResult(%q) = %+v", test.status, got)
		}
	}
}

func TestStatusForUpdate(t *testing.T) {
	tests := []struct {
		name   string
		update grants.StatusUpdate
		want   notify.StatusKind
	}{
		{
			name:   "retained reservation",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateRetainedReservation},
			want:   notify.StatusRetained,
		},
		{
			name:   "used active grant",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateUsed, Grant: grants.Grant{Status: grants.StatusActive}},
			want:   notify.StatusUsedActive,
		},
		{
			name:   "used closed grant",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateUsedExpired, Grant: grants.Grant{Status: grants.StatusConsumed}},
			want:   notify.StatusConsumed,
		},
		{
			name:   "status change",
			update: grants.StatusUpdate{Status: grants.StatusDenied},
			want:   notify.StatusDenied,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := StatusForUpdate(test.update); got.Kind != test.want {
				t.Fatalf("StatusForUpdate() = %+v, want %q", got, test.want)
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
