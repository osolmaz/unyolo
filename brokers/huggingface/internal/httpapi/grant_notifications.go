// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/approval"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	bknotify "github.com/osolmaz/brokerkit/notify"
)

func grantNeedsNotification(grant grants.Grant) bool {
	return grant.Status == grants.StatusPending && grant.Notification == nil
}

func (s *Server) supersedeGrantMessage(ctx context.Context, ref bknotify.MessageRef) {
	if ref.MessageID == 0 {
		return
	}
	_ = s.updateNotifierStatus(ctx, ref, "⚠️ Superseded. Use the latest approval message.")
}

func (s *Server) waitForGrantNotification(ctx context.Context, id string) (grants.Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, grantNotificationClaimWait)
	defer cancel()
	ticker := time.NewTicker(grantNotificationClaimPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return grants.Grant{}, errGrantNotificationStillQueued
		case <-ticker.C:
			grant, err := s.grants.Get(id)
			if err != nil {
				return grants.Grant{}, err
			}
			if state := grantNotificationWaitState(grant); !errors.Is(state, errGrantNotificationStillQueued) {
				return grant, state
			}
		}
	}
}

func grantNotificationWaitState(grant grants.Grant) error {
	switch {
	case grant.Status == grants.StatusCanceled:
		return errGrantNotificationCanceled
	case grant.NotificationDeliveryUnresolved:
		return errGrantNotificationUnresolved
	case grantNeedsNotification(grant):
		return errGrantNotificationStillQueued
	default:
		return nil
	}
}

func grantRefMatchesOperation(operation policy.Operation, ref string) bool {
	switch operation {
	case policy.OpGitPushAppend:
		return !isReplaceRef(ref)
	case policy.OpGitPushForce, policy.OpGitRefDelete:
		return !isTagRef(ref) && !isReplaceRef(ref)
	case policy.OpGitTagUpdate:
		return isTagRef(ref)
	default:
		return false
	}
}

func parseGrantTarget(target string) (route, bool) {
	parts := strings.Split(target, "/")
	if len(parts) != 3 || strings.Contains(target, "..") {
		return route{}, false
	}
	repoType, ok := grantRepoType(parts[0])
	if !ok || invalidGrantTargetSegment(parts[1]) || invalidGrantTargetSegment(parts[2]) {
		return route{}, false
	}
	return route{repoType: repoType, owner: parts[1], name: parts[2]}, true
}

func grantRepoType(value string) (policy.RepoType, bool) {
	switch value {
	case string(policy.TypeModel):
		return policy.TypeModel, true
	case string(policy.TypeDataset):
		return policy.TypeDataset, true
	case string(policy.TypeSpace):
		return policy.TypeSpace, true
	default:
		return "", false
	}
}

func invalidGrantTargetSegment(value string) bool {
	return value == "" || strings.ContainsAny(value, " \t\r\n/\x00*?")
}

func grantApprovalMessage(grant grants.Grant, decisionToken string) bknotify.ApprovalMessage {
	attrs, _ := hfgrant.Attrs(grant)
	target := hfgrant.Target(grant)
	requestedMinutes := hfgrant.RequestedMinutes(grant)
	message := approval.Message{
		Client:           grant.Client,
		Operation:        grant.Operation,
		Mode:             hfgrant.Mode(grant),
		Target:           target,
		Ref:              hfgrant.Ref(grant),
		Attrs:            attrs,
		Reason:           grant.Reason,
		RequestedMinutes: requestedMinutes,
		MaxUses:          grant.MaxUses,
		PendingExpiresAt: grant.PendingExpiresAt,
	}
	return bknotify.ApprovalMessage{
		GrantID:          grant.ID,
		DecisionToken:    decisionToken,
		Text:             approval.Text(message),
		Client:           grant.Client,
		Operation:        grant.Operation,
		Target:           target,
		Reason:           grant.Reason,
		RequestedMinutes: requestedMinutes,
		MaxUses:          grant.MaxUses,
	}
}
