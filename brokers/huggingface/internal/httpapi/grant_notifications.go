// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"context"
	"errors"
	"strings"
	"time"

	bkapproval "github.com/osolmaz/brokerkit/approval"
	bkapprovalnotify "github.com/osolmaz/brokerkit/approval/notification"
	bknotify "github.com/osolmaz/brokerkit/approval/notifier"
	"github.com/osolmaz/brokerkit/authorization/grants"
	hfapproval "github.com/osolmaz/brokerkit/brokers/huggingface/internal/approval"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

func grantNeedsNotification(grant grants.Grant) bool {
	return grant.Status == grants.StatusPending && grant.Notification == nil
}

func (s *Server) supersedeGrantMessage(ctx context.Context, ref bknotify.MessageRef) {
	if ref.MessageID == 0 {
		return
	}
	_ = s.updateNotifierStatus(ctx, ref, bknotify.Status{Kind: bknotify.StatusSuperseded})
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

func grantApprovalMessage(ctx context.Context, grant grants.Grant, decisionToken string) bkapprovalnotify.Approval {
	return bkapprovalnotify.Project(ctx, "Hugging Face", hfapproval.Presenter{}, grant, decisionToken)
}
func (s *Server) startGrantNotificationSweeper(ctx context.Context) {
	if s.notifier == nil {
		return
	}
	s.backgroundWorkers.Add(1)
	go func() {
		defer s.backgroundWorkers.Done()
		s.sweepGrantNotifications(ctx)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sweepGrantNotifications(ctx)
			}
		}
	}()
}

func (s *Server) sweepGrantNotifications(ctx context.Context) {
	s.sweepPendingGrantApprovals(ctx)
	updates, err := s.grants.StatusUpdatesDue()
	if err != nil {
		return
	}
	for _, item := range updates {
		status := bkapproval.StatusForUpdate(item)
		if err := s.updateGrantMessage(ctx, item.Grant, status); err == nil {
			_ = s.grants.MarkNotificationStatus(item.Grant.ID, item.NotificationStatusKey())
		}
	}
}

func (s *Server) sweepPendingGrantApprovals(ctx context.Context) {
	pending, err := s.grants.ApprovalNotificationsDue()
	if err != nil {
		return
	}
	for _, grant := range pending {
		s.sweepPendingGrantApproval(ctx, grant)
	}
}

func (s *Server) sweepPendingGrantApproval(ctx context.Context, grant grants.Grant) {
	claim, claimed, err := s.grants.ClaimNotification(grant.ID, grantNotificationClaimLease)
	if err != nil || !claimed {
		return
	}
	ref, ok := s.sendClaimedGrantApproval(ctx, claim)
	if !ok {
		return
	}
	s.recordClaimedGrantNotification(ctx, claim, ref)
}

func (s *Server) sendClaimedGrantApproval(ctx context.Context, claim grants.NotificationClaim) (bknotify.MessageRef, bool) {
	ref, err := s.notifier.SendApproval(ctx, grantApprovalMessage(ctx, claim.Grant, claim.DecisionToken))
	if err != nil || ref.MessageID <= 0 {
		s.retainGrantNotificationClaim(claim)
		return bknotify.MessageRef{}, false
	}
	return ref, true
}

func (s *Server) recordClaimedGrantNotification(ctx context.Context, claim grants.NotificationClaim, ref bknotify.MessageRef) {
	updated, recorded, err := s.grants.SetNotificationIfClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt, ref)
	if err != nil {
		s.retainGrantNotificationClaim(claim)
		return
	}
	if !recorded && shouldSupersedeNotifier(updated.Notification, ref) {
		s.supersedeGrantMessage(ctx, ref)
	}
}

func (s *Server) retainGrantNotificationClaim(claim grants.NotificationClaim) {
	_, _, _ = s.grants.RetainNotificationClaim(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
}

func (s *Server) updateGrantUseMessage(grant grants.Grant) {
	s.deliverGrantStatusUpdate(context.Background(), grant.ID)
}

func (s *Server) updateRetainedGrantReservationMessage(grant grants.Grant) {
	current, err := s.grants.RetainUse(grant.ID)
	if err != nil {
		return
	}
	s.deliverGrantStatusUpdate(context.Background(), current.ID)
}

func (s *Server) deliverGrantStatusUpdate(ctx context.Context, id string) {
	updates, err := s.grants.StatusUpdatesDue()
	if err != nil {
		return
	}
	for _, update := range updates {
		if update.Grant.ID != id {
			continue
		}
		if err := s.updateGrantMessage(ctx, update.Grant, bkapproval.StatusForUpdate(update)); err == nil {
			_ = s.grants.MarkNotificationStatus(id, update.NotificationStatusKey())
		}
		return
	}
}

func (s *Server) updateGrantMessage(ctx context.Context, grant grants.Grant, status bknotify.Status) error {
	if grant.Notification == nil {
		return nil
	}
	return s.updateNotifierStatus(ctx, *grant.Notification, status)
}

func (s *Server) updateNotifierStatus(ctx context.Context, ref bknotify.MessageRef, status bknotify.Status) error {
	if s.notifier == nil {
		return nil
	}
	return s.notifier.UpdateStatus(ctx, ref, status)
}
