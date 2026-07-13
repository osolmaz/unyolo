// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"context"
	"errors"
	"fmt"
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
		status := grantStatusUpdateText(item)
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
		claim, claimed, err := s.grants.ClaimNotification(grant.ID, grantNotificationClaimLease)
		if err != nil || !claimed {
			continue
		}
		ref, err := s.notifier.SendApproval(ctx, grantApprovalMessage(claim.Grant, claim.DecisionToken))
		if err != nil || ref.MessageID <= 0 {
			_, _, _ = s.grants.RetainNotificationClaim(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
			continue
		}
		updated, recorded, err := s.grants.SetNotificationIfClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt, ref)
		if err != nil {
			_, _, _ = s.grants.RetainNotificationClaim(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
			continue
		}
		if !recorded && shouldSupersedeNotifier(updated.Notification, ref) {
			s.supersedeGrantMessage(ctx, ref)
		}
	}
}

func grantStatusUpdateText(update grants.StatusUpdate) string {
	switch update.Kind {
	case grants.StatusUpdateLifecycle:
	case grants.StatusUpdateRetainedReservation:
		return retainedGrantReservationStatus(update.Grant)
	case grants.StatusUpdateUsed, grants.StatusUpdateUsedExpired:
		return grantUseStatus(update.Grant)
	}
	switch update.Status {
	case grants.StatusActive:
		return "✅ Approved. Access is active."
	case grants.StatusDenied:
		return "❌ Denied. Access was not granted."
	default:
		return pendingExpiredStatusForGrant(update.Grant)
	}
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
		if err := s.updateGrantMessage(ctx, update.Grant, grantStatusUpdateText(update)); err == nil {
			_ = s.grants.MarkNotificationStatus(id, update.NotificationStatusKey())
		}
		return
	}
}

func (s *Server) updateGrantMessage(ctx context.Context, grant grants.Grant, status string) error {
	if grant.Notification == nil {
		return nil
	}
	return s.updateNotifierStatus(ctx, *grant.Notification, status)
}

func (s *Server) updateNotifierStatus(ctx context.Context, ref bknotify.MessageRef, status string) error {
	if s.notifier == nil {
		return nil
	}
	return s.notifier.UpdateStatus(ctx, ref, status)
}

func pendingExpiredStatusForGrant(grant grants.Grant) string {
	if grant.ExpiredFrom == grants.StatusPending {
		return "⌛ Expired. Request was not approved in time."
	}
	return "⌛ Expired. Access window ended."
}

func grantUseStatus(grant grants.Grant) string {
	maxUses := grant.MaxUses
	if grant.Status == grants.StatusConsumed {
		return "✅ Used. Access is now closed."
	}
	if grant.Status == grants.StatusExpired {
		return "✅ Used. Access is now closed."
	}
	heldUses := grant.ReservedCount
	remaining, finite := maxUses.Remaining(grant.UsedCount, heldUses)
	if !finite {
		return fmt.Sprintf("✅ Used %d times. Access remains active until expiry.", grant.UsedCount)
	}
	if heldUses > 0 {
		if heldUses == 1 {
			return fmt.Sprintf("✅ Used %d of %d. 1 use is held; %d uses remain.", grant.UsedCount, int(maxUses), remaining)
		}
		return fmt.Sprintf("✅ Used %d of %d. %d uses are held; %d uses remain.", grant.UsedCount, int(maxUses), heldUses, remaining)
	}
	return fmt.Sprintf("✅ Used %d of %d. %d uses remain.", grant.UsedCount, int(maxUses), remaining)
}

func retainedGrantReservationStatus(grant grants.Grant) string {
	maxUses := grant.MaxUses
	if maxUses.IsUnlimited() {
		return "⚠️ Push result is ambiguous. Unlimited access remains blocked pending operator review."
	}
	if grant.Status == grants.StatusExpired {
		return "⚠️ Push result is ambiguous. Access is closed; operator review is still needed."
	}
	heldUses := grant.UsedCount + grant.ReservedCount
	if heldUses <= grant.UsedCount {
		heldUses = grant.UsedCount + 1
	}
	if maxUses == 1 {
		return "⚠️ Push result is ambiguous. Access is closed until an operator reviews it."
	}
	if heldUses == 1 {
		return fmt.Sprintf("⚠️ Push result is ambiguous. 1 of %d uses is held; access is closed until an operator reviews it.", maxUses)
	}
	return fmt.Sprintf("⚠️ Push result is ambiguous. %d of %d uses are held; access is closed until an operator reviews it.", heldUses, maxUses)
}
