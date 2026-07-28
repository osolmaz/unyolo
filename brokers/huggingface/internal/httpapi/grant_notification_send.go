package httpapi

import (
	"net/http"

	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

func (s *Server) notifyAPICreatedGrant(w http.ResponseWriter, r *http.Request, client string, claim grants.NotificationClaim) (grants.Grant, bool) {
	grant := claim.Grant
	messageRef, err := s.notifier.SendApproval(r.Context(), grantApprovalMessage(r.Context(), grant, claim.DecisionToken))
	if err != nil {
		return s.handleNotificationFailure(w, r, client, grant, "could not notify operator", false)
	}
	if messageRef.MessageID <= 0 {
		return s.handleNotificationFailure(w, r, client, grant, "could not record operator notification", true)
	}
	updated, recorded, err := s.grants.SetNotificationIfClaimed(grant.ID, grant.NotificationClaimedAt, messageRef)
	if err != nil {
		return s.handleNotificationFailure(w, r, client, grant, "could not record operator notification", false)
	}
	if recorded {
		return updated, true
	}
	if shouldSupersedeNotifier(updated.Notification, messageRef) {
		s.supersedeGrantMessage(r.Context(), messageRef)
	}
	return s.resolveAPIPendingGrantNotification(w, r, client, grant, updated)
}

func (s *Server) handleNotificationFailure(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant, reason string, cancel bool) (grants.Grant, bool) {
	if s.operatorConfigured {
		return s.keepGrantInOperatorInbox(w, client, grant, reason)
	}
	if cancel {
		return s.cancelAPIGrantNotificationIfClaimed(w, r, client, grant, reason)
	}
	return s.retainAPIGrantNotificationIfClaimed(w, r, client, grant, reason)
}

func (s *Server) keepGrantInOperatorInbox(w http.ResponseWriter, client string, grant grants.Grant, reason string) (grants.Grant, bool) {
	updated, _, err := s.grants.RetainNotificationClaim(grant.ID, grant.NotificationClaimedAt)
	if err != nil {
		writeJSendError(w, http.StatusBadGateway, reason, "internal_error")
		s.record(client, "grant_request", hfgrant.Target(grant), audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	return updated, true
}
