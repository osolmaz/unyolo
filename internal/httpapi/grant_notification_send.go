package httpapi

import (
	"net/http"

	"github.com/osolmaz/hf-broker/internal/grants"
)

func (s *Server) notifyAPICreatedGrant(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant) (grants.Grant, bool) {
	messageRef, err := s.notifier.SendApproval(r.Context(), grantApprovalMessage(grant))
	if err != nil {
		return s.retainAPIGrantNotificationIfClaimed(w, r, client, grant, "could not notify operator")
	}
	if messageRef.MessageID <= 0 {
		return s.cancelAPIGrantNotificationIfClaimed(w, r, client, grant, "could not record operator notification")
	}
	updated, recorded, err := s.grants.SetNotifierIfClaimed(grant.ID, grant.NotifierClaimedAt, messageRef)
	if err != nil {
		return s.retainAPIGrantNotificationIfClaimed(w, r, client, grant, "could not record operator notification")
	}
	if recorded {
		return updated, true
	}
	if shouldSupersedeNotifier(updated.Notifier, messageRef) {
		s.supersedeGrantMessage(r.Context(), messageRef)
	}
	return s.resolveAPIPendingGrantNotification(w, r, client, grant, updated)
}
