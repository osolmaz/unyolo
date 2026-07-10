package grants

import (
	"errors"

	bkgrants "github.com/osolmaz/brokerkit/grants"
)

// Approve activates a pending grant.
func (s *Store) Approve(id, decisionToken, actor string) (Grant, error) {
	return s.decide(s.core.Approve, id, decisionToken, actor)
}

// ApproveWithNotifier atomically approves a grant and recovers its callback message.
func (s *Store) ApproveWithNotifier(id, decisionToken, actor string, message NotifierMessage) (Grant, error) {
	return s.decideWithNotifier(s.core.ApproveWithNotification, id, decisionToken, actor, message)
}

// Deny closes a pending grant without granting access.
func (s *Store) Deny(id, decisionToken, actor string) (Grant, error) {
	return s.decide(s.core.Deny, id, decisionToken, actor)
}

// DenyWithNotifier atomically denies a grant and recovers its callback message.
func (s *Store) DenyWithNotifier(id, decisionToken, actor string, message NotifierMessage) (Grant, error) {
	return s.decideWithNotifier(s.core.DenyWithNotification, id, decisionToken, actor, message)
}

func (s *Store) decide(decider func(string, string, string) (bkgrants.Grant, error), id, token, actor string) (Grant, error) {
	grant, err := decider(id, token, actor)
	if err != nil {
		return Grant{}, err
	}
	return fromCoreGrant(grant, "")
}

func (s *Store) decideWithNotifier(
	decider func(string, string, string, bkgrants.MessageRef) (bkgrants.Grant, error),
	id, token, actor string,
	message NotifierMessage,
) (Grant, error) {
	grant, err := decider(id, token, actor, message)
	if grant.ID == "" {
		return Grant{}, err
	}
	out, conversionErr := fromCoreGrant(grant, "")
	return out, errors.Join(err, conversionErr)
}
