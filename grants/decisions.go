package grants

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// Approve activates a pending grant.
func (s *Store) Approve(id string, decisionToken string, approver string) (Grant, error) {
	return s.decide(id, decisionToken, approver, StatusActive)
}

// ApproveWithNotification atomically approves a pending grant and records a
// callback-carried notification when no notification is already stored.
func (s *Store) ApproveWithNotification(id string, decisionToken string, approver string, ref MessageRef) (Grant, error) {
	return s.decideWithNotification(context.Background(), id, decisionToken, approver, StatusActive, ref, nil)
}

// ApproveWithNotificationValidated atomically validates and approves a pending
// notification-channel grant. The validation runs against the committed grant
// while the store lock is held.
func (s *Store) ApproveWithNotificationValidated(ctx context.Context, id string, decisionToken string, approver string, ref MessageRef, validate ActivationCheck) (Grant, error) {
	return s.decideWithNotification(ctx, id, decisionToken, approver, StatusActive, ref, validate)
}

// Deny denies a pending grant.
func (s *Store) Deny(id string, decisionToken string, approver string) (Grant, error) {
	return s.decide(id, decisionToken, approver, StatusDenied)
}

// DenyWithNotification atomically denies a pending grant and records a
// callback-carried notification when no notification is already stored.
func (s *Store) DenyWithNotification(id string, decisionToken string, approver string, ref MessageRef) (Grant, error) {
	return s.decideWithNotification(context.Background(), id, decisionToken, approver, StatusDenied, ref, nil)
}

func (s *Store) decide(id string, token string, approver string, status Status) (Grant, error) {
	return s.decideAndNotify(context.Background(), id, token, approver, status, nil, nil)
}

func (s *Store) decideWithNotification(ctx context.Context, id string, token string, approver string, status Status, ref MessageRef, validate ActivationCheck) (Grant, error) {
	if err := validateMessageRef(ref); err != nil {
		return Grant{}, err
	}
	return s.decideAndNotify(ctx, id, token, approver, status, &ref, validate)
}

func (s *Store) decideAndNotify(ctx context.Context, id string, token string, approver string, status Status, ref *MessageRef, validate ActivationCheck) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return Grant{}, err
	}
	before := grantSnapshots(data.Grants)
	eventSequence := data.NextEvent
	index, grant, err := findGrant(data.Grants, id)
	if err != nil {
		return Grant{}, err
	}
	if !decisionTokenMatches(grant.DecisionTokenVerifier, token) {
		return Grant{}, ErrInvalidDecisionToken
	}
	if status == StatusActive && validate != nil && grant.Status == StatusPending && s.opts.Now().UTC().Before(grant.PendingExpiresAt) {
		if err := validate(ctx, grant, ApprovalConstraints{}); err != nil {
			return Grant{}, err
		}
	}
	updated, changed, decisionErr := s.prepareDecision(grant, approver, status)
	if ref != nil && updated.Notification == nil {
		updated.Notification = ref
		updated.NotificationStatus = string(StatusPending)
		clearNotificationClaim(&updated)
		changed = true
	}
	if !changed {
		return Grant{}, decisionErr
	}
	data.Grants[index] = updated
	s.reconcileLifecycle(&data, before)
	if err := s.save(data); err != nil {
		return Grant{}, err
	}
	s.signalNewEvents(eventSequence, data.NextEvent)
	return data.Grants[index], decisionErr
}

func decisionTokenVerifier(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func decisionTokenMatches(storedVerifier string, presented string) bool {
	if storedVerifier == "" {
		return false
	}
	if presented == "" {
		return false
	}
	expectedVerifier := decisionTokenVerifier(presented)
	storedHash := sha256.Sum256([]byte(storedVerifier))
	presentedHash := sha256.Sum256([]byte(expectedVerifier))
	return subtle.ConstantTimeCompare(storedHash[:], presentedHash[:]) == 1
}

func (s *Store) prepareDecision(grant Grant, approver string, status Status) (Grant, bool, error) {
	now := s.opts.Now().UTC()
	if grant.Status != StatusPending {
		return grant, false, ErrNotPending
	}
	if !now.Before(grant.PendingExpiresAt) {
		grant.ExpiredFrom = grant.Status
		grant.Status = StatusExpired
		grant.DecidedAt = now
		grant.NotificationDeliveryUnresolved = false
		return grant, true, ErrNotPending
	}
	grant.Status = status
	grant.DecidedAt = now
	grant.DecidedBy = approver
	grant.NotificationDeliveryUnresolved = false
	if status == StatusActive {
		grant.ExpiresAt = now.Add(s.durationFromGrant(grant))
	}
	return grant, true, nil
}
