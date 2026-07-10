package grants

import (
	"errors"
	"strconv"
	"time"

	"github.com/osolmaz/brokerkit/notify"
)

// MessageRef is the durable form of an editable operator notification.
type MessageRef = notify.MessageRef

// StatusUpdateKind describes why an operator notification needs an update.
type StatusUpdateKind string

const (
	StatusUpdateLifecycle           StatusUpdateKind = "lifecycle"
	StatusUpdateRetainedReservation StatusUpdateKind = "retained_reservation"
	StatusUpdateUsed                StatusUpdateKind = "used"
	StatusUpdateUsedExpired         StatusUpdateKind = "used_expired"
)

const (
	NotificationStatusReserved    = "reserved"
	NotificationStatusUsed        = "used"
	NotificationStatusUsedExpired = "used:expired"
)

// StatusUpdate remains due until MarkNotificationStatus records delivery.
type StatusUpdate struct {
	Grant              Grant
	Kind               StatusUpdateKind
	Status             Status
	NotificationStatus string
}

// NotificationClaim carries the fresh raw decision token for one claimed
// delivery attempt. Only its verifier is stored in Grant.
type NotificationClaim struct {
	Grant         Grant  `json:"grant"`
	DecisionToken string `json:"-"`
}

// NotificationStatusKey returns the durable delivery key for this update.
func (u StatusUpdate) NotificationStatusKey() string {
	if u.NotificationStatus != "" {
		return u.NotificationStatus
	}
	return string(u.Status)
}

// Cancel closes a pending grant, usually after notification delivery fails.
func (s *Store) Cancel(id string) error {
	return s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		if grant.Status != StatusPending {
			return nil
		}
		grant.Status = StatusCanceled
		grant.DecidedAt = s.opts.Now().UTC()
		grant.NotificationClaimedAt = time.Time{}
		grant.NotificationClaimUntil = time.Time{}
		grant.NotificationDeliveryUnresolved = false
		data.Grants[index] = grant
		return nil
	})
}

// CancelIfNotificationClaimed cancels only while claimedAt is current.
func (s *Store) CancelIfNotificationClaimed(id string, claimedAt time.Time) (Grant, bool, error) {
	if claimedAt.IsZero() {
		return Grant{}, false, nil
	}
	var out Grant
	canceled := false
	err := s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		out = grant
		if grant.Status != StatusPending || !grant.NotificationClaimedAt.Equal(claimedAt) {
			return nil
		}
		grant.Status = StatusCanceled
		grant.DecidedAt = s.opts.Now().UTC()
		grant.NotificationClaimedAt = time.Time{}
		grant.NotificationClaimUntil = time.Time{}
		grant.NotificationDeliveryUnresolved = false
		data.Grants[index] = grant
		out = grant
		canceled = true
		return nil
	})
	return out, canceled, err
}

// RetainNotificationClaim marks the current send attempt as ambiguous without
// canceling the grant or making the claim immediately reusable.
func (s *Store) RetainNotificationClaim(id string, claimedAt time.Time) (Grant, bool, error) {
	if claimedAt.IsZero() {
		return Grant{}, false, nil
	}
	var out Grant
	retained := false
	err := s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		out = grant
		if grant.Status != StatusPending || grant.Notification != nil || !grant.NotificationClaimedAt.Equal(claimedAt) {
			return nil
		}
		grant.NotificationDeliveryUnresolved = true
		data.Grants[index] = grant
		out = grant
		retained = true
		return nil
	})
	return out, retained, err
}

// ClaimNotification reserves notification delivery and rotates its decision
// token. Stale claims can be reclaimed after a process restart.
func (s *Store) ClaimNotification(id string, lease time.Duration) (NotificationClaim, bool, error) {
	if lease <= 0 {
		return NotificationClaim{}, false, errors.New("notification claim lease must be positive")
	}
	var out NotificationClaim
	claimed := false
	err := s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		out.Grant = grant
		now := s.opts.Now().UTC()
		if !notificationClaimIsAvailable(grant, now, lease) {
			return nil
		}
		grant, decisionToken, err := s.refreshDecisionToken(grant)
		if err != nil {
			return err
		}
		grant.NotificationClaimedAt = now
		grant.NotificationClaimUntil = now.Add(lease)
		grant.NotificationDeliveryUnresolved = false
		data.Grants[index] = grant
		out = NotificationClaim{Grant: grant, DecisionToken: decisionToken}
		claimed = true
		return nil
	})
	return out, claimed, err
}

func notificationClaimIsAvailable(grant Grant, now time.Time, lease time.Duration) bool {
	if grant.Status != StatusPending || grant.Notification != nil {
		return false
	}
	if grant.NotificationClaimedAt.IsZero() {
		return true
	}
	claimedUntil := grant.NotificationClaimUntil
	if claimedUntil.IsZero() {
		claimedUntil = grant.NotificationClaimedAt.Add(lease)
	}
	return !now.Before(claimedUntil)
}

// SetNotification records the editable operator notification for a grant.
func (s *Store) SetNotification(id string, ref MessageRef) (Grant, error) {
	grant, _, err := s.setNotification(id, time.Time{}, ref, false)
	return grant, err
}

// SetNotificationIfClaimed records ref only if claimedAt is still current.
func (s *Store) SetNotificationIfClaimed(id string, claimedAt time.Time, ref MessageRef) (Grant, bool, error) {
	return s.setNotification(id, claimedAt, ref, true)
}

func (s *Store) setNotification(id string, claimedAt time.Time, ref MessageRef, requireClaim bool) (Grant, bool, error) {
	if requireClaim && claimedAt.IsZero() {
		return Grant{}, false, nil
	}
	if ref.MessageID <= 0 {
		return Grant{}, false, errors.New("notification message id must be positive")
	}
	var out Grant
	recorded := false
	err := s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		out = grant
		if requireClaim && !grant.NotificationClaimedAt.Equal(claimedAt) {
			return nil
		}
		grant.Notification = &ref
		grant.NotificationStatus = string(StatusPending)
		grant.NotificationClaimedAt = time.Time{}
		grant.NotificationClaimUntil = time.Time{}
		grant.NotificationDeliveryUnresolved = false
		data.Grants[index] = grant
		out = grant
		recorded = true
		return nil
	})
	return out, recorded, err
}

// MarkNotificationStatus records successful delivery of one status update.
func (s *Store) MarkNotificationStatus(id string, status string) error {
	if status == "" {
		return errors.New("notification status is required")
	}
	return s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		grant.NotificationStatus = status
		data.Grants[index] = grant
		return nil
	})
}

// StatusUpdatesDue expires grants, recovers stale reservations, and returns
// notification updates that have not been delivered successfully.
func (s *Store) StatusUpdatesDue() ([]StatusUpdate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return nil, err
	}
	changed := s.prepareLifecycle(&data)
	due := statusUpdatesNeedingDelivery(data.Grants)
	if changed {
		if err := s.save(data); err != nil {
			return nil, err
		}
	}
	return due, nil
}

func statusUpdatesNeedingDelivery(grants []Grant) []StatusUpdate {
	updates := make([]StatusUpdate, 0)
	for _, grant := range grants {
		if update, ok := statusUpdateNeedingDelivery(grant); ok {
			updates = append(updates, update)
		}
	}
	return updates
}

func statusUpdateNeedingDelivery(grant Grant) (StatusUpdate, bool) {
	if grant.Notification == nil || grant.Notification.MessageID == 0 {
		return StatusUpdate{}, false
	}
	if update, ok := retainedReservationUpdate(grant); ok {
		return update, grant.NotificationStatus != update.NotificationStatusKey()
	}
	if update, ok := usedExpiredUpdate(grant); ok {
		return update, grant.NotificationStatus != update.NotificationStatusKey()
	}
	if update, ok := usedUpdate(grant); ok {
		return update, grant.NotificationStatus != update.NotificationStatusKey()
	}
	return lifecycleUpdate(grant)
}

func retainedReservationUpdate(grant Grant) (StatusUpdate, bool) {
	if !grant.ReservationRetained || grant.ReservedCount <= 0 ||
		!reservationCanSettle(grant.Status) {
		return StatusUpdate{}, false
	}
	key := NotificationStatusReserved + ":" + string(grant.Status) + ":" + reservationRevision(grant)
	return newStatusUpdate(grant, StatusUpdateRetainedReservation, grant.Status, key), true
}

func usedExpiredUpdate(grant Grant) (StatusUpdate, bool) {
	if grant.Status != StatusExpired || grant.UsedCount <= 0 || grant.ReservedCount != 0 {
		return StatusUpdate{}, false
	}
	key := NotificationStatusUsedExpired + ":" + strconv.Itoa(grant.UseRevision)
	return newStatusUpdate(grant, StatusUpdateUsedExpired, StatusConsumed, key), true
}

func usedUpdate(grant Grant) (StatusUpdate, bool) {
	if (grant.Status != StatusActive && grant.Status != StatusRevoked) || grant.UsedCount <= 0 {
		return StatusUpdate{}, false
	}
	key := NotificationStatusUsed + ":" + string(grant.Status) + ":" + strconv.Itoa(grant.UseRevision)
	return newStatusUpdate(grant, StatusUpdateUsed, grant.Status, key), true
}

func reservationRevision(grant Grant) string {
	return strconv.Itoa(grant.ReservationRevision) + ":" + strconv.Itoa(grant.UsedCount) + ":" + strconv.Itoa(grant.ReservedCount)
}

func lifecycleUpdate(grant Grant) (StatusUpdate, bool) {
	switch grant.Status {
	case StatusActive, StatusDenied, StatusExpired, StatusConsumed, StatusRevoked, StatusCanceled:
		update := newStatusUpdate(grant, StatusUpdateLifecycle, grant.Status, string(grant.Status))
		return update, grant.NotificationStatus != update.NotificationStatusKey()
	default:
		return StatusUpdate{}, false
	}
}

func newStatusUpdate(grant Grant, kind StatusUpdateKind, status Status, key string) StatusUpdate {
	return StatusUpdate{Grant: grant, Kind: kind, Status: status, NotificationStatus: key}
}

// mutate4go-manifest-begin
// {"version":1,"tested_at":"2026-07-10T14:15:32+08:00","module_hash":"f80e09f7cd7ec496a6b6bc2b8dba5633b59ae4c7cf672e1886b985fbe79ff738","functions":[{"id":"func/StatusUpdate.NotificationStatusKey","name":"StatusUpdate.NotificationStatusKey","line":46,"end_line":51,"hash":"be04ff1555749f5c34da2315d46dc9eff875007a1c693af7d07d327bd954f4fe"},{"id":"func/Store.Cancel","name":"Store.Cancel","line":54,"end_line":71,"hash":"a0d4e5f4249c01c523286b896ab2214e2ea64c4f08084edddb4b5bbd77d15901"},{"id":"func/Store.CancelIfNotificationClaimed","name":"Store.CancelIfNotificationClaimed","line":74,"end_line":100,"hash":"1a3fc00ee50ce73c5e567623539674bdeaa2308206a2d366300cf880b0850947"},{"id":"func/Store.RetainNotificationClaim","name":"Store.RetainNotificationClaim","line":104,"end_line":126,"hash":"a1eb37a815c5bbd44d56d97b22bac283b320fc9c6ee10e6a01be978cf4c32f2a"},{"id":"func/Store.ClaimNotification","name":"Store.ClaimNotification","line":130,"end_line":159,"hash":"cbe5c5ece449ba89324cea64fc8e2905df40558961f9d8cfa7739c2a7c5222b7"},{"id":"func/notificationClaimIsAvailable","name":"notificationClaimIsAvailable","line":161,"end_line":173,"hash":"89a5813c2798eb5572deef53edc260f41b6eec9690dde7876a638756bec9c7ba"},{"id":"func/Store.SetNotification","name":"Store.SetNotification","line":176,"end_line":179,"hash":"a58ef4e0ad22e821276c1ad5762b482aef1dd8fdc8e688f791e5efa1ab10f5a4"},{"id":"func/Store.SetNotificationIfClaimed","name":"Store.SetNotificationIfClaimed","line":182,"end_line":184,"hash":"12bcba4aa75024ffce423bcf334ece418ee9a304124c16a82bd29d9895791235"},{"id":"func/Store.setNotification","name":"Store.setNotification","line":186,"end_line":215,"hash":"948402e9e070ef321629429d3f1cabcde1a062c2816390ab713f8b29f27e1d78"},{"id":"func/Store.MarkNotificationStatus","name":"Store.MarkNotificationStatus","line":218,"end_line":231,"hash":"87c70bbd29bdc057f9a0cb0087426dd979acb72c328735cabfa584578aebc06f"},{"id":"func/Store.StatusUpdatesDue","name":"Store.StatusUpdatesDue","line":235,"end_line":250,"hash":"802ea528c2ea937c4643b94fbe9ea9b83a49b5968f6494425feb483dc53a21aa"},{"id":"func/statusUpdatesNeedingDelivery","name":"statusUpdatesNeedingDelivery","line":252,"end_line":260,"hash":"1f09cd1a9b6d7bc61ba1d6aec9755b5e5e4355eda568771570e9c9e953dde9ce"},{"id":"func/statusUpdateNeedingDelivery","name":"statusUpdateNeedingDelivery","line":262,"end_line":276,"hash":"d29cbf0ebd5fb9179a5fb27c1906eb0f6d2571b9894b4bea6ab775eaaacb700c"},{"id":"func/retainedReservationUpdate","name":"retainedReservationUpdate","line":278,"end_line":285,"hash":"7675ce7c068d0f5f3a72c6a3f7cddcf9ee31b5e47f7bf323f871e2255da03c41"},{"id":"func/usedExpiredUpdate","name":"usedExpiredUpdate","line":287,"end_line":293,"hash":"7eaf2b0df7553f9344259b8ea977894bd3661a7278f62425ec0909a003e9274f"},{"id":"func/usedUpdate","name":"usedUpdate","line":295,"end_line":301,"hash":"4f864a186a43d8a4241244bc8b1728578c616f094eed36ee67fbe6cd5e7608b1"},{"id":"func/reservationRevision","name":"reservationRevision","line":303,"end_line":305,"hash":"7ebe45efc68bb9b61cb6f4bba31b32964ab4e16d41d73576515a689e04ca9baf"},{"id":"func/lifecycleUpdate","name":"lifecycleUpdate","line":307,"end_line":315,"hash":"bbe3447c1ef84a5fbd9f007f801a8febafe48fb9c2744507e058d7b5c4c71316"},{"id":"func/newStatusUpdate","name":"newStatusUpdate","line":317,"end_line":319,"hash":"d3d87f3ca7d991e8751538cbb41f47242f20ce4e6d4235d4f434994f8a3a22bc"}]}
// mutate4go-manifest-end
