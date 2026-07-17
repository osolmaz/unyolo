package grants

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/state"
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

const maxNotificationAttempts = 5

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

// ApprovalNotificationsDue returns pending approval deliveries in durable
// outbox order. SQLite-backed stores recover these entries after restart.
func (s *Store) ApprovalNotificationsDue() ([]Grant, error) {
	if s == nil {
		return nil, errors.New("grant store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return nil, err
	}
	before := grantSnapshots(data.Grants)
	eventSequence := data.NextEvent
	if err := s.refreshApprovalLifecycle(&data, before, eventSequence); err != nil {
		return nil, err
	}
	if s.database == nil {
		return pendingApprovalGrants(data.Grants, s.opts.Now().UTC()), nil
	}
	return s.sqliteApprovalNotificationsDue()
}

func (s *Store) refreshApprovalLifecycle(data *fileData, before map[string]Grant, eventSequence uint64) error {
	changed := s.prepareLifecycle(data)
	changed = s.reconcileLifecycle(data, before) || changed
	if !changed {
		return nil
	}
	if err := s.save(*data); err != nil {
		return err
	}
	s.signalNewEvents(eventSequence, data.NextEvent)
	return nil
}

func (s *Store) sqliteApprovalNotificationsDue() ([]Grant, error) {
	snapshot, err := s.database.GrantSnapshot(context.Background())
	if err != nil {
		return nil, err
	}
	loaded, err := fileDataFromSQLite(snapshot)
	if err != nil {
		return nil, err
	}
	return dueApprovalGrants(snapshot.Outbox, grantSnapshots(loaded.Grants), s.opts.Now().UTC()), nil
}

func dueApprovalGrants(records []state.NotificationOutboxRecord, byID map[string]Grant, now time.Time) []Grant {
	out := make([]Grant, 0)
	for _, record := range records {
		if !approvalOutboxDue(record, now) {
			continue
		}
		if grant, ok := byID[record.GrantID]; ok && grant.Status == StatusPending && grant.Notification == nil {
			out = append(out, grant)
		}
	}
	return out
}

func approvalOutboxDue(record state.NotificationOutboxRecord, now time.Time) bool {
	return record.Kind == "approval" && record.Attempts < maxNotificationAttempts &&
		(record.Status == "pending" || record.Status == "ambiguous") && !now.Before(record.AvailableAt)
}

func pendingApprovalGrants(grants []Grant, now time.Time) []Grant {
	out := make([]Grant, 0)
	for _, grant := range grants {
		if grant.Status == StatusPending && grant.Notification == nil &&
			(grant.NotificationClaimedAt.IsZero() || !now.Before(grant.NotificationClaimUntil)) {
			out = append(out, grant)
		}
	}
	return out
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
		clearNotificationClaim(&grant)
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
		clearNotificationClaim(&grant)
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

type notificationWriteMode uint8

const (
	notificationWriteAlways notificationWriteMode = iota
	notificationWriteClaimed
	notificationWriteMissing
)

// SetNotification records the editable operator notification for a grant.
func (s *Store) SetNotification(id string, ref MessageRef) (Grant, error) {
	grant, _, err := s.setNotification(id, time.Time{}, ref, notificationWriteAlways)
	return grant, err
}

// SetNotificationIfMissing records ref only when the grant has no notification.
// Consumers use this to recover the message reference carried by an accepted
// callback after an earlier send returned an ambiguous error.
func (s *Store) SetNotificationIfMissing(id string, ref MessageRef) (Grant, bool, error) {
	return s.setNotification(id, time.Time{}, ref, notificationWriteMissing)
}

// SetNotificationIfClaimed records ref only if claimedAt is still current.
func (s *Store) SetNotificationIfClaimed(id string, claimedAt time.Time, ref MessageRef) (Grant, bool, error) {
	return s.setNotification(id, claimedAt, ref, notificationWriteClaimed)
}

func (s *Store) setNotification(id string, claimedAt time.Time, ref MessageRef, mode notificationWriteMode) (Grant, bool, error) {
	if mode == notificationWriteClaimed && claimedAt.IsZero() {
		return Grant{}, false, nil
	}
	if err := validateMessageRef(ref); err != nil {
		return Grant{}, false, err
	}
	var out Grant
	recorded := false
	err := s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		out = grant
		if !notificationWriteAllowed(grant, claimedAt, mode) {
			return nil
		}
		grant.Notification = &ref
		grant.NotificationStatus = string(StatusPending)
		clearNotificationClaim(&grant)
		data.Grants[index] = grant
		out = grant
		recorded = true
		return nil
	})
	return out, recorded, err
}

func validateMessageRef(ref MessageRef) error {
	if ref.MessageID <= 0 {
		return errors.New("notification message id must be positive")
	}
	if len(ref.Kind) > 32 || len(ref.Renderer) > 64 || len(ref.Text) > 32*1024 || len(ref.PresentationJSON) > 64*1024 {
		return errors.New("notification reference exceeds bounds")
	}
	if err := validatePresentationSnapshot(ref); err != nil {
		return err
	}
	if err := validateRenderedSnapshot(ref); err != nil {
		return err
	}
	if ref.Kind == "telegram" && (ref.ChatID == 0 || ref.Renderer == "" || ref.Text == "" || ref.PresentationJSON == "" || ref.RenderedDigest == "") {
		return errors.New("telegram notification reference is incomplete")
	}
	return nil
}

func validatePresentationSnapshot(ref MessageRef) error {
	if ref.PresentationJSON != "" {
		var snapshot any
		if err := strictjson.Decode([]byte(ref.PresentationJSON), &snapshot, false); err != nil {
			return errors.New("notification presentation snapshot is invalid")
		}
		if !matchesDigest(ref.PresentationJSON, ref.PresentationDigest) {
			return errors.New("notification presentation digest does not match")
		}
	} else if ref.PresentationDigest != "" {
		return errors.New("notification presentation snapshot is missing")
	}
	return nil
}

func validateRenderedSnapshot(ref MessageRef) error {
	if ref.RenderedDigest != "" && !matchesDigest(ref.Text, ref.RenderedDigest) {
		return errors.New("notification rendered digest does not match")
	}
	return nil
}

func matchesDigest(value, digest string) bool {
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+sha256.Size*2 {
		return false
	}
	expected := sha256.Sum256([]byte(value))
	return digest == "sha256:"+hex.EncodeToString(expected[:])
}

func notificationWriteAllowed(grant Grant, claimedAt time.Time, mode notificationWriteMode) bool {
	switch mode {
	case notificationWriteClaimed:
		return grant.NotificationClaimedAt.Equal(claimedAt)
	case notificationWriteMissing:
		return grant.Notification == nil
	default:
		return true
	}
}

func clearNotificationClaim(grant *Grant) {
	grant.NotificationClaimedAt = time.Time{}
	grant.NotificationClaimUntil = time.Time{}
	grant.NotificationDeliveryUnresolved = false
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
	if (grant.Status != StatusActive && grant.Status != StatusConsumed && grant.Status != StatusRevoked) || grant.UsedCount <= 0 {
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
