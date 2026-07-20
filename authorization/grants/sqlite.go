package grants

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/authorization/budget"
	"github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/internal/storage/state"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/operation/digest"
)

func fileDataFromSQLite(snapshot state.GrantSnapshot) (fileData, error) {
	data := fileData{Version: grantFileVersion, NextEvent: 1}
	var err error
	if data.Grants, err = convertRecords(snapshot.Grants, grantFromSQLite); err != nil {
		return fileData{}, err
	}
	if data.Events, data.NextEvent, err = eventsFromSQLite(snapshot.Events); err != nil {
		return fileData{}, err
	}
	if data.DecisionRecords, err = convertRecords(snapshot.Decisions, decisionFromSQLite); err != nil {
		return fileData{}, err
	}
	if err := validateApprovalOutbox(snapshot.Grants, snapshot.Outbox); err != nil {
		return fileData{}, err
	}
	return data, nil
}

func eventsFromSQLite(records []state.GrantLifecycleRecord) ([]lifecycleEventRecord, uint64, error) {
	result := make([]lifecycleEventRecord, 0, len(records))
	next := uint64(1)
	for _, record := range records {
		var event lifecycleEventRecord
		if err := strictjson.Decode(record.PayloadJSON, &event, true); err != nil {
			return nil, 0, fmt.Errorf("decode grant lifecycle event: %w", err)
		}
		if !eventMatchesRecord(event, record) {
			return nil, 0, ErrUnsupportedState
		}
		result = append(result, event)
		next = event.Sequence + 1
	}
	return result, next, nil
}

func eventMatchesRecord(event lifecycleEventRecord, record state.GrantLifecycleRecord) bool {
	return event.Sequence == record.Sequence && event.GrantID == record.GrantID && string(event.Kind) == record.Kind &&
		event.Revision == record.Revision && event.Time.Equal(record.OccurredAt) && encodeEventCursor(event.Sequence) == record.Cursor
}

func fileDataToSQLite(data fileData, previousOutbox []state.NotificationOutboxRecord, now time.Time) (state.GrantSnapshot, error) {
	grants, err := convertRecords(data.Grants, grantToSQLite)
	if err != nil {
		return state.GrantSnapshot{}, err
	}
	events, err := eventsToSQLite(data.Events)
	if err != nil {
		return state.GrantSnapshot{}, err
	}
	decisions, err := convertRecords(data.DecisionRecords, decisionToSQLite)
	if err != nil {
		return state.GrantSnapshot{}, err
	}
	outbox, err := reconcileApprovalOutbox(data.Grants, previousOutbox, now)
	if err != nil {
		return state.GrantSnapshot{}, err
	}
	return state.GrantSnapshot{Grants: grants, Events: events, Decisions: decisions, Outbox: outbox}, nil
}

func eventsToSQLite(events []lifecycleEventRecord) ([]state.GrantLifecycleRecord, error) {
	result := make([]state.GrantLifecycleRecord, 0, len(events))
	for _, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		result = append(result, state.GrantLifecycleRecord{Sequence: event.Sequence, Cursor: encodeEventCursor(event.Sequence),
			GrantID: event.GrantID, Kind: string(event.Kind), Revision: event.Revision, OccurredAt: event.Time, PayloadJSON: payload})
	}
	return result, nil
}

func convertRecords[From, To any](records []From, convert func(From) (To, error)) ([]To, error) {
	result := make([]To, 0, len(records))
	for _, source := range records {
		record, err := convert(source)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

type approvalOutboxPayload struct {
	GrantID string `json:"grant_id"`
}

const approvalOutboxInitialDelay = 5 * time.Second

func reconcileApprovalOutbox(grants []Grant, previous []state.NotificationOutboxRecord, now time.Time) ([]state.NotificationOutboxRecord, error) {
	old := make(map[string]state.NotificationOutboxRecord, len(previous))
	for _, record := range previous {
		if record.Kind == "approval" {
			old[record.GrantID] = record
		}
	}
	result := make([]state.NotificationOutboxRecord, 0, len(grants))
	for _, grant := range grants {
		payload, err := json.Marshal(approvalOutboxPayload{GrantID: grant.ID})
		if err != nil {
			return nil, err
		}
		record, exists := old[grant.ID]
		before := record
		if !exists {
			record = state.NotificationOutboxRecord{GrantID: grant.ID, Kind: "approval", PayloadJSON: payload,
				IdempotencyKey: grant.ID + ":approval", Status: "pending", AvailableAt: grant.CreatedAt.Add(approvalOutboxInitialDelay),
				CreatedAt: grant.CreatedAt, UpdatedAt: now}
		}
		record.PayloadJSON = payload
		applyApprovalOutboxState(&record, grant, now)
		if exists && !reflect.DeepEqual(before, record) {
			record.UpdatedAt = now
		}
		result = append(result, record)
	}
	return result, nil
}

func applyApprovalOutboxState(record *state.NotificationOutboxRecord, grant Grant, now time.Time) {
	switch {
	case grant.Notification != nil:
		markApprovalDelivered(record, now)
	case grant.Status != StatusPending:
		markApprovalCanceled(record)
	case grant.NotificationDeliveryUnresolved:
		markApprovalAmbiguous(record, grant)
	case !grant.NotificationClaimedAt.IsZero():
		markApprovalClaimed(record, grant)
	default:
		markApprovalPending(record)
	}
}

func markApprovalDelivered(record *state.NotificationOutboxRecord, now time.Time) {
	if record.Status != "delivered" {
		record.DeliveredAt = now
	}
	record.Status = "delivered"
	record.ClaimedUntil = time.Time{}
	record.LastErrorCode = ""
}

func markApprovalCanceled(record *state.NotificationOutboxRecord) {
	resetApprovalStatus(record, "canceled")
}

func markApprovalAmbiguous(record *state.NotificationOutboxRecord, grant Grant) {
	record.Status = "ambiguous"
	record.ClaimedUntil = grant.NotificationClaimUntil
	record.AvailableAt = grant.NotificationClaimUntil
	record.LastErrorCode = "delivery_ambiguous"
}

func markApprovalClaimed(record *state.NotificationOutboxRecord, grant Grant) {
	if record.Status != "claimed" || !record.ClaimedUntil.Equal(grant.NotificationClaimUntil) {
		record.Attempts++
	}
	record.Status = "claimed"
	record.ClaimedUntil = grant.NotificationClaimUntil
	record.LastErrorCode = ""
}

func markApprovalPending(record *state.NotificationOutboxRecord) {
	resetApprovalStatus(record, "pending")
}

func resetApprovalStatus(record *state.NotificationOutboxRecord, status string) {
	record.Status = status
	record.ClaimedUntil = time.Time{}
	record.LastErrorCode = ""
}

func validateApprovalOutbox(grants []state.GrantRecord, records []state.NotificationOutboxRecord) error {
	grantIDs := make(map[string]bool, len(grants))
	for _, grant := range grants {
		grantIDs[grant.ID] = true
	}
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if !validApprovalOutboxRecord(record, grantIDs, seen) {
			return ErrUnsupportedState
		}
		seen[record.GrantID] = true
	}
	for id := range grantIDs {
		if !seen[id] {
			return errors.New("grant approval outbox record is missing")
		}
	}
	return nil
}

func validApprovalOutboxRecord(record state.NotificationOutboxRecord, grantIDs, seen map[string]bool) bool {
	if record.Kind != "approval" || !grantIDs[record.GrantID] || seen[record.GrantID] {
		return false
	}
	var payload approvalOutboxPayload
	return strictjson.Decode(record.PayloadJSON, &payload, true) == nil && payload.GrantID == record.GrantID
}

func grantToSQLite(grant Grant) (state.GrantRecord, error) {
	target, err := json.Marshal(grant.Target)
	if err != nil {
		return state.GrantRecord{}, err
	}
	attrs, err := json.Marshal(grant.Attrs)
	if err != nil {
		return state.GrantRecord{}, err
	}
	metadata, err := json.Marshal(grant.Metadata)
	if err != nil {
		return state.GrantRecord{}, err
	}
	var notification []byte
	if grant.Notification != nil {
		notification, err = json.Marshal(grant.Notification)
		if err != nil {
			return state.GrantRecord{}, err
		}
	}
	planDigest, err := metadataPlanDigest(grant.Metadata)
	if err != nil {
		return state.GrantRecord{}, err
	}
	return state.GrantRecord{ID: grant.ID, DecisionTokenVerifier: grant.DecisionTokenVerifier, Client: grant.Client,
		ClientRequestID: grant.ClientRequestID, Operation: grant.Operation, TargetJSON: target, AttrsJSON: attrs,
		MetadataJSON: metadata, PlanDigest: planDigest, Reason: grant.Reason, Status: string(grant.Status), Revision: grant.Revision,
		CreatedAt: grant.CreatedAt, PendingExpiresAt: grant.PendingExpiresAt, ExpiresAt: grant.ExpiresAt, Duration: grant.Duration,
		RequestedDuration: grant.RequestedDuration, PendingTimeout: grant.PendingTimeout, DecidedAt: grant.DecidedAt,
		DecidedBy: grant.DecidedBy, DecidedOnBehalfOf: grant.DecidedOnBehalfOf,
		UsedAt: grant.UsedAt, UsedCount: grant.UsedCount, UseRevision: grant.UseRevision, ReservedCount: grant.ReservedCount,
		ReservedAt: grant.ReservedAt, ReservationRetained: grant.ReservationRetained, ReservationRevision: grant.ReservationRevision,
		MaxUses: useLimitPointer(grant.MaxUses), RequestedMaxUses: useLimitPointer(grant.RequestedMaxUses),
		RequestedMaxUsesDefaulted: grant.RequestedMaxUsesDefaulted, ExpiredFrom: string(grant.ExpiredFrom),
		NotificationJSON: notification, NotificationStatus: grant.NotificationStatus, NotificationClaimedAt: grant.NotificationClaimedAt,
		NotificationClaimUntil: grant.NotificationClaimUntil, NotificationDeliveryUnresolved: grant.NotificationDeliveryUnresolved}, nil
}

func grantFromSQLite(record state.GrantRecord) (Grant, error) {
	target, attrs, metadata, notification, err := decodeGrantJSON(record)
	if err != nil {
		return Grant{}, err
	}
	digest, err := metadataPlanDigest(metadata)
	if err != nil || digest != record.PlanDigest {
		return Grant{}, errors.New("grant plan digest mismatch")
	}
	return Grant{ID: record.ID, DecisionTokenVerifier: record.DecisionTokenVerifier, Client: record.Client,
		ClientRequestID: record.ClientRequestID, Operation: record.Operation, Target: target, Attrs: attrs, Metadata: metadata,
		Reason: record.Reason, Status: Status(record.Status), Revision: record.Revision, CreatedAt: record.CreatedAt,
		PendingExpiresAt: record.PendingExpiresAt, ExpiresAt: record.ExpiresAt, Duration: record.Duration,
		RequestedDuration: record.RequestedDuration, PendingTimeout: record.PendingTimeout, DecidedAt: record.DecidedAt,
		DecidedBy: record.DecidedBy, DecidedOnBehalfOf: record.DecidedOnBehalfOf,
		UsedAt: record.UsedAt, UsedCount: record.UsedCount, UseRevision: record.UseRevision, ReservedCount: record.ReservedCount,
		ReservedAt: record.ReservedAt, ReservationRetained: record.ReservationRetained, ReservationRevision: record.ReservationRevision,
		MaxUses: useLimitValue(record.MaxUses), RequestedMaxUses: useLimitValue(record.RequestedMaxUses),
		RequestedMaxUsesDefaulted: record.RequestedMaxUsesDefaulted, ExpiredFrom: Status(record.ExpiredFrom),
		Notification: notification, NotificationStatus: record.NotificationStatus, NotificationClaimedAt: record.NotificationClaimedAt,
		NotificationClaimUntil: record.NotificationClaimUntil, NotificationDeliveryUnresolved: record.NotificationDeliveryUnresolved}, nil
}

func useLimitPointer(limit usebudget.Limit) *int {
	if limit.IsUnlimited() {
		return nil
	}
	value := int(limit)
	return &value
}

func useLimitValue(value *int) usebudget.Limit {
	if value == nil {
		return usebudget.Unlimited
	}
	return usebudget.Limit(*value)
}

func decodeGrantJSON(record state.GrantRecord) (policy.Target, map[string][]string, map[string]string, *MessageRef, error) {
	var target policy.Target
	if err := strictjson.Decode(record.TargetJSON, &target, true); err != nil {
		return target, nil, nil, nil, fmt.Errorf("decode grant target: %w", err)
	}
	attrs := map[string][]string{}
	if err := strictjson.Decode(record.AttrsJSON, &attrs, true); err != nil {
		return target, nil, nil, nil, fmt.Errorf("decode grant attributes: %w", err)
	}
	metadata := map[string]string{}
	if err := strictjson.Decode(record.MetadataJSON, &metadata, true); err != nil {
		return target, nil, nil, nil, fmt.Errorf("decode grant metadata: %w", err)
	}
	notification, err := decodeNotification(record.NotificationJSON)
	return target, attrs, metadata, notification, err
}

func decodeNotification(raw []byte) (*MessageRef, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var value MessageRef
	if err := strictjson.Decode(raw, &value, true); err != nil {
		return nil, fmt.Errorf("decode grant notification: %w", err)
	}
	if err := validateMessageRef(value); err != nil {
		return nil, fmt.Errorf("decode grant notification: %w", err)
	}
	return &value, nil
}

func metadataPlanDigest(metadata map[string]string) (string, error) {
	var found string
	for key, value := range metadata {
		if !strings.HasSuffix(key, "_plan_digest") {
			continue
		}
		if !plandigest.Valid(value) {
			return "", errors.New("grant plan digest is invalid")
		}
		if found != "" && found != value {
			return "", errors.New("grant has conflicting plan digests")
		}
		found = value
	}
	return found, nil
}

func decisionToSQLite(record decisionRecord) (state.GrantDecisionRecord, error) {
	requestID, action, key, ok := parseDecisionScope(record.Scope)
	if !ok {
		return state.GrantDecisionRecord{}, ErrUnsupportedState
	}
	result, err := json.Marshal(record.Result)
	if err != nil {
		return state.GrantDecisionRecord{}, err
	}
	previous, err := json.Marshal(record.Previous)
	if err != nil {
		return state.GrantDecisionRecord{}, err
	}
	return state.GrantDecisionRecord{Scope: record.Scope, RequestID: requestID, Action: action, IdempotencyKey: key,
		CommandHash: record.CommandHash, ResultJSON: result, PreviousJSON: previous, EventCursor: record.EventCursor, CommittedAt: record.CommittedAt}, nil
}

func decisionFromSQLite(record state.GrantDecisionRecord) (decisionRecord, error) {
	result, previous, err := decodeDecisionGrants(record)
	if err != nil {
		return decisionRecord{}, err
	}
	requestID, action, key, ok := parseDecisionScope(record.Scope)
	if !ok || requestID != record.RequestID || action != record.Action || key != record.IdempotencyKey {
		return decisionRecord{}, ErrUnsupportedState
	}
	return decisionRecord{Scope: record.Scope, CommandHash: record.CommandHash, Result: result, Previous: previous,
		EventCursor: record.EventCursor, CommittedAt: record.CommittedAt}, nil
}

func decodeDecisionGrants(record state.GrantDecisionRecord) (Grant, Grant, error) {
	var result, previous Grant
	if err := strictjson.Decode(record.ResultJSON, &result, true); err != nil {
		return Grant{}, Grant{}, fmt.Errorf("decode decision result: %w", err)
	}
	if err := strictjson.Decode(record.PreviousJSON, &previous, true); err != nil {
		return Grant{}, Grant{}, fmt.Errorf("decode previous decision state: %w", err)
	}
	return result, previous, nil
}

func parseDecisionScope(scope string) (string, string, string, bool) {
	parts := strings.Split(scope, "\x00")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
