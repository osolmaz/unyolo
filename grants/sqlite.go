package grants

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
)

func fileDataFromSQLite(snapshot state.GrantSnapshot) (fileData, error) {
	data := fileData{Version: grantFileVersion, NextEvent: 1}
	for _, record := range snapshot.Grants {
		grant, err := grantFromSQLite(record)
		if err != nil {
			return fileData{}, err
		}
		data.Grants = append(data.Grants, grant)
	}
	for _, record := range snapshot.Events {
		var event lifecycleEventRecord
		if err := strictjson.Decode(record.PayloadJSON, &event, true); err != nil {
			return fileData{}, fmt.Errorf("decode grant lifecycle event: %w", err)
		}
		if event.Sequence != record.Sequence || event.GrantID != record.GrantID || string(event.Kind) != record.Kind ||
			event.Revision != record.Revision || !event.Time.Equal(record.OccurredAt) || encodeEventCursor(event.Sequence) != record.Cursor {
			return fileData{}, ErrUnsupportedState
		}
		data.Events = append(data.Events, event)
		data.NextEvent = event.Sequence + 1
	}
	for _, record := range snapshot.Decisions {
		decision, err := decisionFromSQLite(record)
		if err != nil {
			return fileData{}, err
		}
		data.DecisionRecords = append(data.DecisionRecords, decision)
	}
	if err := validateApprovalOutbox(snapshot.Grants, snapshot.Outbox); err != nil {
		return fileData{}, err
	}
	return data, nil
}

func fileDataToSQLite(data fileData, previousOutbox []state.NotificationOutboxRecord, now time.Time) (state.GrantSnapshot, error) {
	snapshot := state.GrantSnapshot{}
	for _, grant := range data.Grants {
		record, err := grantToSQLite(grant)
		if err != nil {
			return state.GrantSnapshot{}, err
		}
		snapshot.Grants = append(snapshot.Grants, record)
	}
	for _, event := range data.Events {
		payload, err := json.Marshal(event)
		if err != nil {
			return state.GrantSnapshot{}, err
		}
		snapshot.Events = append(snapshot.Events, state.GrantLifecycleRecord{Sequence: event.Sequence, Cursor: encodeEventCursor(event.Sequence),
			GrantID: event.GrantID, Kind: string(event.Kind), Revision: event.Revision, OccurredAt: event.Time, PayloadJSON: payload})
	}
	for _, decision := range data.DecisionRecords {
		record, err := decisionToSQLite(decision)
		if err != nil {
			return state.GrantSnapshot{}, err
		}
		snapshot.Decisions = append(snapshot.Decisions, record)
	}
	outbox, err := reconcileApprovalOutbox(data.Grants, previousOutbox, now)
	if err != nil {
		return state.GrantSnapshot{}, err
	}
	snapshot.Outbox = outbox
	return snapshot, nil
}

type approvalOutboxPayload struct {
	GrantID string `json:"grant_id"`
}

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
				IdempotencyKey: grant.ID + ":approval", Status: "pending", AvailableAt: grant.CreatedAt,
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
		if record.Status != "delivered" {
			record.DeliveredAt = now
		}
		record.Status = "delivered"
		record.ClaimedUntil = time.Time{}
		record.LastErrorCode = ""
	case grant.Status != StatusPending:
		record.Status = "canceled"
		record.ClaimedUntil = time.Time{}
		record.LastErrorCode = ""
	case grant.NotificationDeliveryUnresolved:
		record.Status = "ambiguous"
		record.ClaimedUntil = grant.NotificationClaimUntil
		record.AvailableAt = grant.NotificationClaimUntil
		record.LastErrorCode = "delivery_ambiguous"
	case !grant.NotificationClaimedAt.IsZero():
		if record.Status != "claimed" || !record.ClaimedUntil.Equal(grant.NotificationClaimUntil) {
			record.Attempts++
		}
		record.Status = "claimed"
		record.ClaimedUntil = grant.NotificationClaimUntil
		record.LastErrorCode = ""
	default:
		record.Status = "pending"
		record.ClaimedUntil = time.Time{}
		record.LastErrorCode = ""
	}
}

func validateApprovalOutbox(grants []state.GrantRecord, records []state.NotificationOutboxRecord) error {
	grantIDs := make(map[string]bool, len(grants))
	for _, grant := range grants {
		grantIDs[grant.ID] = true
	}
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		var payload approvalOutboxPayload
		if record.Kind != "approval" || !grantIDs[record.GrantID] || seen[record.GrantID] ||
			strictjson.Decode(record.PayloadJSON, &payload, true) != nil || payload.GrantID != record.GrantID {
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
		DecidedBy: grant.DecidedBy, DecidedOnBehalfOf: grant.DecidedOnBehalfOf, DecisionReason: grant.DecisionReason,
		UsedAt: grant.UsedAt, UsedCount: grant.UsedCount, UseRevision: grant.UseRevision, ReservedCount: grant.ReservedCount,
		ReservedAt: grant.ReservedAt, ReservationRetained: grant.ReservationRetained, ReservationRevision: grant.ReservationRevision,
		MaxUses: grant.MaxUses, RequestedMaxUses: grant.RequestedMaxUses, ExpiredFrom: string(grant.ExpiredFrom),
		NotificationJSON: notification, NotificationStatus: grant.NotificationStatus, NotificationClaimedAt: grant.NotificationClaimedAt,
		NotificationClaimUntil: grant.NotificationClaimUntil, NotificationDeliveryUnresolved: grant.NotificationDeliveryUnresolved}, nil
}

func grantFromSQLite(record state.GrantRecord) (Grant, error) {
	var target policy.Target
	if err := strictjson.Decode(record.TargetJSON, &target, true); err != nil {
		return Grant{}, fmt.Errorf("decode grant target: %w", err)
	}
	attrs := map[string][]string{}
	if err := strictjson.Decode(record.AttrsJSON, &attrs, true); err != nil {
		return Grant{}, fmt.Errorf("decode grant attributes: %w", err)
	}
	metadata := map[string]string{}
	if err := strictjson.Decode(record.MetadataJSON, &metadata, true); err != nil {
		return Grant{}, fmt.Errorf("decode grant metadata: %w", err)
	}
	var notification *MessageRef
	if len(record.NotificationJSON) > 0 {
		var value MessageRef
		if err := strictjson.Decode(record.NotificationJSON, &value, true); err != nil {
			return Grant{}, fmt.Errorf("decode grant notification: %w", err)
		}
		notification = &value
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
		DecidedBy: record.DecidedBy, DecidedOnBehalfOf: record.DecidedOnBehalfOf, DecisionReason: record.DecisionReason,
		UsedAt: record.UsedAt, UsedCount: record.UsedCount, UseRevision: record.UseRevision, ReservedCount: record.ReservedCount,
		ReservedAt: record.ReservedAt, ReservationRetained: record.ReservationRetained, ReservationRevision: record.ReservationRevision,
		MaxUses: record.MaxUses, RequestedMaxUses: record.RequestedMaxUses, ExpiredFrom: Status(record.ExpiredFrom),
		Notification: notification, NotificationStatus: record.NotificationStatus, NotificationClaimedAt: record.NotificationClaimedAt,
		NotificationClaimUntil: record.NotificationClaimUntil, NotificationDeliveryUnresolved: record.NotificationDeliveryUnresolved}, nil
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
	parts := strings.Split(record.Scope, "\x00")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
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
	return state.GrantDecisionRecord{Scope: record.Scope, RequestID: parts[0], Action: parts[1], IdempotencyKey: parts[2],
		CommandHash: record.CommandHash, ResultJSON: result, PreviousJSON: previous, EventCursor: record.EventCursor, CommittedAt: record.CommittedAt}, nil
}

func decisionFromSQLite(record state.GrantDecisionRecord) (decisionRecord, error) {
	var result, previous Grant
	if err := strictjson.Decode(record.ResultJSON, &result, true); err != nil {
		return decisionRecord{}, fmt.Errorf("decode decision result: %w", err)
	}
	if err := strictjson.Decode(record.PreviousJSON, &previous, true); err != nil {
		return decisionRecord{}, fmt.Errorf("decode previous decision state: %w", err)
	}
	parts := strings.Split(record.Scope, "\x00")
	if len(parts) != 3 || parts[0] != record.RequestID || parts[1] != record.Action || parts[2] != record.IdempotencyKey {
		return decisionRecord{}, ErrUnsupportedState
	}
	return decisionRecord{Scope: record.Scope, CommandHash: record.CommandHash, Result: result, Previous: previous,
		EventCursor: record.EventCursor, CommittedAt: record.CommittedAt}, nil
}
