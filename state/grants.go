package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/state/internal/dbsql"
)

var ErrGrantStateConflict = errors.New("grant state revision conflict")

type GrantRecord struct {
	ID, DecisionTokenVerifier, Client, ClientRequestID, Operation string
	TargetJSON, AttrsJSON, MetadataJSON                           []byte
	PlanDigest, Reason, Status                                    string
	Revision                                                      int64
	CreatedAt, PendingExpiresAt                                   time.Time
	ExpiresAt                                                     time.Time
	Duration, RequestedDuration, PendingTimeout                   time.Duration
	DecidedAt                                                     time.Time
	DecidedBy, DecidedOnBehalfOf                                  string
	UsedAt                                                        time.Time
	UsedCount, UseRevision, ReservedCount                         int
	ReservedAt                                                    time.Time
	ReservationRetained                                           bool
	ReservationRevision, MaxUses, RequestedMaxUses                int
	ExpiredFrom                                                   string
	NotificationJSON                                              []byte
	NotificationStatus                                            string
	NotificationClaimedAt, NotificationClaimUntil                 time.Time
	NotificationDeliveryUnresolved                                bool
}

type GrantLifecycleRecord struct {
	Sequence    uint64
	Cursor      string
	GrantID     string
	Kind        string
	Revision    int64
	OccurredAt  time.Time
	PayloadJSON []byte
}

type GrantDecisionRecord struct {
	Scope, RequestID, Action, IdempotencyKey, CommandHash string
	ResultJSON, PreviousJSON                              []byte
	EventCursor                                           string
	CommittedAt                                           time.Time
}

type NotificationOutboxRecord struct {
	ID                        int64
	GrantID, Kind             string
	PayloadJSON               []byte
	IdempotencyKey, Status    string
	Attempts                  int
	AvailableAt, ClaimedUntil time.Time
	DeliveredAt               time.Time
	LastErrorCode             string
	CreatedAt, UpdatedAt      time.Time
}

type GrantSnapshot struct {
	Grants    []GrantRecord
	Events    []GrantLifecycleRecord
	Decisions []GrantDecisionRecord
	Outbox    []NotificationOutboxRecord
}

func (d *Database) GrantSnapshot(ctx context.Context) (GrantSnapshot, error) {
	return loadGrantSnapshot(ctx, d.queries)
}

// SaveGrantSnapshot atomically persists one lifecycle mutation. before is
// checked inside the SQL transaction so a stale in-memory snapshot cannot
// overwrite a newer grant revision.
func (d *Database) SaveGrantSnapshot(ctx context.Context, before, after GrantSnapshot) error {
	return d.saveGrantSnapshot(ctx, before, after, nil)
}

// SaveGrantSnapshotWithPlan commits an immutable plan and its grant lifecycle
// mutation together. A failure in either half rolls the complete request back.
func (d *Database) SaveGrantSnapshotWithPlan(ctx context.Context, before, after GrantSnapshot, plan PlanRecord) error {
	return d.saveGrantSnapshot(ctx, before, after, &plan)
}

func (d *Database) saveGrantSnapshot(ctx context.Context, before, after GrantSnapshot, plan *PlanRecord) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	queries := d.queries.WithTx(tx)
	current, err := loadGrantSnapshot(ctx, queries)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, before) {
		return ErrGrantStateConflict
	}
	if plan != nil {
		if err := putPlanWithQueries(ctx, queries, *plan); err != nil {
			return err
		}
	}
	if err := persistGrantChanges(ctx, queries, before, after); err != nil {
		return err
	}
	return tx.Commit()
}

func putPlanWithQueries(ctx context.Context, queries *dbsql.Queries, plan PlanRecord) error {
	if !plandigest.Valid(plan.Digest) || plan.Digest != plandigest.Digest(plan.Canonical) || strings.TrimSpace(plan.SchemaName) == "" ||
		len(plan.SchemaName) > 128 || len(plan.Canonical) == 0 || len(plan.Canonical) > 1<<20 || !bytes.Equal(bytes.TrimSpace(plan.Canonical), plan.Canonical) || plan.CreatedAt.IsZero() {
		return errors.New("immutable plan is invalid")
	}
	if err := queries.PutPlan(ctx, dbsql.PutPlanParams{Digest: plan.Digest, SchemaName: plan.SchemaName,
		Canonical: plan.Canonical, CreatedAt: formatTime(plan.CreatedAt)}); err != nil {
		return err
	}
	stored, err := queries.GetPlan(ctx, plan.Digest)
	if err != nil {
		return err
	}
	if stored.SchemaName != plan.SchemaName || !bytes.Equal(stored.Canonical, plan.Canonical) || stored.CreatedAt != formatTime(plan.CreatedAt) {
		return errors.New("plan digest collision")
	}
	return nil
}

func loadGrantSnapshot(ctx context.Context, queries *dbsql.Queries) (GrantSnapshot, error) {
	rows, err := queries.ListGrants(ctx)
	if err != nil {
		return GrantSnapshot{}, err
	}
	snapshot := GrantSnapshot{Grants: make([]GrantRecord, 0, len(rows))}
	for _, row := range rows {
		record, err := decodeGrantRecord(row)
		if err != nil {
			return GrantSnapshot{}, err
		}
		snapshot.Grants = append(snapshot.Grants, record)
	}
	events, err := queries.ListGrantLifecycleEvents(ctx)
	if err != nil {
		return GrantSnapshot{}, err
	}
	for _, row := range events {
		occurredAt, err := parseTime(row.OccurredAt)
		if err != nil || row.Sequence < 1 {
			return GrantSnapshot{}, errors.New("invalid grant lifecycle event")
		}
		snapshot.Events = append(snapshot.Events, GrantLifecycleRecord{Sequence: uint64(row.Sequence), Cursor: row.Cursor,
			GrantID: row.SubjectID, Kind: row.Kind, Revision: row.Revision, OccurredAt: occurredAt, PayloadJSON: []byte(row.PayloadJson)})
	}
	decisions, err := queries.ListDecisionRecords(ctx)
	if err != nil {
		return GrantSnapshot{}, err
	}
	for _, row := range decisions {
		committedAt, err := parseTime(row.CommittedAt)
		if err != nil {
			return GrantSnapshot{}, errors.New("invalid grant decision record")
		}
		snapshot.Decisions = append(snapshot.Decisions, GrantDecisionRecord{Scope: row.Scope, RequestID: row.RequestID,
			Action: row.Action, IdempotencyKey: row.IdempotencyKey, CommandHash: row.CommandHash,
			ResultJSON: []byte(row.ResultJson), PreviousJSON: []byte(row.PreviousJson), EventCursor: row.EventCursor, CommittedAt: committedAt})
	}
	outbox, err := queries.ListNotificationOutbox(ctx)
	if err != nil {
		return GrantSnapshot{}, err
	}
	for _, row := range outbox {
		record, err := decodeNotificationOutbox(row)
		if err != nil {
			return GrantSnapshot{}, err
		}
		snapshot.Outbox = append(snapshot.Outbox, record)
	}
	return snapshot, nil
}

func persistGrantChanges(ctx context.Context, queries *dbsql.Queries, before, after GrantSnapshot) error {
	if err := validateGrantSnapshotTransition(before, after); err != nil {
		return err
	}
	oldGrants := make(map[string]GrantRecord, len(before.Grants))
	for _, record := range before.Grants {
		oldGrants[record.ID] = record
	}
	for _, record := range after.Grants {
		previous, exists := oldGrants[record.ID]
		if !exists {
			if err := queries.InsertGrant(ctx, insertGrantParams(record)); err != nil {
				return err
			}
			continue
		}
		if reflect.DeepEqual(previous, record) {
			continue
		}
		params := updateGrantParams(record, previous.Revision)
		updated, err := queries.UpdateGrant(ctx, params)
		if err != nil {
			return err
		}
		if updated != 1 {
			return ErrGrantStateConflict
		}
	}
	if err := persistGrantEvents(ctx, queries, before.Events, after.Events); err != nil {
		return err
	}
	if err := persistGrantDecisions(ctx, queries, before.Decisions, after.Decisions); err != nil {
		return err
	}
	return persistNotificationOutbox(ctx, queries, before.Outbox, after.Outbox)
}

func validateGrantSnapshotTransition(before, after GrantSnapshot) error {
	afterGrants := make(map[string]bool, len(after.Grants))
	for _, record := range after.Grants {
		afterGrants[record.ID] = true
	}
	for _, record := range before.Grants {
		if !afterGrants[record.ID] {
			return errors.New("grant deletion is unsupported")
		}
	}
	oldEvents := make(map[uint64]GrantLifecycleRecord, len(before.Events))
	for _, record := range before.Events {
		oldEvents[record.Sequence] = record
	}
	for _, record := range after.Events {
		if previous, exists := oldEvents[record.Sequence]; exists && !reflect.DeepEqual(previous, record) {
			return errors.New("grant lifecycle event is immutable")
		}
	}
	oldDecisions := make(map[string]GrantDecisionRecord, len(before.Decisions))
	for _, record := range before.Decisions {
		oldDecisions[record.Scope] = record
	}
	afterDecisions := make(map[string]bool, len(after.Decisions))
	for _, record := range after.Decisions {
		afterDecisions[record.Scope] = true
		if previous, exists := oldDecisions[record.Scope]; exists && !reflect.DeepEqual(previous, record) {
			return errors.New("grant decision record is immutable")
		}
	}
	for _, record := range before.Decisions {
		if !afterDecisions[record.Scope] {
			return errors.New("grant decision record deletion is unsupported")
		}
	}
	afterOutbox := make(map[int64]bool, len(after.Outbox))
	for _, record := range after.Outbox {
		if record.ID > 0 {
			afterOutbox[record.ID] = true
		}
	}
	for _, record := range before.Outbox {
		if !afterOutbox[record.ID] {
			return errors.New("notification outbox deletion is unsupported")
		}
	}
	return nil
}

func persistGrantEvents(ctx context.Context, queries *dbsql.Queries, before, after []GrantLifecycleRecord) error {
	if len(after) > 0 && (len(before) == 0 || after[0].Sequence > before[0].Sequence) {
		if err := queries.DeleteGrantLifecycleEventsBefore(ctx, int64(after[0].Sequence)); err != nil {
			return err
		}
	}
	old := make(map[uint64]bool, len(before))
	for _, record := range before {
		old[record.Sequence] = true
	}
	for _, record := range after {
		if old[record.Sequence] {
			continue
		}
		if record.Sequence > uint64(^uint64(0)>>1) {
			return errors.New("grant lifecycle sequence overflow")
		}
		if err := queries.InsertGrantLifecycleEvent(ctx, dbsql.InsertGrantLifecycleEventParams{Sequence: int64(record.Sequence), Cursor: record.Cursor,
			SubjectID: record.GrantID, Kind: record.Kind, Revision: record.Revision, OccurredAt: formatTime(record.OccurredAt), PayloadJson: string(record.PayloadJSON)}); err != nil {
			return err
		}
	}
	return nil
}

func persistGrantDecisions(ctx context.Context, queries *dbsql.Queries, before, after []GrantDecisionRecord) error {
	old := make(map[string]bool, len(before))
	for _, record := range before {
		old[record.Scope] = true
	}
	for _, record := range after {
		if old[record.Scope] {
			continue
		}
		if err := queries.InsertDecisionRecord(ctx, dbsql.InsertDecisionRecordParams{Scope: record.Scope, RequestID: record.RequestID,
			Action: record.Action, IdempotencyKey: record.IdempotencyKey, CommandHash: record.CommandHash,
			ResultJson: string(record.ResultJSON), PreviousJson: string(record.PreviousJSON), EventCursor: record.EventCursor,
			CommittedAt: formatTime(record.CommittedAt)}); err != nil {
			return err
		}
	}
	return nil
}

func persistNotificationOutbox(ctx context.Context, queries *dbsql.Queries, before, after []NotificationOutboxRecord) error {
	old := make(map[int64]NotificationOutboxRecord, len(before))
	for _, record := range before {
		old[record.ID] = record
	}
	for _, record := range after {
		previous, exists := old[record.ID]
		if !exists {
			if record.ID != 0 {
				return errors.New("notification outbox id is invalid")
			}
			if err := queries.InsertNotificationOutbox(ctx, insertNotificationOutboxParams(record)); err != nil {
				return err
			}
			continue
		}
		if reflect.DeepEqual(previous, record) {
			continue
		}
		params := updateNotificationOutboxParams(record, previous)
		updated, err := queries.UpdateNotificationOutbox(ctx, params)
		if err != nil {
			return err
		}
		if updated != 1 {
			return ErrGrantStateConflict
		}
	}
	return nil
}

func decodeGrantRecord(row dbsql.Grant) (GrantRecord, error) {
	record := GrantRecord{ID: row.ID, DecisionTokenVerifier: row.DecisionTokenVerifier, Client: row.Client,
		ClientRequestID: row.ClientRequestID, Operation: row.Operation, TargetJSON: []byte(row.TargetJson), AttrsJSON: []byte(row.AttrsJson),
		MetadataJSON: []byte(row.MetadataJson), PlanDigest: row.PlanDigest.String, Reason: row.Reason, Status: row.Status, Revision: row.Revision,
		Duration: time.Duration(row.DurationNs), RequestedDuration: time.Duration(row.RequestedDurationNs), PendingTimeout: time.Duration(row.PendingTimeoutNs),
		DecidedBy: row.DecidedBy, DecidedOnBehalfOf: row.DecidedOnBehalfOf,
		UsedCount: int(row.UsedCount), UseRevision: int(row.UseRevision), ReservedCount: int(row.ReservedCount),
		ReservationRetained: row.ReservationRetained == 1, ReservationRevision: int(row.ReservationRevision), MaxUses: int(row.MaxUses),
		RequestedMaxUses: int(row.RequestedMaxUses), ExpiredFrom: row.ExpiredFrom.String, NotificationJSON: bytesValue(row.NotificationJson),
		NotificationStatus: row.NotificationStatus, NotificationDeliveryUnresolved: row.NotificationDeliveryUnresolved == 1}
	var err error
	for target, value := range map[*time.Time]string{&record.CreatedAt: row.CreatedAt, &record.PendingExpiresAt: row.PendingExpiresAt} {
		*target, err = parseTime(value)
		if err != nil {
			return GrantRecord{}, fmt.Errorf("parse grant timestamp: %w", err)
		}
	}
	for target, value := range map[*time.Time]sql.NullString{&record.ExpiresAt: row.ExpiresAt, &record.DecidedAt: row.DecidedAt,
		&record.UsedAt: row.UsedAt, &record.ReservedAt: row.ReservedAt, &record.NotificationClaimedAt: row.NotificationClaimedAt,
		&record.NotificationClaimUntil: row.NotificationClaimUntil} {
		*target, err = parseNullTime(value)
		if err != nil {
			return GrantRecord{}, fmt.Errorf("parse optional grant timestamp: %w", err)
		}
	}
	return record, nil
}

func insertGrantParams(record GrantRecord) dbsql.InsertGrantParams {
	return dbsql.InsertGrantParams{ID: record.ID, DecisionTokenVerifier: record.DecisionTokenVerifier, Client: record.Client,
		ClientRequestID: record.ClientRequestID, Operation: record.Operation, TargetJson: string(record.TargetJSON), AttrsJson: string(record.AttrsJSON),
		MetadataJson: string(record.MetadataJSON), PlanDigest: nullableString(record.PlanDigest), Reason: record.Reason, Status: record.Status, Revision: record.Revision,
		CreatedAt: formatTime(record.CreatedAt), PendingExpiresAt: formatTime(record.PendingExpiresAt), ExpiresAt: nullTime(record.ExpiresAt),
		DurationNs: int64(record.Duration), RequestedDurationNs: int64(record.RequestedDuration), PendingTimeoutNs: int64(record.PendingTimeout),
		DecidedAt: nullTime(record.DecidedAt), DecidedBy: record.DecidedBy, DecidedOnBehalfOf: record.DecidedOnBehalfOf,
		UsedAt: nullTime(record.UsedAt), UsedCount: int64(record.UsedCount), UseRevision: int64(record.UseRevision),
		ReservedCount: int64(record.ReservedCount), ReservedAt: nullTime(record.ReservedAt), ReservationRetained: boolInt(record.ReservationRetained),
		ReservationRevision: int64(record.ReservationRevision), MaxUses: int64(record.MaxUses), RequestedMaxUses: int64(record.RequestedMaxUses),
		ExpiredFrom: nullableString(record.ExpiredFrom), NotificationJson: nullableBytes(record.NotificationJSON), NotificationStatus: record.NotificationStatus,
		NotificationClaimedAt: nullTime(record.NotificationClaimedAt), NotificationClaimUntil: nullTime(record.NotificationClaimUntil),
		NotificationDeliveryUnresolved: boolInt(record.NotificationDeliveryUnresolved)}
}

func updateGrantParams(record GrantRecord, previousRevision int64) dbsql.UpdateGrantParams {
	insert := insertGrantParams(record)
	return dbsql.UpdateGrantParams{DecisionTokenVerifier: insert.DecisionTokenVerifier, Client: insert.Client, ClientRequestID: insert.ClientRequestID,
		Operation: insert.Operation, TargetJson: insert.TargetJson, AttrsJson: insert.AttrsJson, MetadataJson: insert.MetadataJson,
		PlanDigest: insert.PlanDigest, Reason: insert.Reason, Status: insert.Status, Revision: insert.Revision, CreatedAt: insert.CreatedAt,
		PendingExpiresAt: insert.PendingExpiresAt, ExpiresAt: insert.ExpiresAt, DurationNs: insert.DurationNs,
		RequestedDurationNs: insert.RequestedDurationNs, PendingTimeoutNs: insert.PendingTimeoutNs, DecidedAt: insert.DecidedAt,
		DecidedBy: insert.DecidedBy, DecidedOnBehalfOf: insert.DecidedOnBehalfOf,
		UsedAt: insert.UsedAt, UsedCount: insert.UsedCount, UseRevision: insert.UseRevision, ReservedCount: insert.ReservedCount,
		ReservedAt: insert.ReservedAt, ReservationRetained: insert.ReservationRetained, ReservationRevision: insert.ReservationRevision,
		MaxUses: insert.MaxUses, RequestedMaxUses: insert.RequestedMaxUses, ExpiredFrom: insert.ExpiredFrom,
		NotificationJson: insert.NotificationJson, NotificationStatus: insert.NotificationStatus,
		NotificationClaimedAt: insert.NotificationClaimedAt, NotificationClaimUntil: insert.NotificationClaimUntil,
		NotificationDeliveryUnresolved: insert.NotificationDeliveryUnresolved, ID: record.ID, Revision_2: previousRevision}
}

func nullTime(value time.Time) sql.NullString {
	if value.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: formatTime(value), Valid: true}
}
func parseNullTime(value sql.NullString) (time.Time, error) {
	if !value.Valid {
		return time.Time{}, nil
	}
	return parseTime(value.String)
}
func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func decodeNotificationOutbox(row dbsql.NotificationOutbox) (NotificationOutboxRecord, error) {
	availableAt, err := parseTime(row.AvailableAt)
	if err != nil {
		return NotificationOutboxRecord{}, errors.New("invalid notification outbox availability")
	}
	claimedUntil, err := parseNullTime(row.ClaimedUntil)
	if err != nil {
		return NotificationOutboxRecord{}, errors.New("invalid notification outbox claim")
	}
	deliveredAt, err := parseNullTime(row.DeliveredAt)
	if err != nil {
		return NotificationOutboxRecord{}, errors.New("invalid notification outbox delivery")
	}
	createdAt, err := parseTime(row.CreatedAt)
	if err != nil {
		return NotificationOutboxRecord{}, errors.New("invalid notification outbox creation")
	}
	updatedAt, err := parseTime(row.UpdatedAt)
	if err != nil {
		return NotificationOutboxRecord{}, errors.New("invalid notification outbox update")
	}
	return NotificationOutboxRecord{ID: row.ID, GrantID: row.GrantID, Kind: row.Kind, PayloadJSON: []byte(row.PayloadJson),
		IdempotencyKey: row.IdempotencyKey, Status: row.Status, Attempts: int(row.Attempts), AvailableAt: availableAt,
		ClaimedUntil: claimedUntil, DeliveredAt: deliveredAt, LastErrorCode: row.LastErrorCode, CreatedAt: createdAt, UpdatedAt: updatedAt}, nil
}

func insertNotificationOutboxParams(record NotificationOutboxRecord) dbsql.InsertNotificationOutboxParams {
	return dbsql.InsertNotificationOutboxParams{GrantID: record.GrantID, Kind: record.Kind, PayloadJson: string(record.PayloadJSON),
		IdempotencyKey: record.IdempotencyKey, Status: record.Status, Attempts: int64(record.Attempts), AvailableAt: formatTime(record.AvailableAt),
		ClaimedUntil: nullTime(record.ClaimedUntil), DeliveredAt: nullTime(record.DeliveredAt), LastErrorCode: record.LastErrorCode,
		CreatedAt: formatTime(record.CreatedAt), UpdatedAt: formatTime(record.UpdatedAt)}
}

func updateNotificationOutboxParams(record, previous NotificationOutboxRecord) dbsql.UpdateNotificationOutboxParams {
	return dbsql.UpdateNotificationOutboxParams{Kind: record.Kind, PayloadJson: string(record.PayloadJSON), IdempotencyKey: record.IdempotencyKey,
		Status: record.Status, Attempts: int64(record.Attempts), AvailableAt: formatTime(record.AvailableAt), ClaimedUntil: nullTime(record.ClaimedUntil),
		DeliveredAt: nullTime(record.DeliveredAt), LastErrorCode: record.LastErrorCode, UpdatedAt: formatTime(record.UpdatedAt),
		ID: record.ID, GrantID: record.GrantID, Status_2: previous.Status, Attempts_2: int64(previous.Attempts)}
}
