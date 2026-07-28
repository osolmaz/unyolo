package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/osolmaz/unyolo/internal/storage/state/internal/dbsql"
	"github.com/osolmaz/unyolo/operation/digest"
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
	ReservationRevision                                           int
	MaxUses, RequestedMaxUses                                     *int
	RequestedMaxUsesDefaulted                                     bool
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
	if err := validatePlanRecord(plan); err != nil {
		return err
	}
	if err := queries.PutPlan(ctx, dbsql.PutPlanParams{Digest: plan.Digest, SchemaName: plan.SchemaName,
		Canonical: plan.Canonical, CreatedAt: formatTime(plan.CreatedAt)}); err != nil {
		return err
	}
	stored, err := queries.GetPlan(ctx, plan.Digest)
	if err != nil {
		return err
	}
	return verifyStoredPlan(stored, plan)
}

func validatePlanRecord(plan PlanRecord) error {
	if err := validatePlanContent(plan.SchemaName, plan.Canonical); err != nil {
		return err
	}
	if !plandigest.Valid(plan.Digest) || plan.Digest != plandigest.Digest(plan.Canonical) {
		return errors.New("immutable plan digest is invalid")
	}
	if plan.CreatedAt.IsZero() {
		return errors.New("immutable plan creation time is required")
	}
	return nil
}

func verifyStoredPlan(stored dbsql.Plan, plan PlanRecord) error {
	if stored.SchemaName != plan.SchemaName || !bytes.Equal(stored.Canonical, plan.Canonical) {
		return errors.New("plan digest collision")
	}
	if stored.CreatedAt != formatTime(plan.CreatedAt) {
		return errors.New("plan creation time collision")
	}
	return nil
}

func loadGrantSnapshot(ctx context.Context, queries *dbsql.Queries) (GrantSnapshot, error) {
	snapshot, err := loadGrants(ctx, queries)
	if err != nil {
		return GrantSnapshot{}, err
	}
	if snapshot.Events, err = loadGrantEvents(ctx, queries); err != nil {
		return GrantSnapshot{}, err
	}
	if snapshot.Decisions, err = loadGrantDecisions(ctx, queries); err != nil {
		return GrantSnapshot{}, err
	}
	if snapshot.Outbox, err = loadNotificationOutbox(ctx, queries); err != nil {
		return GrantSnapshot{}, err
	}
	return snapshot, nil
}

func loadGrants(ctx context.Context, queries *dbsql.Queries) (GrantSnapshot, error) {
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
	return snapshot, nil
}

func loadGrantEvents(ctx context.Context, queries *dbsql.Queries) ([]GrantLifecycleRecord, error) {
	events, err := queries.ListGrantLifecycleEvents(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]GrantLifecycleRecord, 0, len(events))
	for _, row := range events {
		occurredAt, err := parseTime(row.OccurredAt)
		if err != nil || row.Sequence < 1 {
			return nil, errors.New("invalid grant lifecycle event")
		}
		result = append(result, GrantLifecycleRecord{Sequence: uint64(row.Sequence), Cursor: row.Cursor,
			GrantID: row.SubjectID, Kind: row.Kind, Revision: row.Revision, OccurredAt: occurredAt, PayloadJSON: []byte(row.PayloadJson)})
	}
	return result, nil
}

func loadGrantDecisions(ctx context.Context, queries *dbsql.Queries) ([]GrantDecisionRecord, error) {
	decisions, err := queries.ListDecisionRecords(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]GrantDecisionRecord, 0, len(decisions))
	for _, row := range decisions {
		committedAt, err := parseTime(row.CommittedAt)
		if err != nil {
			return nil, errors.New("invalid grant decision record")
		}
		result = append(result, GrantDecisionRecord{Scope: row.Scope, RequestID: row.RequestID,
			Action: row.Action, IdempotencyKey: row.IdempotencyKey, CommandHash: row.CommandHash,
			ResultJSON: []byte(row.ResultJson), PreviousJSON: []byte(row.PreviousJson), EventCursor: row.EventCursor, CommittedAt: committedAt})
	}
	return result, nil
}

func loadNotificationOutbox(ctx context.Context, queries *dbsql.Queries) ([]NotificationOutboxRecord, error) {
	outbox, err := queries.ListNotificationOutbox(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]NotificationOutboxRecord, 0, len(outbox))
	for _, row := range outbox {
		record, err := decodeNotificationOutbox(row)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

func persistGrantChanges(ctx context.Context, queries *dbsql.Queries, before, after GrantSnapshot) error {
	if err := validateGrantSnapshotTransition(before, after); err != nil {
		return err
	}
	if err := persistGrants(ctx, queries, before.Grants, after.Grants); err != nil {
		return err
	}
	if err := persistGrantEvents(ctx, queries, before.Events, after.Events); err != nil {
		return err
	}
	if err := persistGrantDecisions(ctx, queries, before.Decisions, after.Decisions); err != nil {
		return err
	}
	return persistIndexedRecords(before.Outbox, after.Outbox, func(record NotificationOutboxRecord) int64 { return record.ID },
		func(old map[int64]NotificationOutboxRecord, record NotificationOutboxRecord) error {
			return persistOutboxRecord(ctx, queries, old, record)
		})
}

func persistGrants(ctx context.Context, queries *dbsql.Queries, before, after []GrantRecord) error {
	return persistIndexedRecords(before, after, func(record GrantRecord) string { return record.ID },
		func(old map[string]GrantRecord, record GrantRecord) error {
			return persistGrant(ctx, queries, old, record)
		})
}

func persistGrant(ctx context.Context, queries *dbsql.Queries, old map[string]GrantRecord, record GrantRecord) error {
	previous, exists := old[record.ID]
	if !exists {
		return queries.InsertGrant(ctx, insertGrantParams(record))
	}
	if reflect.DeepEqual(previous, record) {
		return nil
	}
	updated, err := queries.UpdateGrant(ctx, updateGrantParams(record, previous.Revision))
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrGrantStateConflict
	}
	return nil
}

func validateGrantSnapshotTransition(before, after GrantSnapshot) error {
	if err := validateGrantRetention(before.Grants, after.Grants); err != nil {
		return err
	}
	if err := validateEventImmutability(before.Events, after.Events); err != nil {
		return err
	}
	if err := validateDecisionRetention(before.Decisions, after.Decisions); err != nil {
		return err
	}
	return validateOutboxRetention(before.Outbox, after.Outbox)
}

func validateGrantRetention(before, after []GrantRecord) error {
	afterGrants := make(map[string]bool, len(after))
	for _, record := range after {
		afterGrants[record.ID] = true
	}
	for _, record := range before {
		if !afterGrants[record.ID] {
			return errors.New("grant deletion is unsupported")
		}
	}
	return nil
}

func validateEventImmutability(before, after []GrantLifecycleRecord) error {
	oldEvents := make(map[uint64]GrantLifecycleRecord, len(before))
	for _, record := range before {
		oldEvents[record.Sequence] = record
	}
	for _, record := range after {
		if previous, exists := oldEvents[record.Sequence]; exists && !reflect.DeepEqual(previous, record) {
			return errors.New("grant lifecycle event is immutable")
		}
	}
	return nil
}

func validateDecisionRetention(before, after []GrantDecisionRecord) error {
	oldDecisions := make(map[string]GrantDecisionRecord, len(before))
	for _, record := range before {
		oldDecisions[record.Scope] = record
	}
	afterDecisions := make(map[string]bool, len(after))
	for _, record := range after {
		afterDecisions[record.Scope] = true
		if previous, exists := oldDecisions[record.Scope]; exists && !reflect.DeepEqual(previous, record) {
			return errors.New("grant decision record is immutable")
		}
	}
	for _, record := range before {
		if !afterDecisions[record.Scope] {
			return errors.New("grant decision record deletion is unsupported")
		}
	}
	return nil
}

func validateOutboxRetention(before, after []NotificationOutboxRecord) error {
	afterOutbox := make(map[int64]bool, len(after))
	for _, record := range after {
		if record.ID > 0 {
			afterOutbox[record.ID] = true
		}
	}
	for _, record := range before {
		if !afterOutbox[record.ID] {
			return errors.New("notification outbox deletion is unsupported")
		}
	}
	return nil
}

func persistGrantEvents(ctx context.Context, queries *dbsql.Queries, before, after []GrantLifecycleRecord) error {
	if err := pruneGrantEvents(ctx, queries, before, after); err != nil {
		return err
	}
	old := make(map[uint64]bool, len(before))
	for _, record := range before {
		old[record.Sequence] = true
	}
	for _, record := range after {
		if old[record.Sequence] {
			continue
		}
		if err := insertGrantEvent(ctx, queries, record); err != nil {
			return err
		}
	}
	return nil
}

func pruneGrantEvents(ctx context.Context, queries *dbsql.Queries, before, after []GrantLifecycleRecord) error {
	if len(after) == 0 || (len(before) > 0 && after[0].Sequence <= before[0].Sequence) {
		return nil
	}
	sequence, err := lifecycleSequenceInt64(after[0].Sequence)
	if err != nil {
		return err
	}
	return queries.DeleteGrantLifecycleEventsBefore(ctx, sequence)
}

func insertGrantEvent(ctx context.Context, queries *dbsql.Queries, record GrantLifecycleRecord) error {
	sequence, err := lifecycleSequenceInt64(record.Sequence)
	if err != nil {
		return err
	}
	return queries.InsertGrantLifecycleEvent(ctx, dbsql.InsertGrantLifecycleEventParams{Sequence: sequence, Cursor: record.Cursor,
		SubjectID: record.GrantID, Kind: record.Kind, Revision: record.Revision, OccurredAt: formatTime(record.OccurredAt), PayloadJson: string(record.PayloadJSON)})
}

func lifecycleSequenceInt64(sequence uint64) (int64, error) {
	if sequence > math.MaxInt64 {
		return 0, errors.New("grant lifecycle sequence overflow")
	}
	return int64(sequence), nil // #nosec G115 -- sequence is bounded by math.MaxInt64.
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

func persistIndexedRecords[Key comparable, Record any](before, after []Record, key func(Record) Key,
	persist func(map[Key]Record, Record) error,
) error {
	old := indexRecords(before, key)
	return persistRecords(after, func(record Record) error { return persist(old, record) })
}

func indexRecords[Key comparable, Record any](records []Record, key func(Record) Key) map[Key]Record {
	result := make(map[Key]Record, len(records))
	for _, record := range records {
		result[key(record)] = record
	}
	return result
}

func persistRecords[Record any](records []Record, persist func(Record) error) error {
	for _, record := range records {
		if err := persist(record); err != nil {
			return err
		}
	}
	return nil
}

func persistOutboxRecord(ctx context.Context, queries *dbsql.Queries, old map[int64]NotificationOutboxRecord, record NotificationOutboxRecord) error {
	previous, exists := old[record.ID]
	if !exists {
		if record.ID != 0 {
			return errors.New("notification outbox id is invalid")
		}
		return queries.InsertNotificationOutbox(ctx, insertNotificationOutboxParams(record))
	}
	if reflect.DeepEqual(previous, record) {
		return nil
	}
	updated, err := queries.UpdateNotificationOutbox(ctx, updateNotificationOutboxParams(record, previous))
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrGrantStateConflict
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
		ReservationRetained: row.ReservationRetained == 1, ReservationRevision: int(row.ReservationRevision), MaxUses: intPointer(row.MaxUses),
		RequestedMaxUses: intPointer(row.RequestedMaxUses), RequestedMaxUsesDefaulted: row.RequestedMaxUsesDefaulted == 1,
		ExpiredFrom: row.ExpiredFrom.String, NotificationJSON: bytesValue(row.NotificationJson),
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
		ReservationRevision: int64(record.ReservationRevision), MaxUses: nullableInt(record.MaxUses), RequestedMaxUses: nullableInt(record.RequestedMaxUses),
		RequestedMaxUsesDefaulted: boolInt(record.RequestedMaxUsesDefaulted),
		ExpiredFrom:               nullableString(record.ExpiredFrom), NotificationJson: nullableBytes(record.NotificationJSON), NotificationStatus: record.NotificationStatus,
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
		MaxUses: insert.MaxUses, RequestedMaxUses: insert.RequestedMaxUses,
		RequestedMaxUsesDefaulted: insert.RequestedMaxUsesDefaulted, ExpiredFrom: insert.ExpiredFrom,
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

func intPointer(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	converted := int(value.Int64)
	return &converted
}

func nullableInt(value *int) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*value), Valid: true}
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
