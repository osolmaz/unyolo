package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/osolmaz/brokerkit/state/internal/dbsql"
)

var ErrNotFound = sql.ErrNoRows

type OperationRecord struct {
	ID               string
	APIVersion       string
	Broker           string
	ClientID         string
	IdempotencyKey   string
	Operation        string
	TargetJSON       []byte
	ArgumentsJSON    []byte
	Reason           string
	State            string
	Revision         int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
	TerminalAt       *time.Time
	ApprovalID       string
	PresentationJSON []byte
	ResultJSON       []byte
	ErrorJSON        []byte
	PlanDigest       string
}

type OperationListOptions struct {
	ClientID       string
	IdempotencyKey string
	State          string
	Cursor         string
	Limit          int
}

func (d *Database) InsertOperation(ctx context.Context, record OperationRecord) error {
	return insertOperation(ctx, d.queries, record)
}

// InsertOperationWithPlan commits an immutable plan and its operation in one
// transaction so execution can never observe an unbound operation.
func (d *Database) InsertOperationWithPlan(ctx context.Context, record OperationRecord, plan PlanRecord) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	queries := d.queries.WithTx(tx)
	if err := putPlanWithQueries(ctx, queries, plan); err != nil {
		return err
	}
	if record.PlanDigest != plan.Digest {
		return errors.New("operation plan digest does not match immutable plan")
	}
	if err := insertOperation(ctx, queries, record); err != nil {
		return err
	}
	return tx.Commit()
}

func insertOperation(ctx context.Context, queries *dbsql.Queries, record OperationRecord) error {
	return queries.InsertOperation(ctx, dbsql.InsertOperationParams{
		ID: record.ID, ApiVersion: record.APIVersion, Broker: record.Broker,
		ClientID: record.ClientID, IdempotencyKey: record.IdempotencyKey,
		Operation: record.Operation, TargetJson: string(record.TargetJSON),
		ArgumentsJson: string(record.ArgumentsJSON), Reason: record.Reason,
		State: record.State, Revision: record.Revision, CreatedAt: formatTime(record.CreatedAt),
		UpdatedAt: formatTime(record.UpdatedAt), TerminalAt: nullableTime(record.TerminalAt),
		ApprovalID: record.ApprovalID, PresentationJson: string(record.PresentationJSON),
		ResultJson: nullableBytes(record.ResultJSON), ErrorJson: nullableBytes(record.ErrorJSON),
		PlanDigest: nullableString(record.PlanDigest),
	})
}

func (d *Database) OperationByID(ctx context.Context, id string) (OperationRecord, error) {
	return d.operation(ctx, id, "")
}

func (d *Database) OperationForClient(ctx context.Context, id, clientID string) (OperationRecord, error) {
	return d.operation(ctx, id, clientID)
}

func (d *Database) operation(ctx context.Context, id, clientID string) (OperationRecord, error) {
	if clientID == "" {
		record, err := d.queries.GetOperationByID(ctx, id)
		return operationRecord(record, err)
	}
	record, err := d.queries.GetOperationForClient(ctx, dbsql.GetOperationForClientParams{ID: id, ClientID: clientID})
	return operationRecord(record, err)
}

func (d *Database) OperationByIdempotency(ctx context.Context, clientID, key string) (OperationRecord, error) {
	record, err := d.queries.FindOperationByIdempotency(ctx, dbsql.FindOperationByIdempotencyParams{ClientID: clientID, IdempotencyKey: key})
	return operationRecord(record, err)
}

// OperationsForClient returns a newest-first page. Cursor is the final
// operation ID from the preceding page and is validated against the client.
func (d *Database) OperationsForClient(ctx context.Context, options OperationListOptions) ([]OperationRecord, error) {
	cursorCreatedAt := ""
	if options.Cursor != "" {
		cursor, err := d.OperationForClient(ctx, options.Cursor, options.ClientID)
		if err != nil {
			return nil, err
		}
		cursorCreatedAt = formatTime(cursor.CreatedAt)
	}
	records, err := d.queries.ListOperationsForClient(ctx, dbsql.ListOperationsForClientParams{
		ClientID: options.ClientID, IdempotencyKey: options.IdempotencyKey, State: options.State,
		CursorCreatedAt: cursorCreatedAt, CursorID: options.Cursor, PageSize: int64(options.Limit),
	})
	if err != nil {
		return nil, err
	}
	result := make([]OperationRecord, 0, len(records))
	for _, record := range records {
		converted, convertErr := operationRecord(record, nil)
		if convertErr != nil {
			return nil, convertErr
		}
		result = append(result, converted)
	}
	return result, nil
}

func (d *Database) UnfinishedOperations(ctx context.Context) ([]OperationRecord, error) {
	records, err := d.queries.ListUnfinishedOperations(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]OperationRecord, 0, len(records))
	for _, record := range records {
		converted, err := operationRecord(record, nil)
		if err != nil {
			return nil, err
		}
		result = append(result, converted)
	}
	return result, nil
}

func (d *Database) CountOperations(ctx context.Context) (int64, error) {
	return d.queries.CountOperations(ctx)
}

func (d *Database) DeleteTerminalOperationsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	return d.queries.DeleteTerminalOperationsBefore(ctx, sql.NullString{String: formatTime(cutoff), Valid: true})
}

func (d *Database) UpdateOperation(ctx context.Context, record OperationRecord, expectedRevision int64) (bool, error) {
	return updateOperation(ctx, d.queries, record, expectedRevision)
}

// UpdateOperationWithPlan commits an immutable plan and its operation binding
// in one transaction.
func (d *Database) UpdateOperationWithPlan(ctx context.Context, record OperationRecord, expectedRevision int64, plan PlanRecord) (bool, error) {
	if record.PlanDigest != plan.Digest {
		return false, errors.New("operation plan digest does not match immutable plan")
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	queries := d.queries.WithTx(tx)
	if err := putPlanWithQueries(ctx, queries, plan); err != nil {
		return false, err
	}
	updated, err := updateOperation(ctx, queries, record, expectedRevision)
	if err != nil || !updated {
		return updated, err
	}
	return true, tx.Commit()
}

func updateOperation(ctx context.Context, queries *dbsql.Queries, record OperationRecord, expectedRevision int64) (bool, error) {
	count, err := queries.UpdateOperation(ctx, dbsql.UpdateOperationParams{
		State: record.State, Revision: record.Revision, UpdatedAt: formatTime(record.UpdatedAt),
		TerminalAt: nullableTime(record.TerminalAt), ApprovalID: record.ApprovalID,
		ResultJson: nullableBytes(record.ResultJSON), ErrorJson: nullableBytes(record.ErrorJSON),
		PlanDigest: nullableString(record.PlanDigest), ID: record.ID, Revision_2: expectedRevision,
	})
	return count == 1, err
}

func operationRecord(record dbsql.Operation, err error) (OperationRecord, error) {
	if err != nil {
		return OperationRecord{}, err
	}
	createdAt, err := parseTime(record.CreatedAt)
	if err != nil {
		return OperationRecord{}, fmt.Errorf("parse operation creation time: %w", err)
	}
	updatedAt, err := parseTime(record.UpdatedAt)
	if err != nil {
		return OperationRecord{}, fmt.Errorf("parse operation update time: %w", err)
	}
	terminalAt, err := parseNullableTime(record.TerminalAt)
	if err != nil {
		return OperationRecord{}, fmt.Errorf("parse operation terminal time: %w", err)
	}
	return OperationRecord{
		ID: record.ID, APIVersion: record.ApiVersion, Broker: record.Broker,
		ClientID: record.ClientID, IdempotencyKey: record.IdempotencyKey,
		Operation: record.Operation, TargetJSON: []byte(record.TargetJson),
		ArgumentsJSON: []byte(record.ArgumentsJson), Reason: record.Reason,
		State: record.State, Revision: record.Revision, CreatedAt: createdAt,
		UpdatedAt: updatedAt, TerminalAt: terminalAt, ApprovalID: record.ApprovalID,
		PresentationJSON: []byte(record.PresentationJson), ResultJSON: bytesValue(record.ResultJson),
		ErrorJSON: bytesValue(record.ErrorJson), PlanDigest: stringValue(record.PlanDigest),
	}, nil
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) { return time.Parse(time.RFC3339Nano, value) }

func nullableTime(value *time.Time) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: formatTime(*value), Valid: true}
}

func parseNullableTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseTime(value.String)
	return &parsed, err
}

func nullableBytes(value []byte) sql.NullString {
	return sql.NullString{String: string(value), Valid: len(value) > 0}
}

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func bytesValue(value sql.NullString) []byte {
	if !value.Valid {
		return nil
	}
	return []byte(value.String)
}

func stringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}
