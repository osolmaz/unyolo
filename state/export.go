package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const (
	maxExportTableRows = 25_000
	maxExportBytes     = int64(64 << 20)
)

type redactedExport struct {
	Format        string                   `json:"format"`
	SchemaVersion int64                    `json:"schema_version"`
	Grants        []redactedGrant          `json:"grants"`
	Operations    []redactedOperation      `json:"operations"`
	Plans         []redactedPlan           `json:"plans"`
	Notifications []redactedNotification   `json:"notifications"`
	AuditRefs     []redactedAuditReference `json:"audit_refs"`
	Decisions     []redactedDecision       `json:"decisions"`
}

type redactedGrant struct {
	ID                     string  `json:"id"`
	Client                 string  `json:"client"`
	ClientRequestID        string  `json:"client_request_id,omitempty"`
	Operation              string  `json:"operation"`
	Status                 string  `json:"status"`
	Revision               int64   `json:"revision"`
	CreatedAt              string  `json:"created_at"`
	PendingExpiresAt       string  `json:"pending_expires_at"`
	ExpiresAt              *string `json:"expires_at,omitempty"`
	DecidedAt              *string `json:"decided_at,omitempty"`
	UsedCount              int64   `json:"used_count"`
	ReservedCount          int64   `json:"reserved_count"`
	ReservationRetained    bool    `json:"reservation_retained"`
	MaxUses                *int64  `json:"max_uses,omitempty"`
	ExpiredFrom            *string `json:"expired_from,omitempty"`
	NotificationStatus     string  `json:"notification_status,omitempty"`
	NotificationUnresolved bool    `json:"notification_delivery_unresolved"`
	NotificationRenderer   string  `json:"notification_renderer,omitempty"`
	PresentationDigest     string  `json:"notification_presentation_digest,omitempty"`
	RenderedDigest         string  `json:"notification_rendered_digest,omitempty"`
}

type redactedOperation struct {
	ID         string  `json:"id"`
	APIVersion string  `json:"api_version"`
	Broker     string  `json:"broker"`
	ClientID   string  `json:"client_id"`
	Operation  string  `json:"operation"`
	State      string  `json:"state"`
	Revision   int64   `json:"revision"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
	TerminalAt *string `json:"terminal_at,omitempty"`
	ApprovalID string  `json:"approval_id,omitempty"`
	PlanDigest *string `json:"plan_digest,omitempty"`
}

type redactedPlan struct {
	Digest     string `json:"digest"`
	SchemaName string `json:"schema_name"`
	CreatedAt  string `json:"created_at"`
}

type redactedNotification struct {
	ID            int64   `json:"id"`
	GrantID       string  `json:"grant_id"`
	Kind          string  `json:"kind"`
	Status        string  `json:"status"`
	Attempts      int64   `json:"attempts"`
	AvailableAt   string  `json:"available_at"`
	ClaimedUntil  *string `json:"claimed_until,omitempty"`
	DeliveredAt   *string `json:"delivered_at,omitempty"`
	LastErrorCode string  `json:"last_error_code,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type redactedAuditReference struct {
	Sequence    int64  `json:"sequence"`
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	Kind        string `json:"kind"`
	Revision    int64  `json:"revision"`
	OccurredAt  string `json:"occurred_at"`
}

type redactedDecision struct {
	RequestID   string `json:"request_id"`
	Action      string `json:"action"`
	CommittedAt string `json:"committed_at"`
}

// Export writes a deterministic bounded JSON projection without operation
// payloads, reasons, plan bodies, decision tokens, notification destinations,
// provider credentials, or command output.
func (d *Database) Export(ctx context.Context, destination string) error {
	if err := d.ValidateCurrentFormat(ctx); err != nil {
		return err
	}
	if err := validateMaintenanceDestination(d.directory, destination); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("state export destination already exists or is unavailable")
	}
	value, err := d.redactedExport(ctx)
	if err != nil {
		return err
	}
	return writeExportFile(destination, value)
}

func writeExportFile(destination string, value redactedExport) error {
	parent := filepath.Dir(destination)
	file, err := os.CreateTemp(parent, ".brokerkit-state-export-*.json")
	if err != nil {
		return err
	}
	path := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := encodeExportFile(file, value); err != nil {
		return err
	}
	if err := publishExportFile(path, destination); err != nil {
		return err
	}
	remove = false
	return syncDirectory(parent)
}

func encodeExportFile(file *os.File, value redactedExport) error {
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	limited := &boundedWriter{writer: file, remaining: maxExportBytes}
	encoder := json.NewEncoder(limited)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func publishExportFile(path, destination string) error {
	if err := os.Link(path, destination); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}

func (d *Database) redactedExport(ctx context.Context) (redactedExport, error) {
	value := redactedExport{Format: exportFormat, SchemaVersion: CurrentSchemaVersion}
	if err := d.populateCoreExport(ctx, &value); err != nil {
		return redactedExport{}, err
	}
	if err := d.populateAuditExport(ctx, &value); err != nil {
		return redactedExport{}, err
	}
	return value, nil
}

func (d *Database) populateCoreExport(ctx context.Context, value *redactedExport) error {
	if err := loadExport(&value.Grants, func() ([]redactedGrant, error) { return d.exportGrants(ctx) }); err != nil {
		return err
	}
	if err := loadExport(&value.Operations, func() ([]redactedOperation, error) { return d.exportOperations(ctx) }); err != nil {
		return err
	}
	if err := loadExport(&value.Plans, func() ([]redactedPlan, error) { return d.exportPlans(ctx) }); err != nil {
		return err
	}
	return loadExport(&value.Notifications, func() ([]redactedNotification, error) { return d.exportNotifications(ctx) })
}

func (d *Database) populateAuditExport(ctx context.Context, value *redactedExport) error {
	if err := loadExport(&value.AuditRefs, func() ([]redactedAuditReference, error) { return d.exportAuditReferences(ctx) }); err != nil {
		return err
	}
	return loadExport(&value.Decisions, func() ([]redactedDecision, error) {
		return exportRows(ctx, d.sql, `SELECT request_id, action, committed_at FROM decision_records
		ORDER BY request_id, action, committed_at LIMIT ?`, func(rows *sql.Rows) (redactedDecision, error) {
			var item redactedDecision
			scanErr := rows.Scan(&item.RequestID, &item.Action, &item.CommittedAt)
			return item, scanErr
		})
	})
}

func loadExport[T any](destination *T, load func() (T, error)) error {
	value, err := load()
	if err != nil {
		return err
	}
	*destination = value
	return nil
}

func (d *Database) exportPlans(ctx context.Context) ([]redactedPlan, error) {
	return exportRows(ctx, d.sql, `SELECT digest, schema_name, created_at FROM plans ORDER BY digest LIMIT ?`, func(rows *sql.Rows) (redactedPlan, error) {
		var item redactedPlan
		scanErr := rows.Scan(&item.Digest, &item.SchemaName, &item.CreatedAt)
		return item, scanErr
	})
}

func (d *Database) exportGrants(ctx context.Context) ([]redactedGrant, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, client, client_request_id, operation, status, revision, created_at,
		pending_expires_at, expires_at, decided_at, used_count, reserved_count, reservation_retained, max_uses,
		expired_from, notification_status, notification_delivery_unresolved, notification_json FROM grants ORDER BY id LIMIT ?`, maxExportTableRows+1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	values := make([]redactedGrant, 0)
	for rows.Next() {
		var item redactedGrant
		var expires, decided, expired, notification sql.NullString
		var maximum sql.NullInt64
		if err := rows.Scan(&item.ID, &item.Client, &item.ClientRequestID, &item.Operation, &item.Status, &item.Revision,
			&item.CreatedAt, &item.PendingExpiresAt, &expires, &decided, &item.UsedCount, &item.ReservedCount,
			&item.ReservationRetained, &maximum, &expired, &item.NotificationStatus, &item.NotificationUnresolved, &notification); err != nil {
			return nil, err
		}
		if notification.Valid {
			var reference struct {
				Renderer           string `json:"renderer"`
				PresentationDigest string `json:"presentation_digest"`
				RenderedDigest     string `json:"rendered_digest"`
			}
			if err := json.Unmarshal([]byte(notification.String), &reference); err != nil {
				return nil, errors.New("invalid persisted notification reference")
			}
			item.NotificationRenderer = reference.Renderer
			item.PresentationDigest = reference.PresentationDigest
			item.RenderedDigest = reference.RenderedDigest
		}
		item.ExpiresAt, item.DecidedAt, item.ExpiredFrom, item.MaxUses = stringPointer(expires), stringPointer(decided), stringPointer(expired), exportInt64Pointer(maximum)
		values = append(values, item)
	}
	return boundedRows(values, rows.Err())
}

func (d *Database) exportOperations(ctx context.Context) ([]redactedOperation, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, api_version, broker, client_id, operation, state,
		revision, created_at, updated_at, terminal_at, approval_id, plan_digest FROM operations ORDER BY id LIMIT ?`, maxExportTableRows+1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	values := make([]redactedOperation, 0)
	for rows.Next() {
		var item redactedOperation
		var terminal, digest sql.NullString
		if err := rows.Scan(&item.ID, &item.APIVersion, &item.Broker, &item.ClientID, &item.Operation,
			&item.State, &item.Revision, &item.CreatedAt, &item.UpdatedAt, &terminal, &item.ApprovalID, &digest); err != nil {
			return nil, err
		}
		item.TerminalAt, item.PlanDigest = stringPointer(terminal), stringPointer(digest)
		values = append(values, item)
	}
	return boundedRows(values, rows.Err())
}

func (d *Database) exportNotifications(ctx context.Context) ([]redactedNotification, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, grant_id, kind, status, attempts, available_at, claimed_until,
		delivered_at, last_error_code, created_at, updated_at FROM notification_outbox ORDER BY id LIMIT ?`, maxExportTableRows+1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	values := make([]redactedNotification, 0)
	for rows.Next() {
		var item redactedNotification
		var claimed, delivered sql.NullString
		if err := rows.Scan(&item.ID, &item.GrantID, &item.Kind, &item.Status, &item.Attempts, &item.AvailableAt,
			&claimed, &delivered, &item.LastErrorCode, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.ClaimedUntil, item.DeliveredAt = stringPointer(claimed), stringPointer(delivered)
		values = append(values, item)
	}
	return boundedRows(values, rows.Err())
}

func (d *Database) exportAuditReferences(ctx context.Context) ([]redactedAuditReference, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT sequence, subject_kind, subject_id, kind, revision, occurred_at
		FROM lifecycle_events ORDER BY sequence LIMIT ?`, maxExportTableRows+1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	values := make([]redactedAuditReference, 0)
	for rows.Next() {
		var item redactedAuditReference
		if err := rows.Scan(&item.Sequence, &item.SubjectKind, &item.SubjectID, &item.Kind, &item.Revision, &item.OccurredAt); err != nil {
			return nil, err
		}
		values = append(values, item)
	}
	return boundedRows(values, rows.Err())
}

func exportRows[T any](ctx context.Context, database *sql.DB, query string, scan func(*sql.Rows) (T, error)) ([]T, error) {
	rows, err := database.QueryContext(ctx, query, maxExportTableRows+1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	values := make([]T, 0)
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, item)
	}
	return boundedRows(values, rows.Err())
}

func boundedRows[T any](values []T, err error) ([]T, error) {
	if err != nil {
		return nil, err
	}
	if len(values) > maxExportTableRows {
		return nil, errors.New("state export exceeds the per-table row limit")
	}
	return values, nil
}

func stringPointer(value sql.NullString) *string {
	return nullablePointer(value.Valid, value.String)
}

func exportInt64Pointer(value sql.NullInt64) *int64 {
	return nullablePointer(value.Valid, value.Int64)
}

func nullablePointer[T any](valid bool, value T) *T {
	if !valid {
		return nil
	}
	return &value
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("state export exceeds the output size limit")
	}
	written, err := w.writer.Write(data)
	w.remaining -= int64(written)
	return written, err
}
