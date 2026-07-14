-- name: Health :one
SELECT 1;

-- name: PutPlan :exec
INSERT INTO plans (digest, schema_name, canonical, created_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(digest) DO NOTHING;

-- name: GetPlan :one
SELECT digest, schema_name, canonical, created_at
FROM plans
WHERE digest = ?;

-- name: CountPlans :one
SELECT count(*) FROM plans;

-- name: ListGrants :many
SELECT * FROM grants ORDER BY created_at, id;

-- name: InsertGrant :exec
INSERT INTO grants (
    id, decision_token_verifier, client, client_request_id, operation,
    target_json, attrs_json, metadata_json, plan_digest, reason, status,
    revision, created_at, pending_expires_at, expires_at, duration_ns,
    requested_duration_ns, pending_timeout_ns, decided_at, decided_by,
    decided_on_behalf_of, used_at, used_count, use_revision,
    reserved_count, reserved_at, reservation_retained, reservation_revision,
	max_uses, requested_max_uses, requested_max_uses_defaulted, expired_from, notification_json,
    notification_status, notification_claimed_at, notification_claim_until,
    notification_delivery_unresolved
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
	?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
);

-- name: UpdateGrant :execrows
UPDATE grants SET
    decision_token_verifier = ?, client = ?, client_request_id = ?, operation = ?,
    target_json = ?, attrs_json = ?, metadata_json = ?, plan_digest = ?, reason = ?,
    status = ?, revision = ?, created_at = ?, pending_expires_at = ?, expires_at = ?,
    duration_ns = ?, requested_duration_ns = ?, pending_timeout_ns = ?, decided_at = ?,
    decided_by = ?, decided_on_behalf_of = ?, used_at = ?,
    used_count = ?, use_revision = ?, reserved_count = ?, reserved_at = ?,
    reservation_retained = ?, reservation_revision = ?, max_uses = ?,
	requested_max_uses = ?, requested_max_uses_defaulted = ?, expired_from = ?, notification_json = ?,
    notification_status = ?, notification_claimed_at = ?, notification_claim_until = ?,
    notification_delivery_unresolved = ?
WHERE id = ? AND revision = ?;

-- name: ListGrantLifecycleEvents :many
SELECT * FROM lifecycle_events
WHERE subject_kind = 'grant'
ORDER BY sequence;

-- name: InsertGrantLifecycleEvent :exec
INSERT INTO lifecycle_events (
    sequence, cursor, subject_kind, subject_id, kind, revision, occurred_at, payload_json
) VALUES (?, ?, 'grant', ?, ?, ?, ?, ?);

-- name: DeleteGrantLifecycleEventsBefore :exec
DELETE FROM lifecycle_events WHERE subject_kind = 'grant' AND sequence < ?;

-- name: ListDecisionRecords :many
SELECT * FROM decision_records ORDER BY committed_at, scope;

-- name: InsertDecisionRecord :exec
INSERT INTO decision_records (
    scope, request_id, action, idempotency_key, command_hash,
    result_json, previous_json, event_cursor, committed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListNotificationOutbox :many
SELECT * FROM notification_outbox ORDER BY id;

-- name: InsertNotificationOutbox :exec
INSERT INTO notification_outbox (
    grant_id, kind, payload_json, idempotency_key, status, attempts,
    available_at, claimed_until, delivered_at, last_error_code, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateNotificationOutbox :execrows
UPDATE notification_outbox SET
    kind = ?, payload_json = ?, idempotency_key = ?, status = ?, attempts = ?,
    available_at = ?, claimed_until = ?, delivered_at = ?, last_error_code = ?, updated_at = ?
WHERE id = ? AND grant_id = ? AND status = ? AND attempts = ?;

-- name: InsertOperation :exec
INSERT INTO operations (
    id, api_version, broker, client_id, idempotency_key, operation,
    target_json, arguments_json, reason, state, revision, created_at, updated_at,
    terminal_at, approval_id, presentation_json, result_json, error_json, plan_digest
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOperationByID :one
SELECT * FROM operations WHERE id = ?;

-- name: GetOperationForClient :one
SELECT * FROM operations WHERE id = ? AND client_id = ?;

-- name: FindOperationByIdempotency :one
SELECT * FROM operations WHERE client_id = ? AND idempotency_key = ?;

-- name: ListOperationsForClient :many
SELECT * FROM operations
WHERE client_id = sqlc.arg(client_id)
  AND (CAST(sqlc.arg(idempotency_key) AS TEXT) = '' OR idempotency_key = CAST(sqlc.arg(idempotency_key) AS TEXT))
  AND (CAST(sqlc.arg(state) AS TEXT) = '' OR state = CAST(sqlc.arg(state) AS TEXT))
  AND (
    CAST(sqlc.arg(cursor_created_at) AS TEXT) = ''
    OR created_at < CAST(sqlc.arg(cursor_created_at) AS TEXT)
    OR (created_at = CAST(sqlc.arg(cursor_created_at) AS TEXT) AND id < sqlc.arg(cursor_id))
  )
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_size);

-- name: ListUnfinishedOperations :many
SELECT * FROM operations
WHERE state NOT IN ('succeeded','failed','denied','expired','canceled')
ORDER BY created_at, id;

-- name: CountOperations :one
SELECT count(*) FROM operations;

-- name: GetOperationUsage :one
SELECT
    CAST(COALESCE(SUM(CASE WHEN client_id = sqlc.arg(client_id) AND state NOT IN ('succeeded','failed','denied','expired','canceled') THEN 1 ELSE 0 END), 0) AS INTEGER) AS client_active,
    CAST((SELECT COUNT(*) FROM grants WHERE client = sqlc.arg(client_id) AND status = 'pending') AS INTEGER) AS client_pending,
    CAST(COALESCE(SUM(CASE WHEN state NOT IN ('succeeded','failed','denied','expired','canceled') THEN 1 ELSE 0 END), 0) AS INTEGER) AS global_active,
    CAST(COALESCE(SUM(CASE WHEN state = 'executing' THEN 1 ELSE 0 END), 0) AS INTEGER) AS global_executing
FROM operations;

-- name: DeleteTerminalOperationsBefore :execrows
DELETE FROM operations
WHERE terminal_at IS NOT NULL AND terminal_at < ?;

-- name: UpdateOperation :execrows
UPDATE operations SET
    state = ?, revision = ?, updated_at = ?, terminal_at = ?, approval_id = ?,
    result_json = ?, error_json = ?, plan_digest = ?
WHERE id = ? AND revision = ?;
