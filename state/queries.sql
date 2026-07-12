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

-- name: ListUnfinishedOperations :many
SELECT * FROM operations
WHERE state NOT IN ('succeeded','failed','denied','expired','canceled')
ORDER BY created_at, id;

-- name: CountOperations :one
SELECT count(*) FROM operations;

-- name: DeleteTerminalOperationsBefore :execrows
DELETE FROM operations
WHERE terminal_at IS NOT NULL AND terminal_at < ?;

-- name: UpdateOperation :execrows
UPDATE operations SET
    state = ?, revision = ?, updated_at = ?, terminal_at = ?, approval_id = ?,
    result_json = ?, error_json = ?, plan_digest = ?
WHERE id = ? AND revision = ?;
