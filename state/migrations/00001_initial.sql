-- +goose Up
CREATE TABLE plans (
    digest TEXT PRIMARY KEY CHECK(length(digest) = 64),
    schema_name TEXT NOT NULL CHECK(length(schema_name) BETWEEN 1 AND 128),
    canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 1048576),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE grants (
    id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128),
    decision_token_verifier TEXT NOT NULL CHECK(length(decision_token_verifier) BETWEEN 1 AND 256),
    client TEXT NOT NULL CHECK(length(client) BETWEEN 1 AND 128),
    client_request_id TEXT NOT NULL DEFAULT '' CHECK(length(client_request_id) <= 128),
    operation TEXT NOT NULL CHECK(length(operation) BETWEEN 1 AND 128),
    target_json TEXT NOT NULL CHECK(length(target_json) BETWEEN 2 AND 16384 AND json_valid(target_json)),
    attrs_json TEXT NOT NULL DEFAULT '{}' CHECK(length(attrs_json) <= 16384 AND json_valid(attrs_json)),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK(length(metadata_json) <= 16384 AND json_valid(metadata_json)),
    plan_digest TEXT REFERENCES plans(digest),
    reason TEXT NOT NULL CHECK(length(reason) <= 2000),
    status TEXT NOT NULL CHECK(status IN ('pending','active','denied','expired','consumed','revoked','canceled')),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    created_at TEXT NOT NULL,
    pending_expires_at TEXT NOT NULL,
    expires_at TEXT,
    duration_ns INTEGER NOT NULL CHECK(duration_ns >= 0),
    requested_duration_ns INTEGER NOT NULL CHECK(requested_duration_ns >= 0),
    pending_timeout_ns INTEGER NOT NULL CHECK(pending_timeout_ns > 0),
    decided_at TEXT,
    decided_by TEXT NOT NULL DEFAULT '' CHECK(length(decided_by) <= 256),
    decided_on_behalf_of TEXT NOT NULL DEFAULT '' CHECK(length(decided_on_behalf_of) <= 256),
    used_at TEXT,
    used_count INTEGER NOT NULL DEFAULT 0 CHECK(used_count >= 0),
    use_revision INTEGER NOT NULL DEFAULT 0 CHECK(use_revision >= 0),
    reserved_count INTEGER NOT NULL DEFAULT 0 CHECK(reserved_count >= 0),
    reserved_at TEXT,
    reservation_retained INTEGER NOT NULL DEFAULT 0 CHECK(reservation_retained IN (0,1)),
    reservation_revision INTEGER NOT NULL DEFAULT 0 CHECK(reservation_revision >= 0),
    max_uses INTEGER CHECK(max_uses BETWEEN 1 AND 25),
    requested_max_uses INTEGER CHECK(requested_max_uses BETWEEN 1 AND 25),
    requested_max_uses_defaulted INTEGER NOT NULL DEFAULT 0 CHECK(requested_max_uses_defaulted IN (0,1)),
    expired_from TEXT,
    notification_json TEXT CHECK(notification_json IS NULL OR (length(notification_json) BETWEEN 2 AND 16384 AND json_valid(notification_json))),
    notification_status TEXT NOT NULL DEFAULT '' CHECK(length(notification_status) <= 256),
    notification_claimed_at TEXT,
    notification_claim_until TEXT,
    notification_delivery_unresolved INTEGER NOT NULL DEFAULT 0 CHECK(notification_delivery_unresolved IN (0,1))
) STRICT;

CREATE INDEX grants_status_created_idx ON grants(status, created_at DESC, id DESC);
CREATE INDEX grants_operation_idx ON grants(operation, status);
CREATE UNIQUE INDEX grants_idempotency_idx ON grants(client, client_request_id)
WHERE client_request_id <> '' AND status <> 'canceled';

CREATE TABLE operations (
    id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128),
    api_version TEXT NOT NULL CHECK(length(api_version) BETWEEN 1 AND 64),
    broker TEXT NOT NULL CHECK(length(broker) BETWEEN 1 AND 64),
    client_id TEXT NOT NULL CHECK(length(client_id) BETWEEN 1 AND 128),
    idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
    operation TEXT NOT NULL CHECK(length(operation) BETWEEN 1 AND 128),
    target_json TEXT NOT NULL CHECK(length(target_json) BETWEEN 2 AND 4096 AND json_valid(target_json)),
    arguments_json TEXT NOT NULL CHECK(length(arguments_json) BETWEEN 2 AND 4096 AND json_valid(arguments_json)),
    reason TEXT NOT NULL CHECK(length(reason) <= 512),
    state TEXT NOT NULL CHECK(state IN ('pending','approved','executing','succeeded','failed','denied','expired','canceled')),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    terminal_at TEXT,
    approval_id TEXT NOT NULL DEFAULT '' CHECK(length(approval_id) <= 128),
    presentation_json TEXT NOT NULL CHECK(length(presentation_json) BETWEEN 2 AND 4096 AND json_valid(presentation_json)),
    result_json TEXT CHECK(result_json IS NULL OR (length(result_json) BETWEEN 2 AND 4096 AND json_valid(result_json))),
    error_json TEXT CHECK(error_json IS NULL OR (length(error_json) BETWEEN 2 AND 4096 AND json_valid(error_json))),
    plan_digest TEXT REFERENCES plans(digest),
    UNIQUE(client_id, idempotency_key)
) STRICT;

CREATE INDEX operations_unfinished_idx ON operations(state, updated_at, id);

CREATE TABLE lifecycle_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    cursor TEXT NOT NULL UNIQUE CHECK(length(cursor) BETWEEN 1 AND 1024),
    subject_kind TEXT NOT NULL CHECK(subject_kind IN ('grant','operation')),
    subject_id TEXT NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 128),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    occurred_at TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(length(payload_json) <= 16384 AND json_valid(payload_json))
) STRICT;

CREATE INDEX lifecycle_events_subject_idx ON lifecycle_events(subject_kind, subject_id, sequence);

CREATE TABLE decision_records (
    scope TEXT PRIMARY KEY CHECK(length(scope) BETWEEN 1 AND 1024),
    request_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 32),
    idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
    command_hash TEXT NOT NULL CHECK(length(command_hash) BETWEEN 43 AND 64),
    result_json TEXT NOT NULL CHECK(length(result_json) BETWEEN 2 AND 32768 AND json_valid(result_json)),
    previous_json TEXT NOT NULL CHECK(length(previous_json) BETWEEN 2 AND 32768 AND json_valid(previous_json)),
    event_cursor TEXT NOT NULL DEFAULT '' CHECK(length(event_cursor) <= 1024),
    committed_at TEXT NOT NULL,
    UNIQUE(request_id, action, idempotency_key)
) STRICT;

CREATE TABLE notification_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),
    payload_json TEXT NOT NULL CHECK(length(payload_json) BETWEEN 2 AND 16384 AND json_valid(payload_json)),
    idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    status TEXT NOT NULL CHECK(status IN ('pending','claimed','delivered','ambiguous','canceled')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    available_at TEXT NOT NULL,
    claimed_until TEXT,
    delivered_at TEXT,
    last_error_code TEXT NOT NULL DEFAULT '' CHECK(length(last_error_code) <= 128),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX notification_outbox_due_idx ON notification_outbox(status, available_at, id);

-- +goose Down
DROP TABLE notification_outbox;
DROP TABLE decision_records;
DROP TABLE lifecycle_events;
DROP TABLE operations;
DROP TABLE grants;
DROP TABLE plans;
