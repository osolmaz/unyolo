-- +goose Up
CREATE TABLE operations_expanded (
    id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128),
    api_version TEXT NOT NULL CHECK(length(api_version) BETWEEN 1 AND 64),
    broker TEXT NOT NULL CHECK(length(broker) BETWEEN 1 AND 64),
    client_id TEXT NOT NULL CHECK(length(client_id) BETWEEN 1 AND 128),
    idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
    operation TEXT NOT NULL CHECK(length(operation) BETWEEN 1 AND 128),
    target_json TEXT NOT NULL CHECK(length(target_json) BETWEEN 2 AND 16384 AND json_valid(target_json)),
    arguments_json TEXT NOT NULL CHECK(length(arguments_json) BETWEEN 2 AND 1048576 AND json_valid(arguments_json)),
    reason TEXT NOT NULL CHECK(length(reason) <= 2000),
    state TEXT NOT NULL CHECK(state IN ('pending','approved','executing','succeeded','failed','denied','expired','canceled')),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    terminal_at TEXT,
    approval_id TEXT NOT NULL DEFAULT '' CHECK(length(approval_id) <= 128),
    presentation_json TEXT NOT NULL CHECK(length(presentation_json) BETWEEN 2 AND 4096 AND json_valid(presentation_json)),
    result_json TEXT CHECK(result_json IS NULL OR (length(result_json) BETWEEN 2 AND 2097152 AND json_valid(result_json))),
    error_json TEXT CHECK(error_json IS NULL OR (length(error_json) BETWEEN 2 AND 4096 AND json_valid(error_json))),
    plan_digest TEXT REFERENCES plans(digest),
    UNIQUE(client_id, idempotency_key)
) STRICT;

INSERT INTO operations_expanded SELECT * FROM operations;
DROP TABLE operations;
ALTER TABLE operations_expanded RENAME TO operations;
CREATE INDEX operations_unfinished_idx ON operations(state, updated_at, id);

-- +goose Down
CREATE TABLE operations_original (
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
    result_json TEXT CHECK(result_json IS NULL OR (length(result_json) BETWEEN 2 AND 2097152 AND json_valid(result_json))),
    error_json TEXT CHECK(error_json IS NULL OR (length(error_json) BETWEEN 2 AND 4096 AND json_valid(error_json))),
    plan_digest TEXT REFERENCES plans(digest),
    UNIQUE(client_id, idempotency_key)
) STRICT;

INSERT INTO operations_original SELECT * FROM operations;
DROP TABLE operations;
ALTER TABLE operations_original RENAME TO operations;
CREATE INDEX operations_unfinished_idx ON operations(state, updated_at, id);
