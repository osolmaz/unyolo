// Generated from protocol/openapi/operator-v1.yaml. Do not edit.
import type { components } from "./openapi-operator-v1.js";

export const OPERATOR_V1_SCHEMA_SHA256 =
  "sha256:db0e8be0f9d7218e44e81367df7584522c508602fc9aaf0a351405f8fb7c6f2b";
export const operatorV1 = {
  apiVersion: "unyolo.io/operator/v1",
  statuses: [
    "pending",
    "active",
    "denied",
    "failed",
    "canceled",
    "expired",
    "consumed",
    "revoked",
  ],
  actions: ["approve", "deny", "revoke"],
  eventKinds: [
    "request.created",
    "request.approved",
    "request.denied",
    "request.failed",
    "request.canceled",
    "request.expired",
    "grant.revoked",
    "grant.reserved",
    "grant.consumed",
    "grant.released",
    "execution.succeeded",
    "execution.failed",
    "execution.ambiguous",
  ],
  errorCodes: [
    "invalid_request",
    "unauthorized",
    "forbidden",
    "not_found",
    "method_not_allowed",
    "revision_conflict",
    "idempotency_conflict",
    "constraint_exceeded",
    "invalid_transition",
    "plan_unavailable",
    "plan_mismatch",
    "credential_changed",
    "credential_insufficient",
    "storage_unavailable",
    "cursor_expired",
    "temporarily_unavailable",
    "internal_error",
  ],
  limits: {
    id: 128,
    requester: 80,
    operation: 500,
    reason: 2000,
    actor: 200,
    title: 200,
    summary: 2000,
    facts: 20,
    factLabel: 80,
    factValue: 500,
    cursor: 1024,
    page: 100,
    idempotencyKey: 200,
    errorMessage: 500,
    correlationId: 128,
  },
} as const;

export type Decision = components["schemas"]["Decision"];
export type Discovery = components["schemas"]["Descriptor"];
export type ErrorEnvelope = components["schemas"]["ErrorEnvelope"];
export type BrokerEvent = components["schemas"]["BrokerEvent"];
export type RequestPage = components["schemas"]["RequestPage"];
export type Presentation = components["schemas"]["Presentation"];
export type BrokerRequest = components["schemas"]["BrokerRequest"];
export type UISnapshot = components["schemas"]["UISnapshot"];
export type UISnapshotEvent = components["schemas"]["UISnapshotEvent"];
export type UISummary = components["schemas"]["UISummary"];
