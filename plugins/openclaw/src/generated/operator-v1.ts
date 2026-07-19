// Generated from protocol/openapi/operator-v1.yaml. Do not edit.
import type { components } from "./openapi-operator-v1.js";

export const OPERATOR_V1_SCHEMA_SHA256 =
  "fb446551ce8f2e00cfb6555daf93ed5b8e2ce8c45d8029b4a49e6a5fb8fef98d";
export const operatorV1 = {
  apiVersion: "brokerkit.io/operator/v1",
  statuses: [
    "pending",
    "active",
    "denied",
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
    "invalid_decision_token",
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
