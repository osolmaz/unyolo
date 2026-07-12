// Generated from protocol/openapi/operator-v1.yaml. Do not edit.
import type { components } from "./openapi-operator-v1.js";

export const OPERATOR_V1_SCHEMA_SHA256 =
  "86271ccfac4700918d1a566db16a52dd6cace6e33a3bb036b7d5525d06e68ef4";
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
  actions: ["approve", "deny", "cancel", "revoke"],
  risks: ["unknown", "low", "medium", "high", "critical"],
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
