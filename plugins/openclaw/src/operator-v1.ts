import {
  validateBrokerEvent,
  validateBrokerRequest,
  validateDescriptor,
  validateErrorEnvelope,
  validateHealth,
  validateRequestPage,
  validateUIRequest,
  validateUISnapshot,
  validateUISnapshotEvent,
  validateUISummary,
} from "./generated/operator-validators.js";
import type {
  BrokerEvent,
  BrokerRequest,
  RequestPage,
  SafeRequest,
  Snapshot,
  SnapshotEvent,
} from "./types.js";

type Validate = (value: unknown) => boolean;

export function parseDescriptor(value: unknown): { api_version: string } {
  return validated(validateDescriptor, value) as { api_version: string };
}

export function parseHealth(value: unknown): { status: string } {
  return validated(validateHealth, value) as { status: string };
}

export function parseRequest(value: unknown): BrokerRequest {
  return validated(validateBrokerRequest, value) as BrokerRequest;
}

export function parseRequestPage(value: unknown): RequestPage {
  return validated(validateRequestPage, value) as RequestPage;
}

export function parseBrokerEvent(value: unknown): BrokerEvent {
  return validated(validateBrokerEvent, value) as BrokerEvent;
}

export function parseUIRequest(value: unknown): SafeRequest {
  return validated(validateUIRequest, value) as SafeRequest;
}

export function parseUISnapshot(value: unknown): Snapshot {
  return validated(validateUISnapshot, value) as Snapshot;
}

export function parseUISnapshotEvent(value: unknown): SnapshotEvent {
  return validated(validateUISnapshotEvent, value) as SnapshotEvent;
}

export function parseUISummary(value: unknown): {
  api_version: "brokerkit.io/operator-ui/v1";
  cursor: string;
  pending: number;
  healthy: boolean;
} {
  return validated(validateUISummary, value) as {
    api_version: "brokerkit.io/operator-ui/v1";
    cursor: string;
    pending: number;
    healthy: boolean;
  };
}

export function parseErrorEnvelope(
  value: unknown,
): { error: { code: string; message: string } } | undefined {
  return validateErrorEnvelope(value)
    ? (value as { error: { code: string; message: string } })
    : undefined;
}

function validated(validate: Validate, value: unknown): unknown {
  if (!validate(value)) throw new Error("Operator V1 response is invalid");
  return value;
}
