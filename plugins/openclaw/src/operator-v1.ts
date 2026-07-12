import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import * as addFormatsModule from "ajv-formats";
import {
  BrokerEventSchema,
  BrokerRequestSchema,
  DescriptorSchema,
  ErrorEnvelopeSchema,
  HealthSchema,
  RequestPageSchema,
  UIRequestSchema,
  UISnapshotEventSchema,
  UISnapshotSchema,
  UISummarySchema,
} from "./generated/operator-schemas.js";
import type {
  BrokerEvent,
  BrokerRequest,
  RequestPage,
  SafeRequest,
  Snapshot,
  SnapshotEvent,
} from "./types.js";

const ajv = new Ajv2020({ strict: true, allErrors: false });
const addFormats = (addFormatsModule.default ??
  addFormatsModule) as unknown as (value: Ajv2020) => void;
addFormats(ajv);

const descriptor = compile(DescriptorSchema);
const health = compile(HealthSchema);
const brokerRequest = compile(BrokerRequestSchema);
const requestPage = compile(RequestPageSchema);
const brokerEvent = compile(BrokerEventSchema);
const errorEnvelope = compile(ErrorEnvelopeSchema);
const uiRequest = compile(UIRequestSchema);
const uiSnapshot = compile(UISnapshotSchema);
const uiSnapshotEvent = compile(UISnapshotEventSchema);
const uiSummary = compile(UISummarySchema);

export function parseDescriptor(value: unknown): { api_version: string } {
  return validated(descriptor, value) as { api_version: string };
}

export function parseHealth(value: unknown): { status: string } {
  return validated(health, value) as { status: string };
}

export function parseRequest(value: unknown): BrokerRequest {
  return validated(brokerRequest, value) as BrokerRequest;
}

export function parseRequestPage(value: unknown): RequestPage {
  return validated(requestPage, value) as RequestPage;
}

export function parseBrokerEvent(value: unknown): BrokerEvent {
  return validated(brokerEvent, value) as BrokerEvent;
}

export function parseUIRequest(value: unknown): SafeRequest {
  return validated(uiRequest, value) as SafeRequest;
}

export function parseUISnapshot(value: unknown): Snapshot {
  return validated(uiSnapshot, value) as Snapshot;
}

export function parseUISnapshotEvent(value: unknown): SnapshotEvent {
  return validated(uiSnapshotEvent, value) as SnapshotEvent;
}

export function parseUISummary(value: unknown): {
  api_version: "brokerkit.io/operator-ui/v1";
  cursor: string;
  pending: number;
  healthy: boolean;
} {
  return validated(uiSummary, value) as {
    api_version: "brokerkit.io/operator-ui/v1";
    cursor: string;
    pending: number;
    healthy: boolean;
  };
}

export function parseErrorEnvelope(
  value: unknown,
): { error: { code: string; message: string } } | undefined {
  return errorEnvelope(value)
    ? (value as { error: { code: string; message: string } })
    : undefined;
}

function compile(schema: object): ValidateFunction {
  return ajv.compile(schema);
}

function validated(validate: ValidateFunction, value: unknown): unknown {
  if (!validate(value)) throw new Error("Operator V1 response is invalid");
  return value;
}
