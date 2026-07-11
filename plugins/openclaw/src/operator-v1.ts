import { z } from "zod";
import type { BrokerEvent, BrokerRequest, RequestPage } from "./types.js";

const boundedText = z.string().min(1).max(4096);
const timestamp = z.iso.datetime({ offset: true });
const nonNegativeInteger = z.number().int().nonnegative().safe();
const positiveInteger = z.number().int().positive().safe();

const status = z.enum([
  "pending",
  "active",
  "denied",
  "canceled",
  "expired",
  "consumed",
  "revoked",
]);
const action = z.enum(["approve", "deny", "cancel", "revoke"]);
const fact = z.object({
  label: boundedText,
  value: z.string().max(16_384),
});
const presentation = z.object({
  risk: z.enum(["unknown", "low", "medium", "high", "critical"]),
  title: boundedText,
  summary: z.string().max(32_768).optional(),
  facts: z.array(fact).max(64).optional(),
});

export const brokerRequestSchema = z.object({
  id: boundedText,
  revision: positiveInteger,
  requester: boundedText,
  operation: boundedText,
  status,
  requested_at: timestamp,
  pending_expires_at: timestamp.optional(),
  active_expires_at: timestamp.optional(),
  requested_duration_seconds: nonNegativeInteger,
  requested_max_uses: positiveInteger,
  granted_max_uses: positiveInteger.nullable(),
  used_count: nonNegativeInteger,
  request_reason: z.string().max(32_768).optional(),
  decided_at: timestamp.optional(),
  decided_by: z.string().max(4096).optional(),
  decided_on_behalf_of: z.string().max(4096).optional(),
  decision_reason: z.string().max(32_768).optional(),
  presentation,
  presentation_unavailable: z.boolean().optional(),
  allowed_actions: z.array(action).max(4),
  approval_bounds: z
    .object({
      max_duration_seconds: nonNegativeInteger,
      max_uses: positiveInteger,
    })
    .optional(),
});

const requestPageSchema = z.object({
  requests: z.array(brokerRequestSchema).max(100),
  next_cursor: z.string().min(1).max(4096).optional(),
  event_cursor: z.string().min(1).max(4096).optional(),
});

const brokerEventSchema = z.object({
  cursor: boundedText,
  kind: boundedText,
  request_id: boundedText,
  revision: positiveInteger,
  status,
  occurred_at: timestamp,
  used_count: nonNegativeInteger,
});

const descriptorSchema = z.object({
  api_version: z.string().min(1).max(128),
});

const healthSchema = z.object({ status: z.string().min(1).max(128) });

const errorEnvelopeSchema = z.object({
  error: z.object({
    code: z.string().min(1).max(128),
    message: z.string().min(1).max(4096),
  }),
});

export function parseDescriptor(value: unknown): { api_version: string } {
  return descriptorSchema.parse(value);
}

export function parseHealth(value: unknown): { status: string } {
  return healthSchema.parse(value);
}

export function parseRequest(value: unknown): BrokerRequest {
  return brokerRequestSchema.parse(value) as BrokerRequest;
}

export function parseRequestPage(value: unknown): RequestPage {
  return requestPageSchema.parse(value) as RequestPage;
}

export function parseBrokerEvent(value: unknown): BrokerEvent {
  return brokerEventSchema.parse(value) as BrokerEvent;
}

export function parseErrorEnvelope(
  value: unknown,
): { error: { code: string; message: string } } | undefined {
  const result = errorEnvelopeSchema.safeParse(value);
  return result.success ? result.data : undefined;
}
