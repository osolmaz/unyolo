import { z } from "zod";
import { operatorV1 } from "./generated/operator-v1.js";
import type { BrokerEvent, BrokerRequest, RequestPage } from "./types.js";

const timestamp = z.iso.datetime({ offset: true });
const nonNegativeInteger = z.number().int().nonnegative().safe();
const positiveInteger = z.number().int().positive().safe();

const status = z.enum(operatorV1.statuses);
const action = z.enum(operatorV1.actions);
const fact = z.object({
  label: z.string().min(1).max(operatorV1.limits.factLabel),
  value: z.string().min(1).max(operatorV1.limits.factValue),
});
const presentation = z.object({
  risk: z.enum(operatorV1.risks),
  title: z.string().min(1).max(operatorV1.limits.title),
  summary: z.string().max(operatorV1.limits.summary).optional(),
  facts: z.array(fact).max(operatorV1.limits.facts).optional(),
});

export const brokerRequestSchema = z.object({
  id: z.string().min(1).max(operatorV1.limits.id),
  revision: positiveInteger,
  requester: z.string().min(1).max(operatorV1.limits.requester),
  operation: z.string().min(1).max(operatorV1.limits.operation),
  status,
  requested_at: timestamp,
  pending_expires_at: timestamp.optional(),
  active_expires_at: timestamp.optional(),
  requested_duration_seconds: positiveInteger,
  requested_max_uses: positiveInteger,
  granted_max_uses: positiveInteger.nullable(),
  used_count: nonNegativeInteger,
  request_reason: z.string().max(operatorV1.limits.reason).optional(),
  decided_at: timestamp.optional(),
  decided_by: z.string().max(operatorV1.limits.actor).optional(),
  decided_on_behalf_of: z.string().max(operatorV1.limits.actor).optional(),
  decision_reason: z.string().max(operatorV1.limits.reason).optional(),
  presentation,
  presentation_unavailable: z.boolean().optional(),
  allowed_actions: z
    .array(action)
    .max(operatorV1.actions.length)
    .refine((value) => new Set(value).size === value.length),
  approval_bounds: z
    .object({
      max_duration_seconds: nonNegativeInteger,
      max_uses: positiveInteger,
    })
    .optional(),
});

const requestPageSchema = z.object({
  requests: z.array(brokerRequestSchema).max(operatorV1.limits.page),
  next_cursor: z.string().min(1).max(operatorV1.limits.cursor).optional(),
  event_cursor: z.string().min(1).max(operatorV1.limits.cursor).optional(),
});

const brokerEventSchema = z.object({
  cursor: z.string().min(1).max(operatorV1.limits.cursor),
  kind: z.enum(operatorV1.eventKinds),
  request_id: z.string().min(1).max(operatorV1.limits.id),
  revision: positiveInteger,
  status,
  occurred_at: timestamp,
  used_count: nonNegativeInteger,
});

const descriptorSchema = z.object({
  api_version: z.literal(operatorV1.apiVersion),
});

const healthSchema = z.object({ status: z.string().min(1).max(128) });

const errorEnvelopeSchema = z.object({
  error: z.object({
    code: z.enum(operatorV1.errorCodes),
    message: z.string().min(1).max(operatorV1.limits.errorMessage),
    correlation_id: z.string().min(1).max(operatorV1.limits.correlationId),
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
