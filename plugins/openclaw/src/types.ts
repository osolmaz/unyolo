import type {
  BrokerEvent as GeneratedBrokerEvent,
  BrokerRequest as GeneratedBrokerRequest,
  Decision as GeneratedDecision,
  Presentation,
  RequestPage as GeneratedRequestPage,
} from "./generated/operator-v1.js";

export type Risk = Presentation["risk"];
export type Action = GeneratedBrokerRequest["allowed_actions"][number];
export type Status = GeneratedBrokerRequest["status"];
export type BrokerRequest = GeneratedBrokerRequest;
export type RequestPage = GeneratedRequestPage;
export type BrokerEvent = GeneratedBrokerEvent;
export type Decision = GeneratedDecision;

export type SourceHealth = {
  id: string;
  label: string;
  healthy: boolean;
  lastSyncAt?: string;
  error?: string;
};
export type SafeRequest = BrokerRequest & {
  sourceId: string;
  sourceLabel: string;
  handle: string;
};
export type Snapshot = {
  sources: SourceHealth[];
  requests: SafeRequest[];
  synchronizedAt: string;
};
