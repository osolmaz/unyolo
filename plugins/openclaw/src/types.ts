import type {
  BrokerEvent as GeneratedBrokerEvent,
  BrokerRequest as GeneratedBrokerRequest,
  Decision as GeneratedDecision,
  Presentation,
  RequestPage as GeneratedRequestPage,
  UISnapshot as GeneratedSnapshot,
  UISnapshotEvent as GeneratedSnapshotEvent,
} from "./generated/operator-v1.js";

export type Risk = Presentation["risk"];
export type Action = GeneratedBrokerRequest["allowed_actions"][number];
export type Status = GeneratedBrokerRequest["status"];
export type BrokerRequest = GeneratedBrokerRequest;
export type RequestPage = GeneratedRequestPage;
export type BrokerEvent = GeneratedBrokerEvent;
export type Decision = GeneratedDecision;

export type Snapshot = GeneratedSnapshot;
export type SnapshotEvent = GeneratedSnapshotEvent;
export type SourceHealth = Snapshot["sources"][number];
export type SafeRequest = Snapshot["requests"][number];
