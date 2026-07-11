export type Risk = "unknown" | "low" | "medium" | "high" | "critical";
export type Action = "approve" | "deny" | "cancel" | "revoke";
export type Status =
  | "pending"
  | "active"
  | "denied"
  | "canceled"
  | "expired"
  | "consumed"
  | "revoked";

export type BrokerRequest = {
  id: string;
  revision: number;
  requester: string;
  operation: string;
  status: Status;
  requested_at: string;
  pending_expires_at?: string;
  active_expires_at?: string;
  requested_duration_seconds: number;
  requested_max_uses: number;
  granted_max_uses: number | null;
  used_count: number;
  request_reason?: string;
  presentation: {
    risk: Risk;
    title: string;
    summary?: string;
    facts?: Array<{ label: string; value: string }>;
  };
  presentation_unavailable?: boolean;
  allowed_actions: Action[];
  approval_bounds?: { max_duration_seconds: number; max_uses: number };
};

export type RequestPage = {
  requests: BrokerRequest[];
  next_cursor?: string;
  event_cursor?: string;
};
export type BrokerEvent = {
  cursor: string;
  kind: string;
  request_id: string;
  revision: number;
  status: Status;
  occurred_at: string;
  used_count: number;
};
export type Decision = {
  expected_revision: number;
  idempotency_key: string;
  decision_reason?: string;
  on_behalf_of?: string;
  constraints?: { duration_seconds?: number; max_uses?: number };
};
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
