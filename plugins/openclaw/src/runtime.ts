import { createHash } from "node:crypto";
import type { BrokerConfig, DirectPluginConfig } from "./config.js";
import { BrokerClient, BrokerError } from "./client.js";
import { StateStore, type Subscription } from "./store.js";
import type {
  Action,
  BrokerRequest,
  Decision,
  SafeRequest,
  Snapshot,
  SourceHealth,
  SnapshotEvent,
} from "./types.js";
import { RevisionPublisher } from "./revisions.js";

type Source = {
  config: BrokerConfig;
  client: BrokerClient;
  abort?: AbortController;
  discovered: boolean;
};
export type RuntimeHooks = {
  resolveCredential(source: BrokerConfig): Promise<string>;
  deliver(subscription: Subscription, text: string): Promise<void>;
  log(level: "info" | "warn", message: string): void;
};
export type DecisionOptions = {
  constraints?: NonNullable<Decision["constraints"]>;
};

export class BrokerRuntime {
  private readonly sources = new Map<string, Source>();
  private readonly requests = new Map<string, SafeRequest>();
  private readonly health = new Map<string, SourceHealth>();
  private store: StateStore | undefined;
  private timer?: NodeJS.Timeout;
  private delivering = false;
  private ready = false;
  private readonly revisions = new RevisionPublisher();
  constructor(
    private readonly config: DirectPluginConfig,
    private readonly hooks: RuntimeHooks,
  ) {
    for (const source of config.brokers)
      this.sources.set(source.id, {
        config: source,
        client: new BrokerClient(
          source.endpoint,
          () => hooks.resolveCredential(source),
          source.requestTimeoutMs,
        ),
        discovered: false,
      });
  }
  async start(stateDir: string): Promise<void> {
    this.store = new StateStore(stateDir);
    this.store.retainSources([...this.sources.keys()]);
    this.store.pruneExpired();
    await Promise.all(
      [...this.sources.values()].map((source) => this.startSource(source)),
    );
    this.ready = true;
    this.publishSnapshot();
    this.timer = setInterval(() => {
      void this.reconcileAll();
      void this.deliverPending();
    }, this.config.pollIntervalMs);
    this.timer.unref();
  }
  async stop(): Promise<void> {
    this.ready = false;
    if (this.timer) clearInterval(this.timer);
    for (const source of this.sources.values()) source.abort?.abort();
    this.revisions.close();
    this.store?.close();
    this.store = undefined;
  }
  snapshot(): Snapshot {
    return this.revisions.snapshot();
  }
  waitForSnapshot(
    cursor: string,
    waitSeconds: number,
    signal?: AbortSignal,
  ): Promise<SnapshotEvent> {
    return this.revisions.wait(cursor, waitSeconds, signal);
  }
  private snapshotMaterial(): Omit<
    Snapshot,
    "api_version" | "cursor" | "synchronized_at"
  > {
    return {
      sources: [...this.health.values()].sort((a, b) =>
        a.id.localeCompare(b.id),
      ),
      requests: [...this.requests.values()].sort((a, b) =>
        b.request.requested_at.localeCompare(a.request.requested_at),
      ),
      delivery_failures: this.store?.failedDeliveryCount() ?? 0,
    };
  }
  private publishSnapshot(): void {
    if (this.ready) this.revisions.publish(this.snapshotMaterial());
  }
  async decide(
    handle: string,
    action: Action,
    expectedRevision: number,
    actor: string,
    options: DecisionOptions = {},
  ): Promise<SafeRequest> {
    const resolved = this.requireStore().resolve(handle);
    if (!resolved) throw new Error("request_not_found");
    const source = this.sources.get(resolved.sourceId);
    if (!source) throw new Error("source_unavailable");
    const current = await source.client.get(resolved.requestId);
    if (
      current.revision !== resolved.revision ||
      current.revision !== expectedRevision
    )
      throw new Error("revision_stale");
    if (!current.allowed_actions.includes(action))
      throw new Error("action_not_allowed");
    if (options.constraints) {
      const bounds = current.approval_bounds;
      if (
        action !== "approve" ||
        !bounds ||
        (options.constraints.duration_seconds !== undefined &&
          options.constraints.duration_seconds > bounds.max_duration_seconds) ||
        (options.constraints.max_uses !== undefined &&
          !validUseConstraint(options.constraints.max_uses, bounds.max_uses))
      )
        throw new Error("action_not_allowed");
    }
    const decision: Decision = {
      expected_revision: expectedRevision,
      idempotency_key: deterministicDecisionKey(
        resolved.sourceId,
        resolved.requestId,
        expectedRevision,
        action,
        actor,
      ),
      on_behalf_of: actor,
      ...(options.constraints ? { constraints: options.constraints } : {}),
    };
    const updated = await this.decideWithRecovery(
      source,
      resolved.requestId,
      action,
      decision,
    );
    this.accept(source, updated);
    return this.requests.get(handle) ?? this.project(source, updated, handle);
  }
  subscribe(value: Omit<Subscription, "id">): Subscription {
    const subscription = this.requireStore().subscribe(value);
    for (const handle of this.requests.keys())
      this.requireStore().enqueue(handle);
    void this.deliverPending();
    return subscription;
  }
  unsubscribe(value: Omit<Subscription, "id">): boolean {
    return this.requireStore().unsubscribe(value);
  }
  subscriptions(): Subscription[] {
    return this.requireStore().subscriptions();
  }
  private async startSource(source: Source): Promise<void> {
    try {
      await this.ensureDiscovered(source);
      await this.reconcile(source);
    } catch (error) {
      this.markUnhealthy(source, error);
    }
    this.watch(source);
  }
  private async decideWithRecovery(
    source: Source,
    requestId: string,
    action: Action,
    decision: Decision,
  ): Promise<BrokerRequest> {
    try {
      return await source.client.decide(requestId, action, decision);
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      try {
        const observed = await source.client.get(requestId);
        this.accept(source, observed);
      } catch {
        throw new Error("source_unavailable");
      }
      try {
        return await source.client.decide(requestId, action, decision);
      } catch (retryError) {
        if (retryError instanceof BrokerError) throw retryError;
        throw new Error("source_unavailable");
      }
    }
  }
  private async reconcileAll(): Promise<void> {
    await Promise.all(
      [...this.sources.values()].map((source) =>
        this.ensureDiscovered(source)
          .then(() => this.reconcile(source))
          .catch((error) => this.markUnhealthy(source, error)),
      ),
    );
  }
  private async reconcile(source: Source): Promise<void> {
    const seen = new Set<string>();
    let eventCursor: string | undefined;
    for (const status of ["pending", "active"] as const) {
      let cursor: string | undefined;
      do {
        const page = await source.client.list(status, cursor);
        eventCursor ??= page.event_cursor;
        for (const request of page.requests) {
          seen.add(request.id);
          this.accept(source, request);
        }
        cursor = page.next_cursor;
      } while (cursor);
    }
    for (const request of [...this.requests.values()])
      if (
        request.source_id === source.config.id &&
        !seen.has(request.request.id)
      ) {
        this.requests.delete(request.handle);
        this.requireStore().remove(source.config.id, request.request.id);
      }
    this.requireStore().retainRequests(source.config.id, seen);
    this.requireStore().pruneExpired();
    if (eventCursor)
      this.requireStore().setCursor(source.config.id, eventCursor);
    this.markHealthy(source);
    this.publishSnapshot();
  }
  private watch(source: Source): void {
    source.abort?.abort();
    const abort = new AbortController();
    source.abort = abort;
    void (async () => {
      let delay = 250;
      while (!abort.signal.aborted) {
        try {
          await this.ensureDiscovered(source);
          for await (const event of source.client.events(
            this.requireStore().cursor(source.config.id),
            abort.signal,
          )) {
            const current = await source.client.get(event.request_id);
            this.accept(source, current);
            this.requireStore().setCursor(source.config.id, event.cursor);
            this.markHealthy(source);
            delay = 250;
          }
        } catch (error) {
          if (abort.signal.aborted) return;
          let recovered = false;
          if (
            error instanceof Error &&
            "code" in error &&
            error.code === "cursor_expired"
          ) {
            try {
              await this.reconcile(source);
              recovered = true;
            } catch (reconcileError) {
              this.markUnhealthy(source, reconcileError);
            }
          }
          if (!recovered) this.markUnhealthy(source, error);
          await sleep(delay);
          delay = Math.min(delay * 2, 30_000);
        }
      }
    })();
  }
  private async ensureDiscovered(source: Source): Promise<void> {
    if (source.discovered) return;
    await source.client.discover();
    source.discovered = true;
  }
  private markHealthy(source: Source): void {
    const current = this.health.get(source.config.id);
    if (current?.healthy) return;
    this.health.set(source.config.id, {
      id: source.config.id,
      label: source.config.label,
      healthy: true,
      last_sync_at: new Date().toISOString(),
    });
    this.publishSnapshot();
  }
  private accept(source: Source, request: BrokerRequest): void {
    if (request.status !== "pending" && request.status !== "active") {
      this.requireStore().remove(source.config.id, request.id);
      for (const [handle, current] of this.requests)
        if (
          current.source_id === source.config.id &&
          current.request.id === request.id
        )
          this.requests.delete(handle);
      this.publishSnapshot();
      return;
    }
    const expires = Date.parse(
      request.pending_expires_at ??
        request.active_expires_at ??
        new Date(Date.now() + 86_400_000).toISOString(),
    );
    const handle = this.requireStore().handle(
      source.config.id,
      request.id,
      request.revision,
      expires,
    );
    for (const [old, current] of this.requests)
      if (
        current.source_id === source.config.id &&
        current.request.id === request.id &&
        old !== handle
      )
        this.requests.delete(old);
    this.requests.set(handle, this.project(source, request, handle));
    this.requireStore().enqueue(handle);
    this.publishSnapshot();
    void this.deliverPending();
  }
  private project(
    source: Source,
    request: BrokerRequest,
    handle: string,
  ): SafeRequest {
    return {
      source_id: source.config.id,
      source_label: source.config.label,
      handle,
      request,
    };
  }
  private markUnhealthy(source: Source, error: unknown): void {
    const message =
      error instanceof Error ? error.message : "source unavailable";
    this.health.set(source.config.id, {
      id: source.config.id,
      label: source.config.label,
      healthy: false,
      error: safeError(message),
    });
    this.publishSnapshot();
    this.hooks.log(
      "warn",
      `BrokerKit source ${source.config.id} unavailable: ${safeError(message)}`,
    );
  }
  private requireStore(): StateStore {
    if (!this.store) throw new Error("BrokerKit runtime is not started");
    return this.store;
  }
  private async deliverPending(): Promise<void> {
    if (this.delivering || !this.store) return;
    this.delivering = true;
    try {
      await Promise.all(
        this.store
          .due(this.config.notificationConcurrency)
          .map(async (delivery) => {
            const request = this.requests.get(delivery.handle);
            if (!request) return;
            try {
              await this.hooks.deliver(delivery, notificationText(request));
              this.store?.markDelivered(delivery.id, delivery.handle);
              this.publishSnapshot();
            } catch {
              this.store?.markDeliveryError(
                delivery.id,
                delivery.handle,
                delivery.attempts,
              );
              this.publishSnapshot();
            }
          }),
      );
    } finally {
      this.delivering = false;
    }
  }
}

function validUseConstraint(
  value: number | null,
  maximum: number | null,
): boolean {
  if (value === null) return maximum === null;
  return (
    Number.isSafeInteger(value) &&
    value > 0 &&
    (maximum === null || value <= maximum)
  );
}

function deterministicDecisionKey(
  source: string,
  request: string,
  revision: number,
  action: Action,
  actor: string,
): string {
  return createHash("sha256")
    .update(
      [
        "brokerkit-decision-v1",
        source,
        request,
        String(revision),
        action,
        actor,
      ].join("\0"),
    )
    .digest("base64url");
}
function safeError(value: string): string {
  return value.replace(/[\r\n]/g, " ").slice(0, 200);
}
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function notificationText(request: SafeRequest): string {
  const value = request.request;
  return [
    `${request.source_label}: ${value.presentation.title}`,
    value.presentation.summary ?? "",
    `Handle: ${request.handle}`,
    ...value.allowed_actions.map(
      (action) => `/brokerkit ${action} ${request.handle}`,
    ),
  ]
    .filter(Boolean)
    .join("\n");
}
