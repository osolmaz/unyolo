import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import * as Dialog from "@radix-ui/react-dialog";
import {
  AlertTriangle,
  Check,
  CircleX,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";
import type { Action, SafeRequest, Snapshot } from "../../src/types.js";
import {
  BrokerKitUiApi,
  parseUiBootstrap,
  type UiDecisionOptions,
} from "./api.js";
import "./styles.css";

const api = new BrokerKitUiApi(parseUiBootstrap(location.hash.slice(1)));
history.replaceState(null, "", location.pathname);

export function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [decision, setDecision] = useState<{
    request: SafeRequest;
    action: Action;
  }>();
  const load = useCallback(async () => {
    try {
      setError("");
      setSnapshot(await api.snapshot());
    } catch (value) {
      setError(
        value instanceof Error ? value.message : "Approvals are unavailable",
      );
    }
  }, []);
  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 15_000);
    return () => clearInterval(timer);
  }, [load]);
  const decide = async (
    request: SafeRequest,
    action: Action,
    options: UiDecisionOptions,
  ) => {
    setBusy(request.handle);
    try {
      await api.decide(request, action, options);
      setDecision(undefined);
      await load();
    } catch (value) {
      setError(value instanceof Error ? value.message : "Decision failed");
    } finally {
      setBusy("");
    }
  };
  const actionable = useMemo(
    () =>
      snapshot?.requests.filter(
        (request) => request.allowed_actions.length > 0,
      ) ?? [],
    [snapshot],
  );
  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">
            <ShieldCheck size={15} /> BrokerKit
          </p>
          <h1>Approvals</h1>
          <p className="subtle">
            {
              actionable.filter((request) => request.status === "pending")
                .length
            }{" "}
            pending across {snapshot?.sources.length ?? 0} sources
          </p>
        </div>
        <button className="icon" title="Refresh" onClick={() => void load()}>
          <RefreshCw size={18} />
        </button>
      </header>
      {error && (
        <div className="error">
          <AlertTriangle size={17} />
          <span>{error}</span>
          <button title="Dismiss" onClick={() => setError("")}>
            <X size={16} />
          </button>
        </div>
      )}
      {(snapshot?.deliveryFailures ?? 0) > 0 && (
        <div className="warning" role="status">
          <AlertTriangle size={17} />
          <span>
            {snapshot?.deliveryFailures} notification
            {snapshot?.deliveryFailures === 1 ? "" : "s"} need attention
          </span>
        </div>
      )}
      <section className="sources" aria-label="Source health">
        {snapshot?.sources.map((source) => (
          <div className="source" key={source.id}>
            <span className={source.healthy ? "dot healthy" : "dot"} />
            <span>{source.label}</span>
            <small>{source.healthy ? "Connected" : "Unavailable"}</small>
          </div>
        ))}
      </section>
      <section className="requests">
        {actionable.map((request) => (
          <article key={request.handle}>
            <div className="request-head">
              <div>
                <span className={`risk ${request.presentation.risk}`}>
                  {request.presentation.risk}
                </span>
                <span className="source-label">{request.sourceLabel}</span>
                <h2>{request.presentation.title}</h2>
              </div>
              <code>{request.handle.slice(0, 8)}</code>
            </div>
            {request.presentation.summary && (
              <p>{request.presentation.summary}</p>
            )}
            <dl>
              {request.presentation.facts?.map((fact) => (
                <React.Fragment key={`${fact.label}-${fact.value}`}>
                  <dt>{fact.label}</dt>
                  <dd>{fact.value}</dd>
                </React.Fragment>
              ))}
            </dl>
            <div className="meta">
              <span>{request.requester}</span>
              <span>
                {request.requested_max_uses} use
                {request.requested_max_uses === 1 ? "" : "s"}
              </span>
              <span>
                {Math.round(request.requested_duration_seconds / 60)} min
              </span>
            </div>
            <div className="actions">
              {request.allowed_actions.includes("cancel") && (
                <button
                  className="secondary"
                  disabled={busy === request.handle}
                  onClick={() => setDecision({ request, action: "cancel" })}
                >
                  <CircleX size={16} />
                  Cancel
                </button>
              )}
              {request.allowed_actions.includes("revoke") && (
                <button
                  className="secondary"
                  disabled={busy === request.handle}
                  onClick={() => setDecision({ request, action: "revoke" })}
                >
                  <CircleX size={16} />
                  Revoke
                </button>
              )}
              {request.allowed_actions.includes("deny") && (
                <button
                  className="secondary"
                  disabled={busy === request.handle}
                  onClick={() => setDecision({ request, action: "deny" })}
                >
                  <CircleX size={16} />
                  Deny
                </button>
              )}
              {request.allowed_actions.includes("approve") && (
                <button
                  className="primary"
                  disabled={busy === request.handle}
                  onClick={() => setDecision({ request, action: "approve" })}
                >
                  <Check size={16} />
                  Approve
                </button>
              )}
            </div>
          </article>
        ))}
        {snapshot && actionable.length === 0 && (
          <div className="empty">
            <ShieldCheck size={30} />
            <h2>No actionable requests</h2>
            <p>
              Approved, denied, expired, and canceled requests clear
              automatically.
            </p>
          </div>
        )}
      </section>
      <DecisionDialog
        decision={decision}
        busy={Boolean(decision && busy === decision.request.handle)}
        onClose={() => setDecision(undefined)}
        onConfirm={decide}
      />
    </main>
  );
}

function DecisionDialog({
  decision,
  busy,
  onClose,
  onConfirm,
}: {
  decision: { request: SafeRequest; action: Action } | undefined;
  busy: boolean;
  onClose(): void;
  onConfirm(
    request: SafeRequest,
    action: Action,
    options: UiDecisionOptions,
  ): Promise<void>;
}) {
  const request = decision?.request;
  const bounds = request?.approval_bounds;
  const [reason, setReason] = useState("");
  const [durationSeconds, setDurationSeconds] = useState(1);
  const [maxUses, setMaxUses] = useState(1);
  useEffect(() => {
    setReason("");
    if (!request) return;
    setDurationSeconds(
      Math.max(
        1,
        Math.min(
          request.requested_duration_seconds,
          bounds?.max_duration_seconds ?? request.requested_duration_seconds,
        ),
      ),
    );
    setMaxUses(
      Math.min(
        request.requested_max_uses,
        bounds?.max_uses ?? request.requested_max_uses,
      ),
    );
  }, [request, bounds]);
  if (!decision || !request) return null;
  const approve = decision.action === "approve";
  const title = `${capitalize(decision.action)} request`;
  return (
    <Dialog.Root open onOpenChange={(open) => !open && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content className="dialog-content">
          <Dialog.Title>{title}</Dialog.Title>
          <Dialog.Description>
            {request.presentation.title} at revision {request.revision}
          </Dialog.Description>
          {approve && bounds && (
            <div className="decision-bounds">
              <label>
                Duration (seconds)
                <input
                  type="number"
                  min={1}
                  max={bounds.max_duration_seconds}
                  value={durationSeconds}
                  onChange={(event) =>
                    setDurationSeconds(event.currentTarget.valueAsNumber)
                  }
                />
              </label>
              <label>
                Maximum uses
                <input
                  type="number"
                  min={1}
                  max={bounds.max_uses}
                  value={maxUses}
                  onChange={(event) =>
                    setMaxUses(event.currentTarget.valueAsNumber)
                  }
                />
              </label>
            </div>
          )}
          <label className="reason">
            Reason (optional)
            <textarea
              maxLength={2000}
              rows={3}
              value={reason}
              onChange={(event) => setReason(event.currentTarget.value)}
            />
          </label>
          <div className="dialog-actions">
            <Dialog.Close asChild>
              <button className="secondary" disabled={busy}>
                Cancel
              </button>
            </Dialog.Close>
            <button
              className={approve ? "primary" : "danger"}
              disabled={
                busy || !validBounds(approve, durationSeconds, maxUses, bounds)
              }
              onClick={() =>
                void onConfirm(request, decision.action, {
                  ...(reason.trim() ? { reason: reason.trim() } : {}),
                  ...(approve && bounds
                    ? {
                        constraints: {
                          durationSeconds,
                          maxUses,
                        },
                      }
                    : {}),
                })
              }
            >
              {capitalize(decision.action)}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function validBounds(
  approve: boolean,
  durationSeconds: number,
  maxUses: number,
  bounds: SafeRequest["approval_bounds"],
): boolean {
  if (!approve || !bounds) return true;
  return (
    Number.isSafeInteger(durationSeconds) &&
    durationSeconds > 0 &&
    durationSeconds <= bounds.max_duration_seconds &&
    Number.isSafeInteger(maxUses) &&
    maxUses > 0 &&
    maxUses <= bounds.max_uses
  );
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
