import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import * as Dialog from "@radix-ui/react-dialog";
import {
  AlertTriangle,
  Check,
  CircleX,
  MapPin,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";
import type { Action, SafeRequest } from "../../src/types.js";
import {
  BrokerKitUiApi,
  parseUiBootstrap,
  type UiDecisionOptions,
} from "./api.js";
import "./styles.css";
import { useBrokerSnapshot } from "./use-broker-snapshot.js";

const bootstrap = parseUiBootstrap(location.hash.slice(1));
const api = new BrokerKitUiApi(bootstrap);
history.replaceState(null, "", location.pathname);

export function App() {
  const { snapshot, canDecide, error, setError, reconcile } =
    useBrokerSnapshot(api);
  const [busy, setBusy] = useState("");
  const [decision, setDecision] = useState<{
    request: SafeRequest;
    action: Action;
  }>();
  const decide = async (
    request: SafeRequest,
    action: Action,
    options: UiDecisionOptions,
  ) => {
    setBusy(request.handle);
    try {
      await api.decide(request, action, options);
      setDecision(undefined);
      await reconcile();
    } catch (value) {
      setError(value instanceof Error ? value.message : "Decision failed");
    } finally {
      setBusy("");
    }
  };
  const actionable = useMemo(
    () =>
      snapshot?.requests.filter(
        (request) => request.request.allowed_actions.length > 0,
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
              actionable.filter(
                (request) => request.request.status === "pending",
              ).length
            }{" "}
            pending across {snapshot?.sources.length ?? 0} sources
          </p>
        </div>
        <button
          className="icon"
          title="Refresh"
          onClick={() => void reconcile().catch(() => undefined)}
        >
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
      {(snapshot?.delivery_failures ?? 0) > 0 && (
        <div className="warning" role="status">
          <AlertTriangle size={17} />
          <span>
            {snapshot?.delivery_failures} notification
            {snapshot?.delivery_failures === 1 ? "" : "s"} need attention
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
                <span className={`risk ${request.request.presentation.risk}`}>
                  {request.request.presentation.risk}
                </span>
                <span className="source-label">{request.source_label}</span>
                <h2>{request.request.presentation.title}</h2>
              </div>
              <code>{request.handle.slice(0, 8)}</code>
            </div>
            <PresentationSafety presentation={request.request.presentation} />
            {request.request.presentation.summary && (
              <p>{request.request.presentation.summary}</p>
            )}
            <dl>
              {request.request.presentation.facts?.map((fact) => (
                <React.Fragment key={`${fact.label}-${fact.value}`}>
                  <dt>{fact.label}</dt>
                  <dd>{fact.value}</dd>
                </React.Fragment>
              ))}
            </dl>
            <div className="meta">
              <span>{request.request.requester}</span>
              <span>
                {request.request.requested_max_uses === null
                  ? "Unlimited uses"
                  : `${request.request.requested_max_uses} use${request.request.requested_max_uses === 1 ? "" : "s"}`}
              </span>
              <span>
                {Math.round(request.request.requested_duration_seconds / 60)}{" "}
                min
              </span>
            </div>
            <div className="actions">
              {canDecide &&
                request.request.allowed_actions.includes("revoke") && (
                  <button
                    className="secondary"
                    disabled={busy === request.handle}
                    onClick={() => setDecision({ request, action: "revoke" })}
                  >
                    <CircleX size={16} />
                    Revoke
                  </button>
                )}
              {canDecide &&
                request.request.allowed_actions.includes("deny") && (
                  <button
                    className="secondary"
                    disabled={busy === request.handle}
                    onClick={() => setDecision({ request, action: "deny" })}
                  >
                    <CircleX size={16} />
                    Deny
                  </button>
                )}
              {canDecide &&
                request.request.allowed_actions.includes("approve") && (
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

function PresentationSafety({
  presentation,
  compact = false,
}: {
  presentation: SafeRequest["request"]["presentation"];
  compact?: boolean;
}) {
  return (
    <div className={`presentation-safety${compact ? " compact" : ""}`}>
      <div className="request-target">
        <MapPin size={15} aria-hidden="true" />
        <span>{presentation.target}</span>
      </div>
      {presentation.warnings && presentation.warnings.length > 0 && (
        <ul className="request-warnings" aria-label="Request warnings">
          {presentation.warnings.map((warning) => (
            <li
              className={`request-warning ${warning.severity}`}
              key={`${warning.severity}-${warning.text}`}
            >
              <AlertTriangle size={15} aria-hidden="true" />
              <span>{warning.text}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
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
  const bounds = request?.request.approval_bounds;
  const [durationSeconds, setDurationSeconds] = useState(1);
  const [maxUses, setMaxUses] = useState<number | null>(1);
  useEffect(() => {
    if (!request) return;
    setDurationSeconds(
      Math.max(
        1,
        Math.min(
          request.request.requested_duration_seconds,
          bounds?.max_duration_seconds ??
            request.request.requested_duration_seconds,
        ),
      ),
    );
    const requestedUses = request.request.requested_max_uses;
    const maximumUses = bounds?.max_uses;
    setMaxUses(
      requestedUses === null
        ? null
        : maximumUses === null || maximumUses === undefined
          ? requestedUses
          : Math.min(requestedUses, maximumUses),
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
            {request.request.presentation.title} at revision{" "}
            {request.request.revision}
          </Dialog.Description>
          <PresentationSafety
            presentation={request.request.presentation}
            compact
          />
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
                  max={bounds.max_uses ?? undefined}
                  value={maxUses ?? 1}
                  disabled={maxUses === null}
                  onChange={(event) =>
                    setMaxUses(event.currentTarget.valueAsNumber)
                  }
                />
              </label>
              {bounds.max_uses === null && (
                <label>
                  <input
                    type="checkbox"
                    checked={maxUses === null}
                    onChange={(event) =>
                      setMaxUses(event.currentTarget.checked ? null : 1)
                    }
                  />
                  Unlimited until expiry
                </label>
              )}
            </div>
          )}
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
  maxUses: number | null,
  bounds: SafeRequest["request"]["approval_bounds"],
): boolean {
  if (!approve || !bounds) return true;
  if (maxUses === null) return bounds.max_uses === null;
  return (
    Number.isSafeInteger(durationSeconds) &&
    durationSeconds > 0 &&
    durationSeconds <= bounds.max_duration_seconds &&
    Number.isSafeInteger(maxUses) &&
    maxUses > 0 &&
    (bounds.max_uses === null || maxUses <= bounds.max_uses)
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
