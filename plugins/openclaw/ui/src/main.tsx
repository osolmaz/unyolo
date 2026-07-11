import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  Check,
  CircleX,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";
import type { Action, SafeRequest, Snapshot } from "../../src/types.js";
import { BrokerKitUiApi, parseUiBootstrap } from "./api.js";
import "./styles.css";

const api = new BrokerKitUiApi(parseUiBootstrap(location.hash.slice(1)));
history.replaceState(null, "", location.pathname);

export function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
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
  const decide = async (request: SafeRequest, action: Action) => {
    setBusy(request.handle);
    try {
      await api.decide(request, action);
      await load();
    } catch (value) {
      setError(value instanceof Error ? value.message : "Decision failed");
    } finally {
      setBusy("");
    }
  };
  const pending = useMemo(
    () =>
      snapshot?.requests.filter((request) => request.status === "pending") ??
      [],
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
            {pending.length} pending across {snapshot?.sources.length ?? 0}{" "}
            sources
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
        {pending.map((request) => (
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
              {request.allowed_actions.includes("deny") && (
                <button
                  className="secondary"
                  disabled={busy === request.handle}
                  onClick={() => void decide(request, "deny")}
                >
                  <CircleX size={16} />
                  Deny
                </button>
              )}
              {request.allowed_actions.includes("approve") && (
                <button
                  className="primary"
                  disabled={busy === request.handle}
                  onClick={() => void decide(request, "approve")}
                >
                  <Check size={16} />
                  Approve once
                </button>
              )}
            </div>
          </article>
        ))}
        {snapshot && pending.length === 0 && (
          <div className="empty">
            <ShieldCheck size={30} />
            <h2>No pending requests</h2>
            <p>
              Approved, denied, expired, and canceled requests clear
              automatically.
            </p>
          </div>
        )}
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
