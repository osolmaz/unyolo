import { useCallback, useEffect, useRef, useState } from "react";
import type { Snapshot } from "../../src/types.js";
import { BrokerKitUiApi } from "./api.js";

export const UI_INVALIDATE = "brokerkit.operator-ui.invalidate";

export function useBrokerSnapshot(api: BrokerKitUiApi) {
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [canDecide, setCanDecide] = useState(false);
  const [error, setError] = useState("");
  const current = useRef<Snapshot | undefined>(undefined);
  const active = useRef<Promise<Snapshot> | undefined>(undefined);
  const snapshotAbort = useRef<AbortController | undefined>(undefined);
  const wait = useRef<AbortController | undefined>(undefined);
  const generation = useRef(0);

  const reconcile = useCallback((): Promise<Snapshot> => {
    wait.current?.abort();
    if (active.current) return active.current;
    const observedGeneration = ++generation.current;
    const controller = new AbortController();
    snapshotAbort.current = controller;
    const request = api
      .snapshot(controller.signal)
      .then((next) => {
        if (observedGeneration === generation.current) {
          current.current = next;
          setSnapshot(next);
          setCanDecide(api.canDecide());
          setError("");
        }
        return next;
      })
      .catch((value: unknown) => {
        if (!aborted(value)) setError(publicError(value));
        throw value;
      })
      .finally(() => {
        if (active.current === request) active.current = undefined;
        if (snapshotAbort.current === controller)
          snapshotAbort.current = undefined;
      });
    active.current = request;
    return request;
  }, [api]);

  useEffect(() => {
    let stopped = false;
    const lifecycle = new AbortController();
    let retryMs = 250;
    const loop = async () => {
      while (!stopped) {
        try {
          const available = current.current ?? (await reconcile());
          if (stopped) return;
          const controller = new AbortController();
          wait.current = controller;
          const event = await api.events(available.cursor, controller.signal);
          if (wait.current === controller) wait.current = undefined;
          if (event.changed && !stopped) await reconcile();
          retryMs = 250;
        } catch (value) {
          if (stopped) return;
          if (aborted(value)) continue;
          if (errorCode(value) === "cursor_expired") {
            try {
              await reconcile();
              retryMs = 250;
              continue;
            } catch {
              // The normal retry path retains the last valid snapshot.
            }
          }
          setError(publicError(value));
          await delay(retryMs, lifecycle.signal);
          retryMs = Math.min(retryMs * 2, 30_000);
        }
      }
    };
    const refresh = () => void reconcile().catch(() => undefined);
    const visible = () => {
      if (document.visibilityState === "visible") refresh();
    };
    const message = (event: MessageEvent) => {
      if (
        event.source !== window.parent ||
        !record(event.data) ||
        Object.keys(event.data).sort().join(",") !== "type,version" ||
        event.data.type !== UI_INVALIDATE ||
        event.data.version !== 1
      )
        return;
      refresh();
    };
    const safety = window.setInterval(refresh, 5 * 60_000);
    window.addEventListener("focus", refresh);
    window.addEventListener("message", message);
    document.addEventListener("visibilitychange", visible);
    void loop();
    return () => {
      stopped = true;
      lifecycle.abort();
      wait.current?.abort();
      snapshotAbort.current?.abort();
      window.clearInterval(safety);
      window.removeEventListener("focus", refresh);
      window.removeEventListener("message", message);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [api, reconcile]);

  return { snapshot, canDecide, error, setError, reconcile };
}

function errorCode(value: unknown): string | undefined {
  return value instanceof Error && "code" in value
    ? String(value.code)
    : undefined;
}

function publicError(value: unknown): string {
  return value instanceof Error ? value.message : "Approvals are unavailable";
}

function aborted(value: unknown): boolean {
  return value instanceof Error && value.name === "AbortError";
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  const jitter = Math.floor(Math.random() * Math.max(1, ms / 4));
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(done, ms + jitter);
    const abort = () => {
      window.clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(new DOMException("The operation was aborted", "AbortError"));
    };
    function done() {
      signal.removeEventListener("abort", abort);
      resolve();
    }
    signal.addEventListener("abort", abort, { once: true });
  });
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
