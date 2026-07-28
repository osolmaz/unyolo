// @vitest-environment jsdom

import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Snapshot, SnapshotEvent } from "../../src/types.js";
import { unYOLOUiApi } from "./api.js";
import { UI_INVALIDATE, useBrokerSnapshot } from "./use-broker-snapshot.js";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("useBrokerSnapshot recovery", () => {
  it("clears an event error after an unchanged successful wait", async () => {
    vi.spyOn(Math, "random").mockReturnValue(0);
    const api = fakeApi({
      snapshots: [snapshot("epoch.1")],
      events: [
        Promise.reject(new Error("Approvals are unavailable")),
        Promise.resolve(event("epoch.1", false)),
        pendingEvent(),
      ],
    });
    const { result } = renderHook(() => useBrokerSnapshot(api));

    await waitFor(() =>
      expect(result.current.error).toBe("Approvals are unavailable"),
    );
    await waitFor(() => expect(result.current.error).toBe(""), {
      timeout: 2_000,
    });
    expect(result.current.snapshot?.cursor).toBe("epoch.1");
  });

  it("clears a snapshot error after an invalidation refresh", async () => {
    vi.spyOn(Math, "random").mockReturnValue(0);
    const api = fakeApi({
      snapshots: [
        Promise.reject(new Error("Approvals are unavailable")),
        snapshot("epoch.2"),
      ],
      events: [pendingEvent()],
    });
    const { result } = renderHook(() => useBrokerSnapshot(api));

    await waitFor(() =>
      expect(result.current.error).toBe("Approvals are unavailable"),
    );
    act(() => {
      window.dispatchEvent(
        new MessageEvent("message", {
          source: window.parent,
          data: { type: UI_INVALIDATE, version: 1 },
        }),
      );
    });
    await waitFor(() =>
      expect(result.current.snapshot?.cursor).toBe("epoch.2"),
    );
    expect(result.current.error).toBe("");
  });

  it("recovers an expired cursor with a fresh snapshot", async () => {
    const expired = Object.assign(new Error("Approval updates expired"), {
      code: "cursor_expired",
    });
    const api = fakeApi({
      snapshots: [snapshot("epoch.1"), snapshot("epoch.2")],
      events: [Promise.reject(expired), pendingEvent()],
    });
    const { result } = renderHook(() => useBrokerSnapshot(api));

    await waitFor(() =>
      expect(result.current.snapshot?.cursor).toBe("epoch.2"),
    );
    expect(result.current.error).toBe("");
  });
});

function fakeApi(params: {
  snapshots: Array<Snapshot | Promise<Snapshot>>;
  events: Array<SnapshotEvent | Promise<SnapshotEvent>>;
}): unYOLOUiApi {
  return {
    snapshot: vi.fn(async () => await shift(params.snapshots, "snapshot")),
    events: vi.fn(async () => await shift(params.events, "event")),
    canDecide: vi.fn(() => true),
  } as unknown as unYOLOUiApi;
}

async function shift<T>(
  values: Array<T | Promise<T>>,
  label: string,
): Promise<T> {
  const next = values.shift();
  if (!next) throw new Error(`unexpected ${label} call`);
  return await next;
}

function snapshot(cursor: string): Snapshot {
  return {
    api_version: "unyolo.io/operator-ui/v1",
    cursor,
    sources: [],
    requests: [],
    synchronized_at: "2026-07-14T00:00:00Z",
    delivery_failures: 0,
  };
}

function event(cursor: string, changed: boolean): SnapshotEvent {
  return {
    api_version: "unyolo.io/operator-ui/v1",
    cursor,
    changed,
  };
}

function pendingEvent(): Promise<SnapshotEvent> {
  return new Promise(() => undefined);
}
