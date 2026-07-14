import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BrokerKitUiApi,
  DELEGATED_OPEN_REQUEST,
  DELEGATED_SESSION_META,
  DELEGATED_SESSION_REQUEST,
  DELEGATED_SESSION_RESPONSE,
  DELEGATED_TOP_LEVEL_META,
  parseUiBootstrap,
  requestDelegatedTopLevelOpen,
  takeDelegatedTopLevelLauncher,
  browserSessionHeaders,
} from "./api.js";
import { BROWSER_SESSION_HEADER } from "../../src/browser-session.js";
import type { SafeRequest } from "../../src/types.js";

const direct = encoded({
  version: 1,
  mode: "direct",
  capability: "a".repeat(43),
});
const delegated = encoded({
  version: 1,
  mode: "delegated-web",
  basePath: "/trusted-host/api/brokerkit",
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("parseUiBootstrap", () => {
  it("accepts closed direct and delegated bootstraps", () => {
    expect(parseUiBootstrap(direct)).toMatchObject({ mode: "direct" });
    expect(parseUiBootstrap(delegated)).toEqual({
      version: 1,
      mode: "delegated-web",
      basePath: "/trusted-host/api/brokerkit",
    });
  });

  it("rejects unknown fields, origins, traversal, and malformed input", () => {
    for (const value of [
      "not-base64",
      encoded({ version: 1, mode: "direct", capability: "short" }),
      encoded({
        version: 1,
        mode: "delegated-web",
        basePath: "https://example.com/api",
      }),
      encoded({
        version: 1,
        mode: "delegated-web",
        basePath: "/api/../admin",
      }),
      encoded({
        version: 1,
        mode: "delegated-web",
        basePath: "/api",
        extra: true,
      }),
    ]) {
      expect(() => parseUiBootstrap(value)).toThrow("bootstrap is invalid");
    }
  });
});

describe("BrokerKitUiApi", () => {
  it("uses the dedicated session field for direct browser requests", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify(emptySnapshot()), {
          status: 200,
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(direct));
    await api.snapshot();
    expect(api.canDecide()).toBe(true);
    expect(fetchCall(fetchMock, 0)[0]).toBe(
      "/plugins/brokerkit/api/v1/snapshot",
    );
    expectBrowserSession(fetchCall(fetchMock, 0)[1], "a".repeat(43));
  });

  it("uses the dedicated session field on every direct and delegated route", async () => {
    const delegatedToken = "d".repeat(48);
    const meta = {
      getAttribute: vi.fn(() =>
        encoded({
          api_version: "brokerkit.io/delegated-web/v1",
          token: delegatedToken,
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          access: "decide",
          renewal_transport: "direct",
        }),
      ),
      remove: vi.fn(),
    };
    vi.stubGlobal("document", { querySelector: vi.fn(() => meta) });
    const topLevelWindow: { parent?: unknown } = {};
    topLevelWindow.parent = topLevelWindow;
    vi.stubGlobal("window", topLevelWindow);
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.includes("/events?"))
        return Response.json({
          api_version: "brokerkit.io/operator-ui/v1",
          cursor: "epoch.1",
          changed: false,
        });
      if (url.endsWith("/snapshot")) return Response.json(emptySnapshot());
      return Response.json(safeRequest());
    });
    vi.stubGlobal("fetch", fetchMock);

    const cases = [
      {
        api: new BrokerKitUiApi(parseUiBootstrap(direct)),
        basePath: "/plugins/brokerkit/api/v1",
        token: "a".repeat(43),
      },
      {
        api: new BrokerKitUiApi(parseUiBootstrap(delegated)),
        basePath: "/trusted-host/api/brokerkit",
        token: delegatedToken,
      },
    ];
    for (const value of cases) {
      const firstCall = fetchCalls(fetchMock).length;
      const controller = new AbortController();
      const request = safeRequest();
      await value.api.snapshot();
      await value.api.events("epoch.1", controller.signal);
      await value.api.detail(request.handle);
      await value.api.decide(request, "approve");
      await value.api.decide(request, "deny");
      await value.api.decide(request, "revoke");

      const calls = fetchCalls(fetchMock).slice(firstCall);
      expect(calls.map(([url]) => String(url))).toEqual([
        `${value.basePath}/snapshot`,
        `${value.basePath}/events?cursor=epoch.1&wait_seconds=25`,
        `${value.basePath}/requests/${request.handle}`,
        `${value.basePath}/requests/${request.handle}/approve`,
        `${value.basePath}/requests/${request.handle}/deny`,
        `${value.basePath}/requests/${request.handle}/revoke`,
      ]);
      for (const [, init] of calls) expectBrowserSession(init, value.token);
    }
  });

  it("waits with an authenticated bounded cursor request", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        api_version: "brokerkit.io/operator-ui/v1",
        cursor: "epoch.2",
        changed: true,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(direct));
    const controller = new AbortController();
    await expect(
      api.events("epoch.1", controller.signal),
    ).resolves.toMatchObject({
      cursor: "epoch.2",
      changed: true,
    });
    expect(fetchCall(fetchMock, 0)[0]).toBe(
      "/plugins/brokerkit/api/v1/events?cursor=epoch.1&wait_seconds=25",
    );
    expect(fetchCall(fetchMock, 0)[1]).toEqual(
      expect.objectContaining({ signal: controller.signal }),
    );
    expectBrowserSession(fetchCall(fetchMock, 0)[1], "a".repeat(43));
  });

  it("does not bootstrap delegated authority with cookies", async () => {
    const topLevelWindow: { parent?: unknown } = {};
    topLevelWindow.parent = topLevelWindow;
    vi.stubGlobal("window", topLevelWindow);
    vi.stubGlobal("document", { querySelector: vi.fn(() => null) });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));
    await expect(api.snapshot()).rejects.toThrow(
      "Approval authorization expired",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("consumes a one-shot delegated session embedded by a trusted host", async () => {
    const session = {
      api_version: "brokerkit.io/delegated-web/v1",
      token: "e".repeat(48),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      access: "decide",
      renewal_transport: "direct",
    };
    const meta = {
      getAttribute: vi.fn(() => encoded(session)),
      remove: vi.fn(),
    };
    vi.stubGlobal("document", {
      querySelector: vi.fn((selector: string) => {
        expect(selector).toBe(`meta[name="${DELEGATED_SESSION_META}"]`);
        return meta;
      }),
    });
    const topLevelWindow: { parent?: unknown } = {};
    topLevelWindow.parent = topLevelWindow;
    vi.stubGlobal("window", topLevelWindow);
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify(emptySnapshot()), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));
    await api.snapshot();

    expect(meta.remove).toHaveBeenCalledOnce();
    expect(api.canDecide()).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    expectBrowserSession(fetchCall(fetchMock, 0)[1], "e".repeat(48));
  });

  it("consumes a trusted embedded delegated session while framed", async () => {
    const session = {
      api_version: "brokerkit.io/delegated-web/v1",
      token: "e".repeat(48),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      access: "read",
      renewal_transport: "direct",
    };
    const meta = {
      getAttribute: vi.fn(() => encoded(session)),
      remove: vi.fn(),
    };
    vi.stubGlobal("document", { querySelector: vi.fn(() => meta) });
    const parent = { postMessage: vi.fn() };
    vi.stubGlobal("window", { parent });
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify(emptySnapshot()), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));
    await api.snapshot();

    expect(meta.remove).toHaveBeenCalledOnce();
    expect(api.canDecide()).toBe(false);
    expect(parent.postMessage).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledOnce();
    expectBrowserSession(fetchCall(fetchMock, 0)[1], "e".repeat(48));
  });

  it("accepts decision authority inside a delegated frame", async () => {
    const session = {
      api_version: "brokerkit.io/delegated-web/v1",
      token: "e".repeat(48),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      access: "decide",
      renewal_transport: "direct",
    };
    const meta = {
      getAttribute: vi.fn(() => encoded(session)),
      remove: vi.fn(),
    };
    vi.stubGlobal("document", { querySelector: vi.fn(() => meta) });
    vi.stubGlobal("window", { parent: {} });
    const fetchMock = vi.fn(async () => Response.json(emptySnapshot()));
    vi.stubGlobal("fetch", fetchMock);

    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));
    await api.snapshot();

    expect(meta.remove).toHaveBeenCalledOnce();
    expect(api.canDecide()).toBe(true);
    expectBrowserSession(fetchCall(fetchMock, 0)[1], "e".repeat(48));
  });

  it("renews delegated authority with the current browser session", async () => {
    let now = Date.now();
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const first = {
      api_version: "brokerkit.io/delegated-web/v1",
      token: "f".repeat(48),
      expires_at: new Date(now + 31_000).toISOString(),
      access: "decide",
      renewal_transport: "direct",
    };
    const renewed = {
      api_version: "brokerkit.io/delegated-web/v1",
      token: "r".repeat(48),
      expires_at: new Date(now + 60_000).toISOString(),
      access: "decide",
      renewal_transport: "direct",
    };
    const meta = { getAttribute: vi.fn(() => encoded(first)), remove: vi.fn() };
    let embedded: typeof meta | null = meta;
    vi.stubGlobal("document", { querySelector: vi.fn(() => embedded) });
    const topLevelWindow: { parent?: unknown } = {};
    topLevelWindow.parent = topLevelWindow;
    vi.stubGlobal("window", topLevelWindow);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(emptySnapshot())))
      .mockResolvedValueOnce(new Response(JSON.stringify(renewed)))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(emptySnapshot("2026-07-11T00:00:01Z", "epoch.2")),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));

    await api.snapshot();
    now += 2_000;
    embedded = null;
    await api.snapshot();

    expect(fetchCall(fetchMock, 1)[0]).toBe(
      "/trusted-host/api/brokerkit/session",
    );
    expectBrowserSession(fetchCall(fetchMock, 1)[1], "f".repeat(48));
    expectBrowserSession(fetchCall(fetchMock, 2)[1], "r".repeat(48));
  });

  it("shares one renewal across concurrent delegated requests", async () => {
    let now = Date.now();
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const initial = {
      api_version: "brokerkit.io/delegated-web/v1",
      token: "f".repeat(48),
      expires_at: new Date(now + 31_000).toISOString(),
      access: "decide",
      renewal_transport: "direct",
    };
    const renewed = {
      api_version: "brokerkit.io/delegated-web/v1",
      token: "r".repeat(48),
      expires_at: new Date(now + 60_000).toISOString(),
      access: "decide",
      renewal_transport: "direct",
    };
    const snapshot = emptySnapshot();
    const meta = {
      getAttribute: vi.fn(() => encoded(initial)),
      remove: vi.fn(),
    };
    let embedded: typeof meta | null = meta;
    vi.stubGlobal("document", { querySelector: vi.fn(() => embedded) });
    const topLevelWindow: { parent?: unknown } = {};
    topLevelWindow.parent = topLevelWindow;
    vi.stubGlobal("window", topLevelWindow);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(snapshot)))
      .mockResolvedValueOnce(new Response(JSON.stringify(renewed)))
      .mockImplementation(async () => new Response(JSON.stringify(snapshot)));
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));

    await api.snapshot();
    now += 2_000;
    embedded = null;
    await Promise.all([api.snapshot(), api.snapshot()]);

    const renewals = fetchCalls(fetchMock).filter(
      ([url, init]) =>
        url === "/trusted-host/api/brokerkit/session" &&
        (init as RequestInit).credentials === "omit",
    );
    expect(renewals).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("recognizes the framed launcher and requests top-level navigation", () => {
    const meta = { remove: vi.fn() };
    vi.stubGlobal("document", {
      querySelector: vi.fn((selector: string) => {
        expect(selector).toBe(`meta[name="${DELEGATED_TOP_LEVEL_META}"]`);
        return meta;
      }),
    });
    const parent = { postMessage: vi.fn() };
    vi.stubGlobal("window", { parent });

    expect(takeDelegatedTopLevelLauncher()).toBe(true);
    requestDelegatedTopLevelOpen();

    expect(meta.remove).toHaveBeenCalledOnce();
    expect(parent.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: DELEGATED_OPEN_REQUEST,
        version: 1,
        nonce: expect.stringMatching(/^[a-f0-9]{32}$/u),
      }),
      "*",
    );
  });

  it("rejects overlong delegated sessions", async () => {
    const meta = {
      getAttribute: vi.fn(() =>
        encoded({
          api_version: "brokerkit.io/delegated-web/v1",
          token: "d".repeat(4097),
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          access: "decide",
          renewal_transport: "direct",
        }),
      ),
      remove: vi.fn(),
    };
    vi.stubGlobal("document", { querySelector: vi.fn(() => meta) });
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));
    await expect(api.snapshot()).rejects.toThrow("session is invalid");
    expect(meta.remove).toHaveBeenCalledOnce();
  });

  it("rejects expired and malformed delegated sessions", async () => {
    const values = [
      {
        token: "d".repeat(48),
        expires_at: new Date(Date.now() - 1_000).toISOString(),
      },
      {
        token: "malformed session value",
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      },
    ];
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    for (const value of values) {
      const meta = {
        getAttribute: vi.fn(() =>
          encoded({
            api_version: "brokerkit.io/delegated-web/v1",
            ...value,
            access: "decide",
            renewal_transport: "direct",
          }),
        ),
        remove: vi.fn(),
      };
      vi.stubGlobal("document", { querySelector: vi.fn(() => meta) });
      await expect(
        new BrokerKitUiApi(parseUiBootstrap(delegated)).snapshot(),
      ).rejects.toThrow("session is invalid");
      expect(meta.remove).toHaveBeenCalledOnce();
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses the host-neutral nonce-bound parent bridge", async () => {
    let receive: ((event: MessageEvent) => void) | undefined;
    const parent = {
      postMessage: vi.fn((message: Record<string, unknown>) => {
        expect(message.type).toBe(DELEGATED_SESSION_REQUEST);
        expect(message.version).toBe(1);
        expect(message.nonce).toMatch(/^[a-f0-9]{32}$/u);
        receive?.({
          source: parent,
          data: {
            type: DELEGATED_SESSION_RESPONSE,
            nonce: message.nonce,
            session: {
              api_version: "brokerkit.io/delegated-web/v1",
              token: "d".repeat(48),
              expires_at: new Date(Date.now() + 60_000).toISOString(),
              access: "read",
              renewal_transport: "parent",
            },
          },
        } as unknown as MessageEvent);
      }),
    };
    const fakeWindow = {
      parent,
      setTimeout,
      clearTimeout,
      addEventListener: vi.fn((_name: string, callback: typeof receive) => {
        receive = callback;
      }),
      removeEventListener: vi.fn(),
    };
    vi.stubGlobal("window", fakeWindow);
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify(emptySnapshot()), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new BrokerKitUiApi(parseUiBootstrap(delegated)).snapshot();

    expect(parent.postMessage).toHaveBeenCalledOnce();
    expectBrowserSession(fetchCall(fetchMock, 0)[1], "d".repeat(48));
  });

  it("renews framed delegated authority through the parent bridge", async () => {
    let now = Date.now();
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let receive: ((event: MessageEvent) => void) | undefined;
    let sessions = 0;
    const parent = {
      postMessage: vi.fn((message: Record<string, unknown>) => {
        sessions += 1;
        receive?.({
          source: parent,
          data: {
            type: DELEGATED_SESSION_RESPONSE,
            nonce: message.nonce,
            session: {
              api_version: "brokerkit.io/delegated-web/v1",
              token: (sessions === 1 ? "f" : "r").repeat(48),
              expires_at: new Date(
                now + (sessions === 1 ? 31_000 : 60_000),
              ).toISOString(),
              access: "read",
              renewal_transport: "parent",
            },
          },
        } as unknown as MessageEvent);
      }),
    };
    const fakeWindow = {
      parent,
      setTimeout,
      clearTimeout,
      addEventListener: vi.fn((_name: string, callback: typeof receive) => {
        receive = callback;
      }),
      removeEventListener: vi.fn(),
    };
    vi.stubGlobal("window", fakeWindow);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(emptySnapshot())))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(emptySnapshot("2026-07-11T00:00:01Z", "epoch.2")),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));

    await api.snapshot();
    now += 2_000;
    await api.snapshot();

    expect(parent.postMessage).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expectBrowserSession(fetchCall(fetchMock, 1)[1], "r".repeat(48));
  });

  it("strips caller authentication fields before applying the session", () => {
    const headers = browserSessionHeaders(
      [
        ["Authorization", "Bearer caller-secret"],
        ["brokerkit-session", "caller-session"],
        ["BrokerKit-Session", "duplicate-session"],
        ["Content-Type", "application/json"],
      ],
      "s".repeat(48),
    );
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get(BROWSER_SESSION_HEADER)).toBe("s".repeat(48));
    expect(headers.get("content-type")).toBe("application/json");
  });

  it("never exposes response details or session values in errors", async () => {
    const secret = "s".repeat(48);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json(
          { error: { code: "unknown", detail: secret }, body: secret },
          { status: 500 },
        ),
      ),
    );
    const api = new BrokerKitUiApi(
      parseUiBootstrap(
        encoded({ version: 1, mode: "direct", capability: secret }),
      ),
    );
    await expect(api.snapshot()).rejects.toThrow(
      "The approval request could not be completed",
    );
    await api.snapshot().catch((error: unknown) => {
      expect(String(error)).not.toContain(secret);
    });
  });
});

function expectBrowserSession(init: unknown, session: string): void {
  const request = init as RequestInit;
  expect(request.credentials).toBe("omit");
  expect(request.cache).toBe("no-store");
  const headers = new Headers(request.headers);
  expect(headers.get(BROWSER_SESSION_HEADER)).toBe(session);
  expect(headers.get("authorization")).toBeNull();
}

function fetchCall(mock: unknown, index: number): [unknown, RequestInit] {
  const call = fetchCalls(mock)[index];
  if (!call) throw new Error(`missing fetch call ${index}`);
  return call;
}

function fetchCalls(mock: unknown): Array<[unknown, RequestInit]> {
  return (mock as { mock: { calls: Array<[unknown, RequestInit]> } }).mock
    .calls;
}

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function emptySnapshot(
  synchronizedAt = "2026-07-11T00:00:00Z",
  cursor = "epoch.1",
) {
  return {
    api_version: "brokerkit.io/operator-ui/v1",
    cursor,
    sources: [],
    requests: [],
    synchronized_at: synchronizedAt,
    delivery_failures: 0,
  };
}

function safeRequest(): SafeRequest {
  return {
    source_id: "hf",
    source_label: "Hugging Face",
    handle: "opaque-request-handle-1",
    request: {
      id: "request-1",
      revision: 1,
      requester: "bob",
      operation: "repo.update",
      status: "pending",
      requested_at: "2026-07-11T00:00:00Z",
      pending_expires_at: "2026-07-11T00:10:00Z",
      requested_duration_seconds: 300,
      requested_max_uses: 1,
      granted_max_uses: null,
      used_count: 0,
      presentation: {
        risk: "high",
        title: "Repository update",
        facts: [],
      },
      allowed_actions: ["approve", "deny", "revoke"],
      approval_bounds: { max_duration_seconds: 300, max_uses: 1 },
    },
  };
}
