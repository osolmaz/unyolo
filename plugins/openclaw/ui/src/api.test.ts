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
} from "./api.js";

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
  it("uses the direct capability without browser credentials", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ sources: [], requests: [], synchronizedAt: "now" }),
          {
            status: 200,
          },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(direct));
    await api.snapshot();
    expect(api.canDecide()).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "/plugins/brokerkit/api/v1/snapshot",
      expect.objectContaining({
        credentials: "omit",
        headers: expect.objectContaining({
          authorization: `Bearer ${"a".repeat(43)}`,
        }),
      }),
    );
  });

  it("bootstraps a delegated token with cookies then omits them from API calls", async () => {
    const expires = new Date(Date.now() + 60_000).toISOString();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            api_version: "brokerkit.io/delegated-web/v1",
            token: "d".repeat(48),
            expires_at: expires,
            access: "decide",
            renewal_transport: "direct",
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ sources: [], requests: [], synchronizedAt: "now" }),
          {
            status: 200,
          },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));
    await api.snapshot();
    expect(api.canDecide()).toBe(true);
    expect(fetchMock.mock.calls[0]).toEqual([
      "/trusted-host/api/brokerkit/session",
      expect.objectContaining({ credentials: "include" }),
    ]);
    expect(fetchMock.mock.calls[1]).toEqual([
      "/trusted-host/api/brokerkit/snapshot",
      expect.objectContaining({
        credentials: "omit",
        headers: expect.objectContaining({
          authorization: `Bearer ${"d".repeat(48)}`,
        }),
      }),
    ]);
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
        new Response(
          JSON.stringify({ sources: [], requests: [], synchronizedAt: "now" }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));
    await api.snapshot();

    expect(meta.remove).toHaveBeenCalledOnce();
    expect(api.canDecide()).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledWith(
      "/trusted-host/api/brokerkit/snapshot",
      expect.objectContaining({
        headers: expect.objectContaining({
          authorization: `Bearer ${"e".repeat(48)}`,
        }),
      }),
    );
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
        new Response(
          JSON.stringify({ sources: [], requests: [], synchronizedAt: "now" }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));
    await api.snapshot();

    expect(meta.remove).toHaveBeenCalledOnce();
    expect(api.canDecide()).toBe(false);
    expect(parent.postMessage).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledWith(
      "/trusted-host/api/brokerkit/snapshot",
      expect.objectContaining({
        credentials: "omit",
        headers: expect.objectContaining({
          authorization: `Bearer ${"e".repeat(48)}`,
        }),
      }),
    );
  });

  it("rejects decision authority inside a delegated frame", async () => {
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
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      new BrokerKitUiApi(parseUiBootstrap(delegated)).snapshot(),
    ).rejects.toThrow("session is invalid");

    expect(meta.remove).toHaveBeenCalledOnce();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("renews delegated authority with the current bearer token", async () => {
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
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ sources: [], requests: [], synchronizedAt: "now" }),
        ),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(renewed)))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            sources: [],
            requests: [],
            synchronizedAt: "later",
          }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));

    await api.snapshot();
    now += 2_000;
    embedded = null;
    await api.snapshot();

    expect(fetchMock.mock.calls[1]).toEqual([
      "/trusted-host/api/brokerkit/session",
      expect.objectContaining({
        credentials: "omit",
        headers: { authorization: `Bearer ${"f".repeat(48)}` },
      }),
    ]);
    expect(fetchMock.mock.calls[2]?.[1]).toEqual(
      expect.objectContaining({
        headers: expect.objectContaining({
          authorization: `Bearer ${"r".repeat(48)}`,
        }),
      }),
    );
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
    const snapshot = { sources: [], requests: [], synchronizedAt: "now" };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(initial)))
      .mockResolvedValueOnce(new Response(JSON.stringify(snapshot)))
      .mockResolvedValueOnce(new Response(JSON.stringify(renewed)))
      .mockImplementation(async () => new Response(JSON.stringify(snapshot)));
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));

    await api.snapshot();
    now += 2_000;
    await Promise.all([api.snapshot(), api.snapshot()]);

    const renewals = fetchMock.mock.calls.filter(
      ([url, init]) =>
        url === "/trusted-host/api/brokerkit/session" &&
        (init as RequestInit).credentials === "omit",
    );
    expect(renewals).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledTimes(5);
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
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              api_version: "brokerkit.io/delegated-web/v1",
              token: "d".repeat(48),
              expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
              access: "decide",
              renewal_transport: "direct",
            }),
            { status: 200 },
          ),
      ),
    );
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));
    await expect(api.snapshot()).rejects.toThrow("session is invalid");
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
        new Response(
          JSON.stringify({ sources: [], requests: [], synchronizedAt: "now" }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new BrokerKitUiApi(parseUiBootstrap(delegated)).snapshot();

    expect(parent.postMessage).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledWith(
      "/trusted-host/api/brokerkit/snapshot",
      expect.objectContaining({
        headers: expect.objectContaining({
          authorization: `Bearer ${"d".repeat(48)}`,
        }),
      }),
    );
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
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ sources: [], requests: [], synchronizedAt: "now" }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            sources: [],
            requests: [],
            synchronizedAt: "later",
          }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const api = new BrokerKitUiApi(parseUiBootstrap(delegated));

    await api.snapshot();
    now += 2_000;
    await api.snapshot();

    expect(parent.postMessage).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1]?.[1]).toEqual(
      expect.objectContaining({
        headers: expect.objectContaining({
          authorization: `Bearer ${"r".repeat(48)}`,
        }),
      }),
    );
  });
});

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
