import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BrokerKitUiApi,
  DELEGATED_SESSION_REQUEST,
  DELEGATED_SESSION_RESPONSE,
  DELEGATED_SESSION_META,
  parseUiBootstrap,
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

afterEach(() => vi.unstubAllGlobals());

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
            actor: "osolmaz",
            decision_token: "d".repeat(48),
            expires_at: expires,
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

  it("consumes a one-shot delegated session embedded by a trusted sandbox host", async () => {
    const session = {
      api_version: "brokerkit.io/delegated-web/v1",
      actor: "osolmaz",
      decision_token: "e".repeat(48),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
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
    vi.stubGlobal("window", { parent: { postMessage: vi.fn() } });
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ sources: [], requests: [], synchronizedAt: "now" }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new BrokerKitUiApi(parseUiBootstrap(delegated)).snapshot();

    expect(meta.remove).toHaveBeenCalledOnce();
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

  it("rejects overlong delegated sessions", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              api_version: "brokerkit.io/delegated-web/v1",
              actor: "osolmaz",
              decision_token: "d".repeat(48),
              expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
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
              decision_token: "d".repeat(48),
              expires_at: new Date(Date.now() + 60_000).toISOString(),
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
});

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
