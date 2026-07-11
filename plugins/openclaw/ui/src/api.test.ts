import { afterEach, describe, expect, it, vi } from "vitest";
import { BrokerKitUiApi, parseUiBootstrap } from "./api.js";

const direct = encoded({
  version: 1,
  mode: "direct",
  capability: "a".repeat(43),
});
const delegated = encoded({
  version: 1,
  mode: "delegated-web",
  basePath: "/mlclaw/api/brokerkit",
});

afterEach(() => vi.unstubAllGlobals());

describe("parseUiBootstrap", () => {
  it("accepts closed direct and delegated bootstraps", () => {
    expect(parseUiBootstrap(direct)).toMatchObject({ mode: "direct" });
    expect(parseUiBootstrap(delegated)).toEqual({
      version: 1,
      mode: "delegated-web",
      basePath: "/mlclaw/api/brokerkit",
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
      "/mlclaw/api/brokerkit/session",
      expect.objectContaining({ credentials: "include" }),
    ]);
    expect(fetchMock.mock.calls[1]).toEqual([
      "/mlclaw/api/brokerkit/snapshot",
      expect.objectContaining({
        credentials: "omit",
        headers: expect.objectContaining({
          authorization: `Bearer ${"d".repeat(48)}`,
        }),
      }),
    ]);
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
});

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
