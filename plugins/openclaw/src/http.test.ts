import { createServer, request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createHttpHandler } from "./http.js";
import { BrokerError } from "./client.js";
import { BROWSER_SESSION_HEADER } from "./browser-session.js";

const servers: Array<ReturnType<typeof createServer>> = [];
const capability = "c".repeat(43);
const handle = "h".repeat(22);

afterEach(() => {
  for (const server of servers.splice(0)) server.closeAllConnections();
});

describe("OpenClaw HTTP boundary", () => {
  it("authenticates exact API routes and maps decision errors", async () => {
    const decide = vi.fn(async () => {
      throw new Error("revision_stale");
    });
    const base = await serve({
      snapshot,
      decide,
    });
    expect(
      (
        await fetch(`${base}/plugins/brokerkit/api/v1/snapshot`, {
          headers: { origin: "null" },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await fetch(`${base}/plugins/brokerkit/api/v1/snapshot`, {
          headers: { authorization: `Bearer ${capability}`, origin: "null" },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await apiFetch(base, "/snapshot", {
          headers: { origin: "https://untrusted.example" },
        })
      ).status,
    ).toBe(403);
    expect((await apiFetch(base, "/snapshot?token=nope")).status).toBe(400);
    const response = await apiFetch(base, `/requests/${handle}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        expectedRevision: 2,
        constraints: { durationSeconds: 300, maxUses: 1 },
      }),
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      error: { code: "revision_stale" },
    });
    expect(decide).toHaveBeenCalledWith(
      handle,
      "approve",
      2,
      "openclaw:control-ui",
      {
        constraints: { duration_seconds: 300, max_uses: 1 },
      },
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("accepts one bounded browser session field and rejects ambiguous values", async () => {
    const base = await serve({ snapshot, decide: vi.fn() });
    expect((await apiFetch(base, "/snapshot")).status).toBe(200);
    for (const value of [
      "",
      "short",
      `Bearer ${capability}`,
      `${capability},${capability}`,
      "x".repeat(4097),
      `${capability} invalid`,
    ]) {
      expect(
        (
          await fetch(`${base}/plugins/brokerkit/api/v1/snapshot`, {
            headers: { [BROWSER_SESSION_HEADER]: value, origin: "null" },
          })
        ).status,
      ).toBe(401);
    }
    expect([400, 401]).toContain(
      await rawStatus(base, [
        BROWSER_SESSION_HEADER,
        capability,
        BROWSER_SESSION_HEADER,
        capability,
        "Origin",
        "null",
      ]),
    );
  });

  it("answers strict opaque-origin preflights without cookies", async () => {
    const base = await serve({ snapshot, decide: vi.fn() });
    const response = await fetch(`${base}/plugins/brokerkit/api/v1/snapshot`, {
      method: "OPTIONS",
      headers: {
        origin: "null",
        "access-control-request-method": "GET",
        "access-control-request-headers": BROWSER_SESSION_HEADER,
      },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe("null");
    expect(response.headers.get("access-control-allow-headers")).toContain(
      BROWSER_SESSION_HEADER,
    );
    expect(response.headers.get("access-control-allow-credentials")).toBeNull();
    expect(response.headers.get("vary")).toBe("Origin");
    expect(
      (
        await fetch(`${base}/plugins/brokerkit/api/v1/snapshot`, {
          method: "OPTIONS",
          headers: {
            origin: "null",
            "access-control-request-method": "DELETE",
            "access-control-request-headers": BROWSER_SESSION_HEADER,
          },
        })
      ).status,
    ).toBe(403);
  });

  it("rejects malformed decision requests without leaking diagnostics", async () => {
    const decide = vi.fn();
    const base = await serve({
      snapshot,
      decide,
    });
    for (const [body, contentType = "application/json"] of [
      ["not-json"],
      [JSON.stringify({ expectedRevision: 0 })],
      [JSON.stringify({ expectedRevision: 1, extra: true })],
      ['{"expectedRevision":1,"expectedRevision":2}'],
      [
        '{"expectedRevision":1,"constraints":{"durationSeconds":300,"durationSeconds":60,"maxUses":1}}',
      ],
      [JSON.stringify({ expectedRevision: 1, reason: "removed" })],
      [JSON.stringify({ expectedRevision: 1 }), "text/plain"],
    ] as const) {
      const response = await apiFetch(base, `/requests/${handle}/deny`, {
        method: "POST",
        headers: { "content-type": contentType },
        body,
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        error: { code: "invalid_input" },
      });
    }
    expect(decide).not.toHaveBeenCalled();
  });

  it("preserves an explicit unlimited-use approval constraint", async () => {
    const decide = vi.fn(async () => snapshot());
    const base = await serve({ snapshot, decide });
    const response = await apiFetch(base, `/requests/${handle}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        expectedRevision: 2,
        constraints: { durationSeconds: 300, maxUses: null },
      }),
    });
    expect(response.status).toBe(200);
    expect(decide).toHaveBeenCalledWith(
      handle,
      "approve",
      2,
      "openclaw:control-ui",
      { constraints: { duration_seconds: 300, max_uses: null } },
    );
  });

  it("normalizes Operator V1 errors to stable plugin codes", async () => {
    const decide = vi.fn(async () => {
      throw new BrokerError("revision_conflict", "upstream detail", 409);
    });
    const base = await serve({
      snapshot,
      decide,
    });
    const response = await apiFetch(base, `/requests/${handle}/deny`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expectedRevision: 2 }),
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      error: { code: "revision_stale" },
    });
  });

  it("serves bounded cursor waits and rejects expired cursors", async () => {
    const waitForSnapshot = vi
      .fn()
      .mockResolvedValueOnce({
        api_version: "brokerkit.io/operator-ui/v1",
        cursor: "epoch.2",
        changed: true,
      })
      .mockRejectedValueOnce(new Error("cursor_expired"));
    const base = await serve({
      snapshot: () => snapshot(),
      waitForSnapshot,
      decide: vi.fn(),
    });
    const changed = await apiFetch(
      base,
      "/events?cursor=epoch.1&wait_seconds=25",
    );
    expect(changed.status).toBe(200);
    expect(await changed.json()).toEqual({
      api_version: "brokerkit.io/operator-ui/v1",
      cursor: "epoch.2",
      changed: true,
    });
    expect(waitForSnapshot).toHaveBeenCalledWith(
      "epoch.1",
      25,
      expect.any(AbortSignal),
    );
    expect(
      (await apiFetch(base, "/events?cursor=epoch.1&wait_seconds=26")).status,
    ).toBe(400);
    expect(
      (await apiFetch(base, "/events?cursor=epoch.1&extra=true")).status,
    ).toBe(400);
    expect(
      (await apiFetch(base, "/events?cursor=epoch.1&wait_seconds=1")).status,
    ).toBe(410);
  });

  it("serves only the packaged UI prefix with restrictive headers", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "brokerkit-http-"));
    const ui = path.join(root, "dist", "ui");
    mkdirSync(ui, { recursive: true });
    writeFileSync(
      path.join(ui, "index.html"),
      "<!doctype html><title>Approvals</title>",
    );
    mkdirSync(path.join(ui, "assets"));
    writeFileSync(
      path.join(ui, "assets", "app.js"),
      "globalThis.brokerKit = true;",
    );
    const base = await serve({ snapshot: vi.fn(), decide: vi.fn() }, root);
    const response = await fetch(`${base}/plugins/brokerkit/ui/`);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("Approvals");
    expect(response.headers.get("content-security-policy")).toContain(
      "frame-ancestors 'self'",
    );
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("cross-origin-resource-policy")).toBe(
      "same-origin",
    );
    const asset = await fetch(`${base}/plugins/brokerkit/ui/assets/app.js`);
    expect(asset.status).toBe(200);
    expect(asset.headers.get("cross-origin-resource-policy")).toBe(
      "cross-origin",
    );
    expect((await fetch(`${base}/plugins/brokerkit/unrelated`)).status).toBe(
      404,
    );
    expect(
      (await fetch(`${base}/plugins/brokerkit/ui/?token=nope`)).status,
    ).toBe(404);
  });
});

async function serve(runtime: object, rootDir = "/tmp/missing-plugin") {
  const handler = createHttpHandler(
    () => runtime as never,
    rootDir,
    capability,
  );
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no address");
  return `http://127.0.0.1:${address.port}`;
}

function apiFetch(base: string, route: string, init: RequestInit = {}) {
  return fetch(`${base}/plugins/brokerkit/api/v1${route}`, {
    ...init,
    headers: {
      [BROWSER_SESSION_HEADER]: capability,
      origin: "null",
      ...init.headers,
    },
  });
}

function rawStatus(base: string, rawHeaders: string[]): Promise<number> {
  const url = new URL(`${base}/plugins/brokerkit/api/v1/snapshot`);
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "GET",
        headers: rawHeaders,
      },
      (response) => {
        response.resume();
        response.once("end", () => resolve(response.statusCode ?? 0));
      },
    );
    request.once("error", reject);
    request.end();
  });
}

function snapshot() {
  return {
    api_version: "brokerkit.io/operator-ui/v1",
    cursor: "epoch.1",
    synchronized_at: "2026-07-11T00:00:00Z",
    sources: [],
    requests: [],
    delivery_failures: 0,
  };
}
