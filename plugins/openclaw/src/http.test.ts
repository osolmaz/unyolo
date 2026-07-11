import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createHttpHandler } from "../index.js";

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
      snapshot: () => ({ sources: [], requests: [], synchronizedAt: "now" }),
      decide,
    });
    expect(
      (await fetch(`${base}/plugins/brokerkit/api/v1/snapshot`)).status,
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
        reason: " reviewed ",
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
        reason: "reviewed",
        constraints: { duration_seconds: 300, max_uses: 1 },
      },
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("rejects malformed decision requests without leaking diagnostics", async () => {
    const decide = vi.fn();
    const base = await serve({
      snapshot: () => ({ sources: [], requests: [], synchronizedAt: "now" }),
      decide,
    });
    for (const [body, contentType = "application/json"] of [
      ["not-json"],
      [JSON.stringify({ expectedRevision: 0 })],
      [JSON.stringify({ expectedRevision: 1, extra: true })],
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

  it("serves only the packaged UI prefix with restrictive headers", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "brokerkit-http-"));
    const ui = path.join(root, "dist", "ui");
    mkdirSync(ui, { recursive: true });
    writeFileSync(
      path.join(ui, "index.html"),
      "<!doctype html><title>Approvals</title>",
    );
    const base = await serve({ snapshot: vi.fn(), decide: vi.fn() }, root);
    const response = await fetch(`${base}/plugins/brokerkit/ui/`);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("Approvals");
    expect(response.headers.get("content-security-policy")).toContain(
      "frame-ancestors 'self'",
    );
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
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
      authorization: `Bearer ${capability}`,
      origin: "null",
      ...init.headers,
    },
  });
}
