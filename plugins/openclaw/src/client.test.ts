import { createServer } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { BrokerClient } from "./client.js";
import { OPERATOR_V1_SCHEMA_SHA256 } from "./operator-v1.js";

const discovery = JSON.stringify({
  api_version: "unyolo.io/operator/v1",
  contract_digest: OPERATOR_V1_SCHEMA_SHA256,
  build_id: "test",
});

const servers: Array<ReturnType<typeof createServer>> = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.close();
});
describe("BrokerClient", () => {
  it("discovers, lists, decides, and parses SSE with auth", async () => {
    const server = createServer((req, res) => {
      if (
        req.url !== "/healthz" &&
        req.headers.authorization !== "Bearer operator"
      ) {
        res.statusCode = 401;
        return res.end();
      }
      if (req.headers["unyolo-session"] !== undefined) {
        res.statusCode = 400;
        return res.end();
      }
      res.setHeader("content-type", "application/json");
      if (req.url === "/.well-known/unyolo-operator")
        return res.end(discovery);
      if (req.url?.startsWith("/api/operator/v1/requests?"))
        return res.end('{"requests":[],"event_cursor":"cursor-1"}');
      if (req.url === "/api/operator/v1/events") {
        res.setHeader("content-type", "text/event-stream");
        return res.end(
          'id: cursor-2\ndata: {"cursor":"cursor-2","kind":"request.created","request_id":"one","revision":1,"status":"pending","occurred_at":"2026-07-11T00:00:00Z","used_count":0}\n\n',
        );
      }
      return res.end('{"status":"ok"}');
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("no address");
    const client = new BrokerClient(
      `http://127.0.0.1:${address.port}`,
      async () => "operator",
      1000,
    );
    await client.discover();
    expect((await client.list()).event_cursor).toBe("cursor-1");
    const stream = client.events(undefined, new AbortController().signal);
    expect((await stream.next()).value?.cursor).toBe("cursor-2");
  });

  it("rejects unknown response fields and malformed broker data", async () => {
    let malformed = false;
    let includeUnknown = true;
    const server = createServer((req, res) => {
      res.setHeader("content-type", "application/json; charset=utf-8");
      if (req.url?.startsWith("/api/operator/v1/requests?")) {
        return res.end(
          JSON.stringify({
            requests: malformed
              ? [{ id: "request-1", revision: "not-an-integer" }]
              : [],
            event_cursor: "cursor-1",
            ...(includeUnknown ? { future_field: "rejected" } : {}),
          }),
        );
      }
      return res.end(discovery);
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("no address");
    const client = new BrokerClient(
      `http://127.0.0.1:${address.port}`,
      async () => "operator",
      1000,
    );
    await expect(client.list()).rejects.toThrow();
    includeUnknown = false;
    malformed = true;
    await expect(client.list()).rejects.toThrow();
  });

  it("rejects wrong media types and oversized SSE frames", async () => {
    const server = createServer((req, res) => {
      if (req.url?.startsWith("/api/operator/v1/requests?")) {
        res.setHeader("content-type", "text/plain");
        return res.end('{"requests":[]}');
      }
      res.setHeader("content-type", "text/event-stream");
      return res.end(`data: ${"x".repeat(256_001)}\n\n`);
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("no address");
    const client = new BrokerClient(
      `http://127.0.0.1:${address.port}`,
      async () => "operator",
      1000,
    );
    await expect(client.list()).rejects.toThrow("invalid content type");
    const stream = client.events(undefined, new AbortController().signal);
    await expect(stream.next()).rejects.toThrow("frame is too large");
  });
});
