import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseConfig } from "./config.js";
import { BrokerRuntime } from "./runtime.js";
import type { Subscription } from "./store.js";

const servers: Array<ReturnType<typeof createServer>> = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.closeAllConnections();
});

describe("BrokerRuntime", () => {
  it("recovers handles and subscriptions, delivers generically, and decides", async () => {
    let status = "pending";
    let decisionBody = "";
    let decisionAttempts = 0;
    const decisionBodies: string[] = [];
    const request = () => ({
      id: "request-1",
      revision: status === "pending" ? 1 : 2,
      requester: "bob",
      operation: "write",
      status,
      requested_at: "2026-07-11T00:00:00Z",
      pending_expires_at: "2099-07-11T00:10:00Z",
      requested_duration_seconds: 300,
      requested_max_uses: 1,
      granted_max_uses: status === "pending" ? null : 1,
      used_count: 0,
      presentation: { risk: "high", title: "Protected write", facts: [] },
      allowed_actions:
        status === "pending" ? ["approve", "deny", "cancel"] : ["revoke"],
      approval_bounds: { max_duration_seconds: 300, max_uses: 1 },
    });
    const server = createServer(async (req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.headers.authorization !== "Bearer operator") {
        res.statusCode = 401;
        return res.end();
      }
      if (req.url === "/.well-known/brokerkit-operator")
        return res.end('{"api_version":"brokerkit.io/operator/v1"}');
      if (req.url?.startsWith("/api/operator/v1/requests?"))
        return res.end(
          JSON.stringify({
            requests: req.url.includes(`status=${status}`) ? [request()] : [],
            event_cursor: "cursor-1",
          }),
        );
      if (req.url === "/api/operator/v1/events?cursor=cursor-1") {
        res.setHeader("content-type", "text/event-stream");
        return;
      }
      if (req.method === "POST") {
        let attemptBody = "";
        for await (const chunk of req) attemptBody += chunk;
        decisionAttempts += 1;
        decisionBodies.push(attemptBody);
        if (decisionAttempts === 1) {
          req.socket.destroy();
          return;
        }
        decisionBody = attemptBody;
        status = "active";
        return res.end(JSON.stringify(request()));
      }
      return res.end(JSON.stringify(request()));
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("missing address");
    const config = parseConfig({
      mode: "direct",
      brokers: [
        {
          id: "test",
          label: "Test",
          endpoint: `http://127.0.0.1:${address.port}`,
          operatorCredential: {
            source: "env",
            provider: "default",
            id: "TEST_SECRET",
          },
        },
      ],
      pollIntervalMs: 5000,
    });
    if (config.mode !== "direct") throw new Error("unexpected mode");
    const stateDir = mkdtempSync(path.join(os.tmpdir(), "brokerkit-runtime-"));
    const delivered: Array<{ channel: string; text: string }> = [];
    const hooks = {
      resolveCredential: async () => "operator",
      deliver: async (subscription: Subscription, text: string) => {
        delivered.push({ channel: subscription.channel, text });
      },
      log: () => undefined,
    };
    let runtime = new BrokerRuntime(config, hooks);
    await runtime.start(stateDir);
    const handle = runtime.snapshot().requests[0]?.handle;
    expect(handle).toBeTruthy();
    runtime.subscribe({ channel: "adapter-one", target: "room-one" });
    runtime.subscribe({ channel: "adapter-two", target: "room-two" });
    await runtime.stop();
    runtime = new BrokerRuntime(config, hooks);
    await runtime.start(stateDir);
    await expect
      .poll(() => new Set(delivered.map((item) => item.channel)).size)
      .toBe(2);
    expect(
      delivered.every((item) => item.text.includes("/brokerkit approve")),
    ).toBe(true);
    await expect(
      runtime.decide(handle!, "approve", 1, "operator:onur", {
        constraints: { duration_seconds: 301, max_uses: 1 },
      }),
    ).rejects.toThrow("action_not_allowed");
    await runtime.decide(handle!, "approve", 1, "operator:onur", {
      constraints: { duration_seconds: 300, max_uses: 1 },
    });
    expect(JSON.parse(decisionBody)).toMatchObject({
      expected_revision: 1,
      on_behalf_of: "operator:onur",
      constraints: { duration_seconds: 300, max_uses: 1 },
    });
    expect(decisionAttempts).toBe(2);
    expect(decisionBodies[1]).toBe(decisionBodies[0]);
    await runtime.stop();
    runtime = new BrokerRuntime(config, hooks);
    await runtime.start(stateDir);
    expect(runtime.snapshot().requests).toEqual([
      expect.objectContaining({
        status: "active",
        allowed_actions: ["revoke"],
      }),
    ]);
    await runtime.stop();
  });

  it("keeps healthy sources available when another source fails discovery", async () => {
    const server = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/.well-known/brokerkit-operator") {
        return res.end(
          JSON.stringify({
            api_version:
              req.headers.authorization === "Bearer good"
                ? "brokerkit.io/operator/v1"
                : "brokerkit.io/operator/v2",
          }),
        );
      }
      if (req.url?.startsWith("/api/operator/v1/requests?"))
        return res.end('{"requests":[],"event_cursor":"cursor-1"}');
      if (req.url === "/api/operator/v1/events?cursor=cursor-1") {
        res.setHeader("content-type", "text/event-stream");
        return;
      }
      res.statusCode = 404;
      return res.end('{"error":{"code":"not_found"}}');
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("no address");
    const endpoint = `http://127.0.0.1:${address.port}`;
    const config = parseConfig({
      mode: "direct",
      brokers: [
        brokerConfig("good", endpoint, "GOOD_SECRET"),
        brokerConfig("bad", endpoint, "BAD_SECRET"),
      ],
      pollIntervalMs: 5000,
    });
    if (config.mode !== "direct") throw new Error("unexpected mode");
    const runtime = new BrokerRuntime(config, {
      resolveCredential: async (source) => source.id,
      deliver: async () => undefined,
      log: () => undefined,
    });
    await runtime.start(
      mkdtempSync(path.join(os.tmpdir(), "brokerkit-runtime-")),
    );
    expect(runtime.snapshot().sources).toEqual([
      expect.objectContaining({ id: "bad", healthy: false }),
      expect.objectContaining({ id: "good", healthy: true }),
    ]);
    await runtime.stop();
  });

  it("reconciles an expired event cursor without marking the source unhealthy", async () => {
    let listCalls = 0;
    const server = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/.well-known/brokerkit-operator")
        return res.end('{"api_version":"brokerkit.io/operator/v1"}');
      if (req.url?.startsWith("/api/operator/v1/requests?")) {
        listCalls += 1;
        return res.end('{"requests":[],"event_cursor":"cursor-1"}');
      }
      if (req.url === "/api/operator/v1/events?cursor=cursor-1") {
        res.statusCode = 410;
        return res.end(
          '{"error":{"code":"cursor_expired","message":"expired","correlation_id":"test"}}',
        );
      }
      res.statusCode = 404;
      return res.end(
        '{"error":{"code":"not_found","message":"missing","correlation_id":"test"}}',
      );
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("no address");
    const config = parseConfig({
      mode: "direct",
      brokers: [
        brokerConfig(
          "source",
          `http://127.0.0.1:${address.port}`,
          "SOURCE_SECRET",
        ),
      ],
      pollIntervalMs: 5000,
    });
    if (config.mode !== "direct") throw new Error("unexpected mode");
    const runtime = new BrokerRuntime(config, {
      resolveCredential: async () => "source",
      deliver: async () => undefined,
      log: () => undefined,
    });
    await runtime.start(
      mkdtempSync(path.join(os.tmpdir(), "brokerkit-runtime-")),
    );
    await expect.poll(() => listCalls).toBeGreaterThanOrEqual(4);
    expect(runtime.snapshot().sources).toEqual([
      expect.objectContaining({ id: "source", healthy: true }),
    ]);
    await runtime.stop();
  });
});

function brokerConfig(id: string, endpoint: string, secret: string) {
  return {
    id,
    label: id,
    endpoint,
    operatorCredential: {
      source: "env" as const,
      provider: "default",
      id: secret,
    },
  };
}
