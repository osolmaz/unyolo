import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseConfig } from "./config.js";
import { BrokerRuntime } from "./runtime.js";

const servers: Array<ReturnType<typeof createServer>> = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.closeAllConnections();
});

describe("BrokerRuntime", () => {
  it("recovers handles and subscriptions, delivers generically, and decides", async () => {
    let status = "pending";
    let decisionBody = "";
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
            requests: status === "pending" ? [request()] : [],
            event_cursor: "cursor-1",
          }),
        );
      if (req.url === "/api/operator/v1/events?cursor=cursor-1") {
        res.setHeader("content-type", "text/event-stream");
        return;
      }
      if (req.method === "POST") {
        for await (const chunk of req) decisionBody += chunk;
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
    const delivered: string[] = [];
    const hooks = {
      resolveCredential: async () => "operator",
      deliver: async (_subscription: unknown, text: string) => {
        delivered.push(text);
      },
      log: () => undefined,
    };
    let runtime = new BrokerRuntime(config, hooks);
    await runtime.start(stateDir);
    const handle = runtime.snapshot().requests[0]?.handle;
    expect(handle).toBeTruthy();
    runtime.subscribe({ channel: "test", target: "room" });
    await runtime.stop();
    runtime = new BrokerRuntime(config, hooks);
    await runtime.start(stateDir);
    await expect.poll(() => delivered.length).toBeGreaterThan(0);
    expect(delivered.length).toBeLessThanOrEqual(2);
    await runtime.decide(handle!, "approve", 1, "operator:onur");
    expect(JSON.parse(decisionBody)).toMatchObject({
      expected_revision: 1,
      on_behalf_of: "operator:onur",
    });
    await runtime.stop();
  });
});
