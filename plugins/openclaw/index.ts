import { createReadStream, existsSync, statSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import path from "node:path";
import {
  definePluginEntry,
  type OpenClawPluginApi,
  type PluginCommandContext,
} from "openclaw/plugin-sdk/plugin-entry";
import { resolveConfiguredSecretInputString } from "openclaw/plugin-sdk/secret-input-runtime";
import { parseConfig, type BrokerConfig } from "./src/config.js";
import { BrokerError } from "./src/client.js";
import { BrokerRuntime, type DecisionOptions } from "./src/runtime.js";
import type { Action } from "./src/types.js";

const configSchema = { parse: parseConfig };

type DirectBootstrap = {
  version: 1;
  mode: "direct";
  capability: string;
};
type DelegatedBootstrap = {
  version: 1;
  mode: "delegated-web";
  basePath: string;
};

export function registerBrokerKit(api: OpenClawPluginApi): void {
  const config = parseConfig(api.pluginConfig);
  const capability =
    config.mode === "direct"
      ? randomBytes(32).toString("base64url")
      : undefined;
  const bootstrap: DirectBootstrap | DelegatedBootstrap =
    config.mode === "direct"
      ? {
          version: 1,
          mode: "direct",
          capability: requiredCapability(capability),
        }
      : {
          version: 1,
          mode: "delegated-web",
          basePath: config.delegatedWeb.basePath,
        };
  let runtime: BrokerRuntime | undefined;
  const requireRuntime = () => {
    if (!runtime) throw new Error("BrokerKit runtime is not running");
    return runtime;
  };
  api.session.controls.registerControlUiDescriptor({
    surface: "tab",
    id: "brokerkit",
    label: "Approvals",
    description: "Review pending BrokerKit requests.",
    icon: "shield-check",
    group: "control",
    requiredScopes: ["operator.approvals"],
    path: `/plugins/brokerkit/ui/#${encodeUiBootstrap(bootstrap)}`,
  });
  if (config.mode === "direct") {
    api.registerService({
      id: "brokerkit",
      start: async (ctx) => {
        runtime = new BrokerRuntime(config, {
          resolveCredential: (source) => resolveCredential(api, source),
          deliver: async (subscription, text) => {
            const adapter = await api.runtime.channel.outbound.loadAdapter(
              subscription.channel,
            );
            if (!adapter?.sendText)
              throw new Error("channel does not support text delivery");
            await adapter.sendText({
              cfg: api.config,
              to: subscription.target,
              text,
              ...(subscription.accountId
                ? { accountId: subscription.accountId }
                : {}),
              ...(subscription.threadId
                ? { threadId: subscription.threadId }
                : {}),
            });
          },
          log: (level, message) => api.logger[level]?.(message),
        });
        await runtime.start(ctx.stateDir);
      },
      stop: async () => {
        await runtime?.stop();
        runtime = undefined;
      },
    });
    api.registerCommand({
      name: "brokerkit",
      description: "Review and decide BrokerKit approval requests.",
      acceptsArgs: true,
      requireAuth: true,
      requiredScopes: ["operator.approvals"],
      handler: (ctx) => handleCommand(requireRuntime(), ctx),
    });
  }
  api.registerHttpRoute({
    path: "/plugins/brokerkit",
    auth: "plugin",
    match: "prefix",
    handler: createHttpHandler(
      config.mode === "direct" ? requireRuntime : undefined,
      api.rootDir ?? process.cwd(),
      capability,
    ),
  });
}

function encodeUiBootstrap(
  value: DirectBootstrap | DelegatedBootstrap,
): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function requiredCapability(value: string | undefined): string {
  if (!value) throw new Error("BrokerKit UI capability was not initialized");
  return value;
}

export default definePluginEntry({
  id: "brokerkit",
  name: "BrokerKit",
  description: "Provider-neutral BrokerKit approvals",
  configSchema,
  register: registerBrokerKit,
});

async function resolveCredential(
  api: OpenClawPluginApi,
  source: BrokerConfig,
): Promise<string> {
  const resolved = await resolveConfiguredSecretInputString({
    config: api.config,
    env: process.env,
    value: source.operatorCredential,
    path: `plugins.entries.brokerkit.config.brokers.${source.id}.operatorCredential`,
  });
  if (!resolved.value)
    throw new Error(`operator credential unavailable for ${source.id}`);
  return resolved.value;
}

export async function handleCommand(
  runtime: BrokerRuntime,
  ctx: PluginCommandContext,
) {
  if (!ctx.isAuthorizedSender || !ctx.senderId)
    return { text: "Not authorized." };
  const tokens = (ctx.args ?? "").trim().split(/\s+/).filter(Boolean);
  const command = tokens[0] ?? "pending";
  const handle = tokens[1];
  if (command === "subscribe" || command === "unsubscribe") {
    if (tokens.length !== 1) return { text: "Invalid BrokerKit command." };
    if (!validRouting(ctx.channel, ctx.to, ctx.accountId, ctx.messageThreadId))
      return { text: "This conversation has no stable delivery target." };
    const value = {
      channel: ctx.channel,
      target: ctx.to,
      ...(ctx.accountId ? { accountId: ctx.accountId } : {}),
      ...(ctx.messageThreadId !== undefined
        ? { threadId: String(ctx.messageThreadId) }
        : {}),
    };
    if (command === "subscribe") {
      const subscription = runtime.subscribe(value);
      return {
        text: `Subscribed this conversation (${subscription.id.slice(0, 8)}).`,
      };
    }
    const removed = runtime.unsubscribe(value);
    return {
      text: removed
        ? "Unsubscribed this conversation."
        : "This conversation was not subscribed.",
    };
  }
  if (command === "pending") {
    if (tokens.length > 1) return { text: "Invalid BrokerKit command." };
    const snapshot = runtime.snapshot();
    const lines = snapshot.requests
      .filter((request) => request.status === "pending")
      .map(
        (request) =>
          `${request.handle} · ${request.sourceLabel} · ${request.presentation.title}`,
      );
    return {
      text: lines.length ? lines.join("\n") : "No pending BrokerKit requests.",
    };
  }
  if (!handle || tokens.length !== 2)
    return { text: "A single request handle is required." };
  if (command === "show") {
    const request = runtime
      .snapshot()
      .requests.find((item) => item.handle === handle);
    return { text: request ? formatRequest(request) : "Request not found." };
  }
  if (["approve", "deny", "cancel", "revoke"].includes(command)) {
    const request = runtime
      .snapshot()
      .requests.find((item) => item.handle === handle);
    if (!request) return { text: "Request not found." };
    try {
      const updated = await runtime.decide(
        handle,
        command as Action,
        request.revision,
        ctx.senderId,
      );
      return {
        text: `${capitalize(command)} committed for ${updated.presentation.title}.`,
      };
    } catch (error) {
      return { text: commandError(error) };
    }
  }
  return { text: "Unknown BrokerKit command." };
}

function validRouting(
  channel: string,
  target: string | undefined,
  accountId: string | undefined,
  threadId: string | number | undefined,
): target is string {
  return Boolean(
    channel &&
      channel.length <= 128 &&
      target &&
      target.length <= 4096 &&
      (!accountId || accountId.length <= 512) &&
      (threadId === undefined || String(threadId).length <= 512),
  );
}

function commandError(error: unknown): string {
  const code = pluginErrorCode(error);
  if (code === "revision_stale")
    return "This request changed. Review it again before deciding.";
  if (code === "request_not_found" || code === "request_terminal")
    return "This request is no longer actionable.";
  if (code === "action_not_allowed")
    return "That action is not allowed for this request.";
  if (code === "source_unavailable")
    return "The approval source is unavailable. No decision was reported.";
  return "The decision could not be confirmed. No success was reported.";
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function formatRequest(
  request: ReturnType<BrokerRuntime["snapshot"]>["requests"][number],
): string {
  const facts =
    request.presentation.facts?.map((fact) => `${fact.label}: ${fact.value}`) ??
    [];
  return [
    `${request.sourceLabel}: ${request.presentation.title}`,
    request.presentation.summary ?? "",
    ...facts,
    `Handle: ${request.handle}`,
  ]
    .filter(Boolean)
    .join("\n");
}

export function createHttpHandler(
  runtime: (() => BrokerRuntime) | undefined,
  rootDir: string,
  capability: string | undefined,
) {
  const uiDir = path.join(rootDir, "dist", "ui");
  const rateLimit = createRateLimiter(120, 60_000);
  return async (
    req: import("node:http").IncomingMessage,
    res: import("node:http").ServerResponse,
  ): Promise<boolean> => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname.startsWith("/plugins/brokerkit/api/v1/")) {
      if (!runtime || !capability)
        return json(res, 404, { error: { code: "not_found" } });
      if (!authorized(req.headers.authorization, capability))
        return json(res, 401, { error: { code: "not_authorized" } });
      if (req.headers.origin !== "null")
        return json(res, 403, { error: { code: "not_authorized" } });
      if (url.search)
        return json(res, 400, { error: { code: "invalid_input" } });
      const rateKey = req.socket.remoteAddress ?? "local";
      if (!rateLimit(rateKey))
        return json(res, 429, { error: { code: "rate_limited" } });
      res.setHeader("cache-control", "no-store");
      try {
        if (
          req.method === "GET" &&
          url.pathname === "/plugins/brokerkit/api/v1/snapshot"
        )
          return json(res, 200, runtime().snapshot());
        const detail = url.pathname.match(
          /^\/plugins\/brokerkit\/api\/v1\/requests\/([^/]+)$/,
        );
        if (req.method === "GET" && detail) {
          const handle = decodeHandle(detail[1]);
          const request = runtime()
            .snapshot()
            .requests.find((value) => value.handle === handle);
          return request
            ? json(res, 200, request)
            : json(res, 404, { error: { code: "request_not_found" } });
        }
        const match = url.pathname.match(
          /^\/plugins\/brokerkit\/api\/v1\/requests\/([^/]+)\/(approve|deny|cancel|revoke)$/,
        );
        if (req.method === "POST" && match) {
          if (!isJSON(req.headers["content-type"]))
            throw new Error("invalid_input");
          const body = await readJSON(req);
          const input = parseDecisionInput(body, match[2] as Action);
          const result = await runtime().decide(
            decodeHandle(match[1]),
            match[2] as Action,
            input.expectedRevision,
            "openclaw:control-ui",
            input.options,
          );
          return json(res, 200, result);
        }
      } catch (error) {
        const mapped = mapHttpError(error);
        return json(res, mapped.status, { error: { code: mapped.code } });
      }
      return json(res, 404, { error: { code: "not_found" } });
    }
    if (url.search || !url.pathname.startsWith("/plugins/brokerkit/ui/"))
      return json(res, 404, { error: { code: "not_found" } });
    if (req.method !== "GET")
      return json(res, 405, { error: { code: "invalid_input" } });
    const relative =
      url.pathname.replace(/^\/plugins\/brokerkit\/ui\/?/, "") || "index.html";
    if (relative.includes("..")) return json(res, 404, {});
    let file = path.join(uiDir, relative);
    if (!existsSync(file) || !statSync(file).isFile())
      file = path.join(uiDir, "index.html");
    res.statusCode = 200;
    res.setHeader("content-type", contentType(file));
    res.setHeader(
      "cache-control",
      file.endsWith("index.html")
        ? "no-store"
        : "public, max-age=31536000, immutable",
    );
    res.setHeader(
      "content-security-policy",
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'self'",
    );
    securityHeaders(res);
    createReadStream(file).pipe(res);
    return true;
  };
}

function authorized(header: string | undefined, capability: string): boolean {
  const token = header?.startsWith("Bearer ") ? header.slice(7) : "";
  const left = Buffer.from(token);
  const right = Buffer.from(capability);
  return left.length === right.length && timingSafeEqual(left, right);
}
async function readJSON(
  req: import("node:http").IncomingMessage,
): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const value = Buffer.from(chunk);
    size += value.length;
    if (size > 16_384) throw new Error("invalid_input");
    chunks.push(value);
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.concat(chunks),
    );
    assertUniqueObjectKeys(text);
    const value = JSON.parse(text) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new Error("invalid_input");
    return value as Record<string, unknown>;
  } catch {
    throw new Error("invalid_input");
  }
}

function assertUniqueObjectKeys(text: string): void {
  let index = 0;
  const whitespace = () => {
    while (/\s/u.test(text[index] ?? "")) index += 1;
  };
  const string = (): string => {
    const start = index;
    if (text[index] !== '"') throw new Error("invalid_input");
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") {
        index += 2;
        continue;
      }
      if (text[index] === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index)) as string;
      }
      index += 1;
    }
    throw new Error("invalid_input");
  };
  const value = (depth: number): void => {
    if (depth > 32) throw new Error("invalid_input");
    whitespace();
    if (text[index] === '"') {
      string();
      return;
    }
    if (text[index] === "{") {
      index += 1;
      whitespace();
      const keys = new Set<string>();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      for (;;) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new Error("invalid_input");
        keys.add(key);
        whitespace();
        if (text[index] !== ":") throw new Error("invalid_input");
        index += 1;
        value(depth + 1);
        whitespace();
        if (text[index] === "}") {
          index += 1;
          return;
        }
        if (text[index] !== ",") throw new Error("invalid_input");
        index += 1;
      }
    }
    if (text[index] === "[") {
      index += 1;
      whitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      for (;;) {
        value(depth + 1);
        whitespace();
        if (text[index] === "]") {
          index += 1;
          return;
        }
        if (text[index] !== ",") throw new Error("invalid_input");
        index += 1;
      }
    }
    const start = index;
    while (index < text.length && !/[\s,}\]]/u.test(text[index] ?? ""))
      index += 1;
    if (start === index) throw new Error("invalid_input");
    JSON.parse(text.slice(start, index));
  };
  value(0);
  whitespace();
  if (index !== text.length) throw new Error("invalid_input");
}
function json(
  res: import("node:http").ServerResponse,
  status: number,
  value: unknown,
): true {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.setHeader("cache-control", "no-store");
  res.setHeader("content-security-policy", "default-src 'none'");
  securityHeaders(res);
  res.end(JSON.stringify(value));
  return true;
}

function securityHeaders(res: import("node:http").ServerResponse): void {
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("referrer-policy", "no-referrer");
  res.setHeader("cross-origin-resource-policy", "same-origin");
}

function decodeHandle(value: string | undefined): string {
  if (!value || value.length > 256) throw new Error("invalid_input");
  const decoded = decodeURIComponent(value);
  if (!/^[A-Za-z0-9_-]{22,256}$/u.test(decoded))
    throw new Error("invalid_input");
  return decoded;
}

function isJSON(value: string | undefined): boolean {
  return Boolean(value && /^application\/json(?:\s*;|$)/iu.test(value));
}

function mapHttpError(error: unknown): { code: string; status: number } {
  const code = pluginErrorCode(error);
  if (code === "invalid_input") return { code, status: 400 };
  if (code === "request_not_found") return { code, status: 404 };
  if (code === "revision_stale" || code === "request_terminal")
    return { code, status: 409 };
  if (code === "action_not_allowed") return { code, status: 422 };
  if (code === "source_unavailable") return { code, status: 503 };
  return { code: "internal_error", status: 500 };
}

function pluginErrorCode(error: unknown): string {
  const code =
    error instanceof BrokerError
      ? error.code
      : error instanceof Error
        ? error.message
        : "internal_error";
  if (code === "revision_conflict") return "revision_stale";
  if (code === "not_found") return "request_not_found";
  if (code === "invalid_transition" || code === "constraint_exceeded")
    return "action_not_allowed";
  return code;
}

function parseDecisionInput(
  body: Record<string, unknown>,
  action: Action,
): { expectedRevision: number; options: DecisionOptions } {
  if (
    Object.keys(body).some(
      (key) =>
        key !== "expectedRevision" && key !== "reason" && key !== "constraints",
    ) ||
    !Number.isSafeInteger(body.expectedRevision) ||
    (body.expectedRevision as number) <= 0 ||
    (body.reason !== undefined &&
      (typeof body.reason !== "string" || body.reason.length > 4096))
  )
    throw new Error("invalid_input");
  const options: DecisionOptions = {};
  if (typeof body.reason === "string" && body.reason.trim())
    options.reason = body.reason.trim();
  if (body.constraints !== undefined) {
    if (action !== "approve" || !record(body.constraints))
      throw new Error("invalid_input");
    const constraints = body.constraints;
    if (
      Object.keys(constraints).some(
        (key) => key !== "durationSeconds" && key !== "maxUses",
      ) ||
      !positiveSafeInteger(constraints.durationSeconds) ||
      !positiveSafeInteger(constraints.maxUses)
    )
      throw new Error("invalid_input");
    options.constraints = {
      duration_seconds: constraints.durationSeconds,
      max_uses: constraints.maxUses,
    };
  }
  return { expectedRevision: body.expectedRevision as number, options };
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function positiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function createRateLimiter(limit: number, windowMs: number) {
  const entries = new Map<string, { count: number; resetAt: number }>();
  return (key: string): boolean => {
    const now = Date.now();
    const current = entries.get(key);
    if (!current || current.resetAt <= now) {
      entries.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }
    current.count += 1;
    return current.count <= limit;
  };
}
function contentType(file: string): string {
  if (file.endsWith(".js")) return "text/javascript";
  if (file.endsWith(".css")) return "text/css";
  if (file.endsWith(".svg")) return "image/svg+xml";
  return "text/html; charset=utf-8";
}
