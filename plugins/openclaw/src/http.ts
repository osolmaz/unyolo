import { timingSafeEqual } from "node:crypto";
import { createReadStream, existsSync, statSync } from "node:fs";
import path from "node:path";
import { pluginErrorCode } from "./errors.js";
import type { BrokerRuntime, DecisionOptions } from "./runtime.js";
import type { Action } from "./types.js";

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
    if (url.pathname.startsWith("/plugins/brokerkit/api/v1/"))
      return handleApi(req, res, url, runtime, capability, rateLimit);
    return serveUi(req, res, url, uiDir);
  };
}

async function handleApi(
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
  url: URL,
  runtime: (() => BrokerRuntime) | undefined,
  capability: string | undefined,
  rateLimit: (key: string) => boolean,
): Promise<boolean> {
  if (!runtime || !capability)
    return json(res, 404, { error: { code: "not_found" } });
  if (!authorized(req.headers.authorization, capability))
    return json(res, 401, { error: { code: "not_authorized" } });
  if (req.headers.origin !== "null")
    return json(res, 403, { error: { code: "not_authorized" } });
  if (!rateLimit(req.socket.remoteAddress ?? "local"))
    return json(res, 429, { error: { code: "rate_limited" } });
  try {
    if (
      req.method === "GET" &&
      url.pathname === "/plugins/brokerkit/api/v1/events"
    ) {
      const input = parseEventQuery(url);
      const controller = new AbortController();
      const close = () => controller.abort();
      res.once("close", close);
      try {
        return json(
          res,
          200,
          await runtime().waitForSnapshot(
            input.cursor,
            input.waitSeconds,
            controller.signal,
          ),
        );
      } finally {
        res.off("close", close);
      }
    }
    if (url.search) return json(res, 400, { error: { code: "invalid_input" } });
    if (
      req.method === "GET" &&
      url.pathname === "/plugins/brokerkit/api/v1/snapshot"
    )
      return json(res, 200, runtime().snapshot());
    if (
      req.method === "GET" &&
      url.pathname === "/plugins/brokerkit/api/v1/summary"
    ) {
      const snapshot = runtime().snapshot();
      return json(res, 200, {
        api_version: snapshot.api_version,
        cursor: snapshot.cursor,
        pending: snapshot.requests.filter(
          (request) => request.request.status === "pending",
        ).length,
        healthy: snapshot.sources.every((source) => source.healthy),
      });
    }
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
    const decision = url.pathname.match(
      /^\/plugins\/brokerkit\/api\/v1\/requests\/([^/]+)\/(approve|deny|revoke)$/,
    );
    if (req.method === "POST" && decision) {
      if (!isJSON(req.headers["content-type"]))
        throw new Error("invalid_input");
      const input = parseDecisionInput(
        await readJSON(req),
        decision[2] as Action,
      );
      const result = await runtime().decide(
        decodeHandle(decision[1]),
        decision[2] as Action,
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

function serveUi(
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
  url: URL,
  uiDir: string,
): boolean {
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
  if (!file.endsWith("index.html")) {
    res.setHeader("cross-origin-resource-policy", "cross-origin");
  }
  createReadStream(file).pipe(res);
  return true;
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
    if (!record(value)) throw new Error("invalid_input");
    return value;
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
    if (text[index] === '"') return void string();
    if (text[index] === "{") {
      index += 1;
      whitespace();
      const keys = new Set<string>();
      if (text[index] === "}") return void (index += 1);
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
        if (text[index] === "}") return void (index += 1);
        if (text[index] !== ",") throw new Error("invalid_input");
        index += 1;
      }
    }
    if (text[index] === "[") {
      index += 1;
      whitespace();
      if (text[index] === "]") return void (index += 1);
      for (;;) {
        value(depth + 1);
        whitespace();
        if (text[index] === "]") return void (index += 1);
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
  if (code === "cursor_expired") return { code, status: 410 };
  if (code === "source_unavailable") return { code, status: 503 };
  return { code: "internal_error", status: 500 };
}

function parseEventQuery(url: URL): {
  cursor: string;
  waitSeconds: number;
} {
  if (
    [...url.searchParams.keys()].some(
      (key) => !["cursor", "wait_seconds"].includes(key),
    )
  )
    throw new Error("invalid_input");
  const cursor = url.searchParams.get("cursor") ?? "";
  const wait = url.searchParams.get("wait_seconds") ?? "25";
  if (
    cursor.length < 1 ||
    cursor.length > 128 ||
    !/^[A-Za-z0-9_.-]+$/u.test(cursor) ||
    !/^(?:[1-9]|1[0-9]|2[0-5])$/u.test(wait)
  )
    throw new Error("invalid_input");
  return { cursor, waitSeconds: Number(wait) };
}

function parseDecisionInput(
  body: Record<string, unknown>,
  action: Action,
): { expectedRevision: number; options: DecisionOptions } {
  if (
    Object.keys(body).some(
      (key) => key !== "expectedRevision" && key !== "constraints",
    ) ||
    !positiveSafeInteger(body.expectedRevision)
  )
    throw new Error("invalid_input");
  const options: DecisionOptions = {};
  if (body.constraints !== undefined) {
    if (action !== "approve" || !record(body.constraints))
      throw new Error("invalid_input");
    const constraints = body.constraints;
    if (
      Object.keys(constraints).some(
        (key) => key !== "durationSeconds" && key !== "maxUses",
      ) ||
      !positiveSafeInteger(constraints.durationSeconds) ||
      !(
        constraints.maxUses === null || positiveSafeInteger(constraints.maxUses)
      )
    )
      throw new Error("invalid_input");
    options.constraints = {
      duration_seconds: constraints.durationSeconds,
      max_uses: constraints.maxUses,
    };
  }
  return { expectedRevision: body.expectedRevision, options };
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
