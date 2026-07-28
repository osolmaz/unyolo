import type {
  Action,
  BrokerEvent,
  BrokerRequest,
  Decision,
  RequestPage,
} from "./types.js";
import {
  parseBrokerEvent,
  parseDescriptor,
  parseErrorEnvelope,
  parseHealth,
  parseRequest,
  parseRequestPage,
  OPERATOR_V1_SCHEMA_SHA256,
} from "./operator-v1.js";

const MAX_JSON_BYTES = 2_000_000;
const MAX_SSE_FRAME_BYTES = 256_000;

export class BrokerError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export class BrokerClient {
  constructor(
    private readonly endpoint: string,
    private readonly credential: () => Promise<string>,
    private readonly timeoutMs: number,
  ) {}
  async discover(): Promise<void> {
    const value = parseDescriptor(
      await this.json("/.well-known/unyolo-operator"),
    );
    if (value.api_version !== "unyolo.io/operator/v1")
      throw new Error(`unsupported unYOLO API ${value.api_version}`);
    if (value.contract_digest !== OPERATOR_V1_SCHEMA_SHA256)
      throw new Error("unsupported unYOLO operator contract");
  }
  async health(): Promise<void> {
    const health = parseHealth(await this.json("/healthz", {}, false));
    if (health.contract_digest !== OPERATOR_V1_SCHEMA_SHA256)
      throw new Error("unsupported unYOLO operator contract");
  }
  async list(
    status: "pending" | "active" = "pending",
    cursor?: string,
  ): Promise<RequestPage> {
    return parseRequestPage(
      await this.json(
        `/api/operator/v1/requests?status=${status}&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
      ),
    );
  }
  async get(id: string): Promise<BrokerRequest> {
    return parseRequest(
      await this.json(`/api/operator/v1/requests/${encodeURIComponent(id)}`),
    );
  }
  decide(
    id: string,
    action: Action,
    decision: Decision,
  ): Promise<BrokerRequest> {
    return this.json(
      `/api/operator/v1/requests/${encodeURIComponent(id)}/${action}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(decision),
      },
    ).then(parseRequest);
  }
  async *events(
    cursor: string | undefined,
    signal: AbortSignal,
  ): AsyncGenerator<BrokerEvent> {
    const response = await this.request(
      `/api/operator/v1/events${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`,
      { headers: { accept: "text/event-stream" }, signal },
    );
    if (!response.ok || !response.body) throw await this.error(response);
    const reader = response.body
      .pipeThrough(new TextDecoderStream())
      .getReader();
    let buffer = "";
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) return;
      buffer += chunk.value;
      if (Buffer.byteLength(buffer, "utf8") > MAX_SSE_FRAME_BYTES)
        throw new Error("unYOLO event frame is too large");
      buffer = buffer.replaceAll("\r\n", "\n");
      for (;;) {
        const boundary = buffer.indexOf("\n\n");
        if (boundary < 0) break;
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const id = frame
          .split("\n")
          .find((line) => line.startsWith("id:"))
          ?.slice(3)
          .trim();
        const data = frame
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trimStart())
          .join("\n");
        if (!data) continue;
        const event = parseBrokerEvent(JSON.parse(data));
        if (!id || event.cursor !== id)
          throw new Error("unYOLO event cursor mismatch");
        yield event;
      }
    }
  }
  private async json(
    path: string,
    init: RequestInit = {},
    authenticated = true,
  ): Promise<unknown> {
    const response = await this.request(path, init, authenticated);
    if (!response.ok) throw await this.error(response);
    requireJSON(response);
    return JSON.parse(await boundedText(response, MAX_JSON_BYTES));
  }
  private async request(
    path: string,
    init: RequestInit = {},
    authenticated = true,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    const signal = init.signal
      ? AbortSignal.any([init.signal, controller.signal])
      : controller.signal;
    try {
      const headers = new Headers(init.headers);
      if (authenticated)
        headers.set("authorization", `Bearer ${await this.credential()}`);
      return await fetch(new URL(path, this.endpoint), {
        ...init,
        headers,
        signal,
        redirect: "error",
      });
    } finally {
      clearTimeout(timeout);
    }
  }
  private async error(response: Response): Promise<BrokerError> {
    try {
      requireJSON(response);
      const value = parseErrorEnvelope(
        JSON.parse(await boundedText(response, 64_000)),
      );
      return new BrokerError(
        value?.error.code ?? "internal_error",
        value?.error.message ?? "unYOLO request failed",
        response.status,
      );
    } catch {
      return new BrokerError(
        "internal_error",
        "unYOLO request failed",
        response.status,
      );
    }
  }
}

function requireJSON(response: Response): void {
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|$)/iu.test(contentType))
    throw new Error("unYOLO returned an invalid content type");
}

async function boundedText(response: Response, limit: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new Error("unYOLO response is too large");
    }
    chunks.push(value);
  }
  const joined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(joined);
}
