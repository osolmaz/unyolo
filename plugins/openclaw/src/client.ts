import type {
  Action,
  BrokerEvent,
  BrokerRequest,
  Decision,
  RequestPage,
} from "./types.js";

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
    const value = await this.json<{ api_version: string }>(
      "/.well-known/brokerkit-operator",
    );
    if (value.api_version !== "brokerkit.io/operator/v1")
      throw new Error(`unsupported BrokerKit API ${value.api_version}`);
  }
  async health(): Promise<void> {
    await this.json<{ status: string }>("/healthz", {}, false);
  }
  list(cursor?: string): Promise<RequestPage> {
    return this.json(
      `/api/operator/v1/requests?status=pending&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
    );
  }
  get(id: string): Promise<BrokerRequest> {
    return this.json(`/api/operator/v1/requests/${encodeURIComponent(id)}`);
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
    );
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
          .find((line) => line.startsWith("data:"))
          ?.slice(5)
          .trim();
        if (!data) continue;
        const event = JSON.parse(data) as BrokerEvent;
        if (!id || event.cursor !== id)
          throw new Error("BrokerKit event cursor mismatch");
        yield event;
      }
    }
  }
  private async json<T>(
    path: string,
    init: RequestInit = {},
    authenticated = true,
  ): Promise<T> {
    const response = await this.request(path, init, authenticated);
    if (!response.ok) throw await this.error(response);
    const text = await response.text();
    if (text.length > 2_000_000)
      throw new Error("BrokerKit response is too large");
    return JSON.parse(text) as T;
  }
  private async request(
    path: string,
    init: RequestInit = {},
    authenticated = true,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    const signal = init.signal ?? controller.signal;
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
      const value = (await response.json()) as {
        error?: { code?: string; message?: string };
      };
      return new BrokerError(
        value.error?.code ?? "internal_error",
        value.error?.message ?? "BrokerKit request failed",
        response.status,
      );
    } catch {
      return new BrokerError(
        "internal_error",
        "BrokerKit request failed",
        response.status,
      );
    }
  }
}
