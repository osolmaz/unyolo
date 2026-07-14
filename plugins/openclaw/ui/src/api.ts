import {
  parseUIRequest,
  parseUISnapshot,
  parseUISnapshotEvent,
} from "../../src/operator-v1.js";
import type {
  Action,
  SafeRequest,
  Snapshot,
  SnapshotEvent,
} from "../../src/types.js";
import {
  BROWSER_SESSION_HEADER,
  validBrowserSession,
} from "../../src/browser-session.js";

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
export type UiBootstrap = DirectBootstrap | DelegatedBootstrap;
export type UiDecisionOptions = {
  constraints?: { durationSeconds: number; maxUses: number | null };
};

type DelegatedSession = {
  token: string;
  expiresAtMs: number;
  access: "read" | "decide";
  renewalTransport: "direct" | "parent";
};

export const DELEGATED_SESSION_REQUEST =
  "brokerkit.delegated-web.session.request";
export const DELEGATED_SESSION_RESPONSE =
  "brokerkit.delegated-web.session.response";
export const DELEGATED_SESSION_META = "brokerkit-delegated-session";
export const DELEGATED_TOP_LEVEL_META = "brokerkit-delegated-top-level";
export const DELEGATED_OPEN_REQUEST = "brokerkit.delegated-web.open";

export class BrokerKitUiApi {
  private delegatedSession?: DelegatedSession;
  private delegatedRefresh: Promise<DelegatedSession> | undefined;

  constructor(private readonly bootstrap: UiBootstrap) {}

  snapshot(signal?: AbortSignal): Promise<Snapshot> {
    return this.request("/snapshot", signal ? { signal } : {}).then(
      parseUISnapshot,
    );
  }

  events(cursor: string, signal: AbortSignal): Promise<SnapshotEvent> {
    return this.request(
      `/events?cursor=${encodeURIComponent(cursor)}&wait_seconds=25`,
      { signal },
    ).then(parseUISnapshotEvent);
  }

  canDecide(): boolean {
    return (
      this.bootstrap.mode === "direct" ||
      this.delegatedSession?.access === "decide"
    );
  }

  detail(handle: string): Promise<SafeRequest> {
    return this.request(`/requests/${encodeURIComponent(handle)}`).then(
      parseUIRequest,
    );
  }

  decide(
    request: SafeRequest,
    action: Action,
    options: UiDecisionOptions = {},
  ): Promise<SafeRequest> {
    return this.request(
      `/requests/${encodeURIComponent(request.handle)}/${action}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          expectedRevision: request.request.revision,
          ...options,
        }),
      },
    ).then(parseUIRequest);
  }

  private async request(
    path: string,
    init: RequestInit = {},
  ): Promise<unknown> {
    const auth = await this.authorization();
    const basePath =
      this.bootstrap.mode === "direct"
        ? "/plugins/brokerkit/api/v1"
        : this.bootstrap.basePath;
    const response = await fetch(`${basePath}${path}`, {
      ...init,
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: browserSessionHeaders(init.headers, auth.token),
    });
    if (!response.ok) throw await safeError(response);
    return JSON.parse(
      await boundedResponseText(response, 2_000_000),
    ) as unknown;
  }

  private async authorization(): Promise<DelegatedSession> {
    if (this.bootstrap.mode === "direct") {
      return {
        token: this.bootstrap.capability,
        expiresAtMs: Number.POSITIVE_INFINITY,
        access: "decide",
        renewalTransport: "direct",
      };
    }
    if (
      this.delegatedSession &&
      this.delegatedSession.expiresAtMs > Date.now() + 30_000
    ) {
      return this.delegatedSession;
    }
    if (this.delegatedRefresh) return this.delegatedRefresh;
    this.delegatedRefresh = this.refreshDelegatedAuthorization();
    try {
      return await this.delegatedRefresh;
    } finally {
      this.delegatedRefresh = undefined;
    }
  }

  private async refreshDelegatedAuthorization(): Promise<DelegatedSession> {
    if (this.bootstrap.mode !== "delegated-web")
      throw new Error("Delegated approval session is invalid");
    const value = await delegatedSessionPayload(
      this.bootstrap.basePath,
      this.delegatedSession,
    );
    const expiresAtMs = Date.parse(
      typeof value.expires_at === "string" ? value.expires_at : "",
    );
    const keys = Object.keys(value).sort().join(",");
    if (
      keys !== "access,api_version,expires_at,renewal_transport,token" ||
      value.api_version !== "brokerkit.io/delegated-web/v1" ||
      typeof value.token !== "string" ||
      !validBrowserSession(value.token) ||
      (value.access !== "read" && value.access !== "decide") ||
      (value.renewal_transport !== "direct" &&
        value.renewal_transport !== "parent") ||
      !Number.isFinite(expiresAtMs) ||
      expiresAtMs <= Date.now() ||
      expiresAtMs > Date.now() + 5 * 60_000
    ) {
      throw new Error("Delegated approval session is invalid");
    }
    this.delegatedSession = {
      token: value.token,
      expiresAtMs,
      access: value.access,
      renewalTransport: value.renewal_transport,
    };
    return this.delegatedSession;
  }
}

async function delegatedSessionPayload(
  basePath: string,
  current?: DelegatedSession,
): Promise<Record<string, unknown>> {
  const embedded = embeddedDelegatedSession();
  if (embedded) return embedded;
  if (current && (current.renewalTransport === "direct" || !framed())) {
    const response = await fetch(`${basePath}/session`, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: browserSessionHeaders(undefined, current.token),
    });
    if (!response.ok) throw await safeError(response);
    return JSON.parse(await boundedResponseText(response, 16_384)) as Record<
      string,
      unknown
    >;
  }
  if (current) return delegatedSessionFromParent();
  if (!framed()) throw new Error("Approval authorization expired");
  return delegatedSessionFromParent();
}

export function browserSessionHeaders(
  input: HeadersInit | undefined,
  session: string,
): Headers {
  if (!validBrowserSession(session))
    throw new Error("Approval authorization expired");
  const headers = new Headers(input);
  headers.delete("authorization");
  headers.delete(BROWSER_SESSION_HEADER);
  headers.set(BROWSER_SESSION_HEADER, session);
  return headers;
}

export function takeDelegatedTopLevelLauncher(): boolean {
  if (typeof document === "undefined") return false;
  const element = document.querySelector(
    `meta[name="${DELEGATED_TOP_LEVEL_META}"]`,
  );
  if (!element) return false;
  element.remove();
  return true;
}

export function requestDelegatedTopLevelOpen(): void {
  if (typeof window === "undefined" || window.parent === window) return;
  window.parent.postMessage(
    { type: DELEGATED_OPEN_REQUEST, version: 1, nonce: randomNonce() },
    "*",
  );
}

function embeddedDelegatedSession(): Record<string, unknown> | undefined {
  if (typeof document === "undefined") return undefined;
  const element = document.querySelector(
    `meta[name="${DELEGATED_SESSION_META}"]`,
  );
  if (!element) return undefined;
  const encoded = element.getAttribute("content") ?? "";
  element.remove();
  if (!encoded || encoded.length > 8192) return {};
  try {
    const normalized = encoded.replace(/-/gu, "+").replace(/_/gu, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const value = JSON.parse(atob(padded)) as unknown;
    return record(value) ? value : {};
  } catch {
    return {};
  }
}

function framed(): boolean {
  return typeof window !== "undefined" && window.parent !== window;
}

function delegatedSessionFromParent(): Promise<Record<string, unknown>> {
  const nonce = randomNonce();
  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      cleanup();
      reject(new Error("Approval authorization expired"));
    }, 10_000);
    const receive = (event: MessageEvent) => {
      if (event.source !== window.parent || !record(event.data)) return;
      if (
        event.data.type !== DELEGATED_SESSION_RESPONSE ||
        event.data.nonce !== nonce
      )
        return;
      cleanup();
      if (!record(event.data.session)) {
        reject(new Error("Approval authorization expired"));
        return;
      }
      resolve(event.data.session);
    };
    const cleanup = () => {
      window.clearTimeout(timeout);
      window.removeEventListener("message", receive);
    };
    window.addEventListener("message", receive);
    window.parent.postMessage(
      { type: DELEGATED_SESSION_REQUEST, version: 1, nonce },
      "*",
    );
  });
}

function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

export function parseUiBootstrap(hash: string): UiBootstrap {
  if (!hash || hash.length > 2048)
    throw new Error("Approval UI bootstrap is invalid");
  let value: unknown;
  try {
    const normalized = hash.replace(/-/gu, "+").replace(/_/gu, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    value = JSON.parse(atob(padded));
  } catch {
    throw new Error("Approval UI bootstrap is invalid");
  }
  if (!record(value) || value.version !== 1 || typeof value.mode !== "string") {
    throw new Error("Approval UI bootstrap is invalid");
  }
  const keys = Object.keys(value).sort().join(",");
  if (
    value.mode === "direct" &&
    keys === "capability,mode,version" &&
    typeof value.capability === "string" &&
    validBrowserSession(value.capability) &&
    value.capability.length >= 32 &&
    value.capability.length <= 256
  ) {
    return { version: 1, mode: "direct", capability: value.capability };
  }
  if (
    value.mode === "delegated-web" &&
    keys === "basePath,mode,version" &&
    typeof value.basePath === "string" &&
    validBasePath(value.basePath)
  ) {
    return { version: 1, mode: "delegated-web", basePath: value.basePath };
  }
  throw new Error("Approval UI bootstrap is invalid");
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function validBasePath(value: string): boolean {
  return (
    value.length >= 2 &&
    value.length <= 256 &&
    value.startsWith("/") &&
    !value.startsWith("//") &&
    !value.endsWith("/") &&
    !/[?#\\]/u.test(value) &&
    !hasControlCharacter(value) &&
    !value.includes("..") &&
    value
      .split("/")
      .every((part, index) => index === 0 || /^[A-Za-z0-9._~-]+$/u.test(part))
  );
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 32 || code === 127;
  });
}

async function safeError(
  response: Response,
): Promise<Error & { code?: string }> {
  try {
    const value = JSON.parse(
      await boundedResponseText(response, 64_000),
    ) as Record<string, unknown>;
    const error = record(value.error) ? value.error : undefined;
    if (error && typeof error.code === "string")
      return Object.assign(new Error(messageForCode(error.code)), {
        code: error.code,
      });
  } catch {
    // Keep the public error independent from upstream response details.
  }
  return new Error(
    response.status === 401 || response.status === 403
      ? "Approval authorization expired"
      : "Approvals are unavailable",
  );
}

function messageForCode(code: string): string {
  if (code === "revision_stale")
    return "This request changed; refresh and review it again";
  if (code === "request_terminal") return "This request is already settled";
  if (code === "not_authorized") return "Approval authorization expired";
  if (code === "source_unavailable")
    return "The approval source is unavailable";
  if (code === "cursor_expired") return "Approval updates expired";
  return "The approval request could not be completed";
}

async function boundedResponseText(
  response: Response,
  limit: number,
): Promise<string> {
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
      throw new Error("Approvals are unavailable");
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
