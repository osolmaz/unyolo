import type { Action, SafeRequest, Snapshot } from "../../src/types.js";

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

type DelegatedSession = {
  token: string;
  expiresAtMs: number;
};

export class BrokerKitUiApi {
  private delegatedSession?: DelegatedSession;

  constructor(private readonly bootstrap: UiBootstrap) {}

  snapshot(): Promise<Snapshot> {
    return this.request<Snapshot>("/snapshot");
  }

  detail(handle: string): Promise<SafeRequest> {
    return this.request<SafeRequest>(`/requests/${encodeURIComponent(handle)}`);
  }

  decide(request: SafeRequest, action: Action): Promise<SafeRequest> {
    return this.request<SafeRequest>(
      `/requests/${encodeURIComponent(request.handle)}/${action}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ expectedRevision: request.revision }),
      },
    );
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const auth = await this.authorization();
    const basePath =
      this.bootstrap.mode === "direct"
        ? "/plugins/brokerkit/api/v1"
        : this.bootstrap.basePath;
    const response = await fetch(`${basePath}${path}`, {
      ...init,
      credentials: "omit",
      cache: "no-store",
      headers: {
        ...init.headers,
        authorization: `Bearer ${auth}`,
      },
    });
    if (!response.ok) throw new Error(await safeError(response));
    return (await response.json()) as T;
  }

  private async authorization(): Promise<string> {
    if (this.bootstrap.mode === "direct") return this.bootstrap.capability;
    if (
      this.delegatedSession &&
      this.delegatedSession.expiresAtMs > Date.now() + 30_000
    ) {
      return this.delegatedSession.token;
    }
    const response = await fetch(`${this.bootstrap.basePath}/session`, {
      credentials: "include",
      cache: "no-store",
      headers: { accept: "application/json" },
    });
    if (!response.ok) throw new Error(await safeError(response));
    const value = (await response.json()) as Record<string, unknown>;
    const expiresAtMs = Date.parse(
      typeof value.expires_at === "string" ? value.expires_at : "",
    );
    if (
      value.api_version !== "brokerkit.io/delegated-web/v1" ||
      typeof value.decision_token !== "string" ||
      value.decision_token.length < 32 ||
      value.decision_token.length > 4096 ||
      !Number.isFinite(expiresAtMs) ||
      expiresAtMs <= Date.now() ||
      expiresAtMs > Date.now() + 5 * 60_000
    ) {
      throw new Error("Delegated approval session is invalid");
    }
    this.delegatedSession = {
      token: value.decision_token,
      expiresAtMs,
    };
    return this.delegatedSession.token;
  }
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

async function safeError(response: Response): Promise<string> {
  try {
    const value = (await response.json()) as Record<string, unknown>;
    const error = record(value.error) ? value.error : undefined;
    if (error && typeof error.code === "string")
      return messageForCode(error.code);
  } catch {
    // Keep the public error independent from upstream response details.
  }
  return response.status === 401 || response.status === 403
    ? "Approval authorization expired"
    : "Approvals are unavailable";
}

function messageForCode(code: string): string {
  if (code === "revision_stale")
    return "This request changed; refresh and review it again";
  if (code === "request_terminal") return "This request is already settled";
  if (code === "not_authorized") return "Approval authorization expired";
  if (code === "source_unavailable")
    return "The approval source is unavailable";
  return "The approval request could not be completed";
}
