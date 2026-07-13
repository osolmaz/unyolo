import type { PluginCommandContext } from "openclaw/plugin-sdk/plugin-entry";
import type { BrokerRuntime } from "./runtime.js";
import type { Action } from "./types.js";
import { pluginErrorCode } from "./errors.js";

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
    const lines = runtime
      .snapshot()
      .requests.filter((request) => request.request.status === "pending")
      .map(
        (request) =>
          `${request.handle} · ${request.source_label} · ${request.request.presentation.title}`,
      );
    return {
      text: lines.length ? lines.join("\n") : "No pending BrokerKit requests.",
    };
  }
  if (!handle || tokens.length !== 2)
    return { text: "A single request handle is required." };
  const request = runtime
    .snapshot()
    .requests.find((item) => item.handle === handle);
  if (command === "show")
    return { text: request ? formatRequest(request) : "Request not found." };
  if (["approve", "deny", "revoke"].includes(command)) {
    if (!request) return { text: "Request not found." };
    try {
      const updated = await runtime.decide(
        handle,
        command as Action,
        request.request.revision,
        ctx.senderId,
      );
      return {
        text: `${capitalize(command)} committed for ${updated.request.presentation.title}.`,
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
    request.request.presentation.facts?.map(
      (fact) => `${fact.label}: ${fact.value}`,
    ) ?? [];
  return [
    `${request.source_label}: ${request.request.presentation.title}`,
    request.request.presentation.summary ?? "",
    ...facts,
    `Handle: ${request.handle}`,
  ]
    .filter(Boolean)
    .join("\n");
}
