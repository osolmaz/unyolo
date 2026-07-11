import { BrokerError } from "./client.js";

export function pluginErrorCode(error: unknown): string {
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
