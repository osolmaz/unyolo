import { describe, expect, it, vi } from "vitest";
import { handleCommand } from "./commands.js";

const request = {
  handle: "opaque-handle",
  source_id: "hf",
  source_label: "Hugging Face",
  request: {
    revision: 3,
    status: "pending",
    presentation: { title: "Protected write", facts: [] },
  },
};

describe("BrokerKit command", () => {
  it("requires authenticated server-attributed actors", async () => {
    const runtime = fakeRuntime();
    expect(
      await handleCommand(
        runtime as never,
        context({ isAuthorizedSender: false }),
      ),
    ).toEqual({ text: "Not authorized." });
    expect(
      await handleCommand(runtime as never, context({ senderId: undefined })),
    ).toEqual({ text: "Not authorized." });
    expect(runtime.decide).not.toHaveBeenCalled();
  });

  it("captures only bounded generic routing coordinates", async () => {
    const runtime = fakeRuntime();
    expect(
      await handleCommand(
        runtime as never,
        context({
          args: "subscribe",
          channel: "adapter-one",
          to: "room",
          accountId: "account",
          messageThreadId: 42,
        }),
      ),
    ).toEqual({ text: "Subscribed this conversation (subscrip)." });
    expect(runtime.subscribe).toHaveBeenCalledWith({
      channel: "adapter-one",
      target: "room",
      accountId: "account",
      threadId: "42",
    });
    expect(
      await handleCommand(
        runtime as never,
        context({ args: "subscribe extra" }),
      ),
    ).toEqual({ text: "Invalid BrokerKit command." });
    expect(
      await handleCommand(
        runtime as never,
        context({ args: "subscribe", to: "x".repeat(4097) }),
      ),
    ).toEqual({ text: "This conversation has no stable delivery target." });
  });

  it("parses exact commands and attributes decisions to the sender", async () => {
    const runtime = fakeRuntime();
    expect(
      await handleCommand(
        runtime as never,
        context({ args: "approve opaque-handle" }),
      ),
    ).toEqual({ text: "Approve committed for Protected write." });
    expect(runtime.decide).toHaveBeenCalledWith(
      "opaque-handle",
      "approve",
      3,
      "operator:onur",
    );
    expect(
      await handleCommand(
        runtime as never,
        context({ args: "approve opaque-handle extra" }),
      ),
    ).toEqual({ text: "A single request handle is required." });
    expect(
      await handleCommand(runtime as never, context({ args: "unknown value" })),
    ).toEqual({ text: "Unknown BrokerKit command." });
  });

  it("never translates a failed decision into success", async () => {
    const runtime = fakeRuntime();
    runtime.decide.mockRejectedValueOnce(new Error("revision_stale"));
    expect(
      await handleCommand(
        runtime as never,
        context({ args: "deny opaque-handle" }),
      ),
    ).toEqual({
      text: "This request changed. Review it again before deciding.",
    });
  });
});

function fakeRuntime() {
  return {
    snapshot: vi.fn(() => ({ sources: [], requests: [request] })),
    subscribe: vi.fn(() => ({ id: "subscription-id" })),
    unsubscribe: vi.fn(() => true),
    decide: vi.fn(async () => request),
  };
}

function context(overrides: Record<string, unknown> = {}) {
  return {
    args: "",
    isAuthorizedSender: true,
    senderId: "operator:onur",
    channel: "adapter-one",
    to: "room",
    ...overrides,
  } as never;
}
