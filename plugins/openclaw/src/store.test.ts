import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { StateStore } from "./store.js";

describe("StateStore", () => {
  it("persists cursors, handles, subscriptions, and deduplicated delivery", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "brokerkit-state-"));
    let store = new StateStore(directory);
    store.setCursor("hf", "cursor-1");
    const handle = store.handle("hf", "request-1", 1, Date.now() + 60_000);
    expect(store.handle("hf", "request-1", 1, Date.now() + 60_000)).toBe(
      handle,
    );
    const subscription = store.subscribe({ channel: "test", target: "room" });
    store.enqueue(handle);
    store.enqueue(handle);
    expect(store.due(10)).toHaveLength(1);
    store.markDelivered(subscription.id, handle);
    expect(store.due(10)).toHaveLength(0);
    store.close();
    store = new StateStore(directory);
    expect(store.cursor("hf")).toBe("cursor-1");
    expect(store.resolve(handle)?.requestId).toBe("request-1");
    expect(
      lstatSync(path.join(directory, "plugins", "brokerkit", "state.sqlite"))
        .mode & 0o777,
    ).toBe(0o600);
    store.close();
  });
  it("rejects a symlink database", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "brokerkit-state-"));
    const target = path.join(directory, "target");
    const database = path.join(
      directory,
      "plugins",
      "brokerkit",
      "state.sqlite",
    );
    mkdirSync(path.dirname(database), { recursive: true });
    writeFileSync(target, "");
    symlinkSync(target, database);
    expect(() => new StateStore(directory)).toThrow(/symlink/);
  });
});
