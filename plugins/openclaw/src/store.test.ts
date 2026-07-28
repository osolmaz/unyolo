import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { StateStore } from "./store.js";

describe("StateStore", () => {
  it("persists cursors, handles, subscriptions, and deduplicated delivery", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "unyolo-state-"));
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
      lstatSync(path.join(directory, "plugins", "unyolo", "state.sqlite"))
        .mode & 0o777,
    ).toBe(0o600);
    expect(
      lstatSync(path.join(directory, "plugins", "unyolo")).mode & 0o777,
    ).toBe(0o700);
    store.close();
  });
  it("stops bounded delivery retries and exposes permanent failures", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "unyolo-state-"));
    const store = new StateStore(directory);
    const handle = store.handle("hf", "request-1", 1, Date.now() + 60_000);
    const subscription = store.subscribe({ channel: "test", target: "room" });
    store.enqueue(handle);
    for (let attempts = 0; attempts < 8; attempts += 1)
      store.markDeliveryError(subscription.id, handle, attempts);
    expect(store.failedDeliveryCount()).toBe(1);
    expect(store.due(10)).toHaveLength(0);
    store.close();
  });
  it("removes stale revisions, expired handles, and removed source cursors", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "unyolo-state-"));
    const store = new StateStore(directory);
    store.setCursor("removed", "cursor-old");
    store.setCursor("kept", "cursor-new");
    store.retainSources(["kept"]);
    expect(store.cursor("removed")).toBeUndefined();
    const old = store.handle("kept", "request-1", 1, Date.now() + 60_000);
    store.handle("kept", "request-1", 2, Date.now() + 60_000);
    expect(store.resolve(old)).toBeUndefined();
    const expired = store.handle("kept", "expired", 1, Date.now() - 1);
    store.pruneExpired();
    expect(store.resolve(expired)).toBeUndefined();
    store.close();
  });
  it("rejects an earlier or unknown state schema", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "unyolo-state-"));
    const database = path.join(directory, "plugins", "unyolo", "state.sqlite");
    mkdirSync(path.dirname(database), { recursive: true, mode: 0o700 });
    const db = new DatabaseSync(database);
    db.exec("PRAGMA user_version=1");
    db.close();
    chmodSync(database, 0o600);
    expect(() => new StateStore(directory)).toThrow(/state version 1/);
  });
  it("rejects a symlink database", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "unyolo-state-"));
    const target = path.join(directory, "target");
    const database = path.join(directory, "plugins", "unyolo", "state.sqlite");
    mkdirSync(path.dirname(database), { recursive: true, mode: 0o700 });
    writeFileSync(target, "");
    symlinkSync(target, database);
    expect(() => new StateStore(directory)).toThrow(/symlink/);
  });
});
