import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export type Subscription = {
  id: string;
  channel: string;
  target: string;
  accountId?: string;
  threadId?: string;
};
export type Delivery = Subscription & { handle: string; attempts: number };
export class StateStore {
  private readonly db: DatabaseSync;
  constructor(stateDir: string) {
    const directory = path.join(stateDir, "plugins", "brokerkit");
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const databasePath = path.join(directory, "state.sqlite");
    if (existsSync(databasePath) && lstatSync(databasePath).isSymbolicLink())
      throw new Error("BrokerKit state database must not be a symlink");
    this.db = new DatabaseSync(databasePath);
    chmodSync(databasePath, 0o600);
    this.db.exec(
      "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000",
    );
    const version = this.db.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    if (version.user_version !== 0 && version.user_version !== 1)
      throw new Error(
        `unsupported BrokerKit state version ${version.user_version}`,
      );
    this.db.exec(
      `CREATE TABLE IF NOT EXISTS source_cursor(source_id TEXT PRIMARY KEY,cursor TEXT NOT NULL); CREATE TABLE IF NOT EXISTS request_handle(handle TEXT PRIMARY KEY,source_id TEXT NOT NULL,request_id TEXT NOT NULL,revision INTEGER NOT NULL,expires_at_ms INTEGER NOT NULL,UNIQUE(source_id,request_id,revision)); CREATE TABLE IF NOT EXISTS channel_subscription(id TEXT PRIMARY KEY,channel TEXT NOT NULL,target TEXT NOT NULL,account_id TEXT,thread_id TEXT,UNIQUE(channel,target,account_id,thread_id)); CREATE TABLE IF NOT EXISTS notification_delivery(subscription_id TEXT NOT NULL REFERENCES channel_subscription(id) ON DELETE CASCADE,handle TEXT NOT NULL REFERENCES request_handle(handle) ON DELETE CASCADE,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at_ms INTEGER NOT NULL,PRIMARY KEY(subscription_id,handle)); PRAGMA user_version=1;`,
    );
  }
  close(): void {
    this.db.close();
  }
  cursor(sourceId: string): string | undefined {
    return (
      this.db
        .prepare("SELECT cursor FROM source_cursor WHERE source_id=?")
        .get(sourceId) as { cursor: string } | undefined
    )?.cursor;
  }
  setCursor(sourceId: string, cursor: string): void {
    this.db
      .prepare(
        "INSERT INTO source_cursor VALUES(?,?) ON CONFLICT(source_id) DO UPDATE SET cursor=excluded.cursor",
      )
      .run(sourceId, cursor);
  }
  handle(
    sourceId: string,
    requestId: string,
    revision: number,
    expiresAtMs: number,
  ): string {
    const existing = this.db
      .prepare(
        "SELECT handle FROM request_handle WHERE source_id=? AND request_id=? AND revision=?",
      )
      .get(sourceId, requestId, revision) as { handle: string } | undefined;
    if (existing) return existing.handle;
    const handle = randomBytes(16).toString("base64url");
    this.db
      .prepare("INSERT INTO request_handle VALUES(?,?,?,?,?)")
      .run(handle, sourceId, requestId, revision, expiresAtMs);
    return handle;
  }
  resolve(
    handle: string,
  ): { sourceId: string; requestId: string; revision: number } | undefined {
    const value = this.db
      .prepare(
        "SELECT source_id,request_id,revision FROM request_handle WHERE handle=? AND expires_at_ms>?",
      )
      .get(handle, Date.now()) as
      | { source_id: string; request_id: string; revision: number }
      | undefined;
    return (
      value && {
        sourceId: value.source_id,
        requestId: value.request_id,
        revision: value.revision,
      }
    );
  }
  remove(sourceId: string, requestId: string): void {
    this.db
      .prepare("DELETE FROM request_handle WHERE source_id=? AND request_id=?")
      .run(sourceId, requestId);
  }
  subscribe(value: Omit<Subscription, "id">): Subscription {
    const normalized = [
      value.channel,
      value.target,
      value.accountId ?? "",
      value.threadId ?? "",
    ].join("\0");
    const id = createHash("sha256")
      .update("brokerkit-subscription\0")
      .update(normalized)
      .digest("hex");
    this.db
      .prepare("INSERT OR IGNORE INTO channel_subscription VALUES(?,?,?,?,?)")
      .run(
        id,
        value.channel,
        value.target,
        value.accountId ?? null,
        value.threadId ?? null,
      );
    return { id, ...value };
  }
  unsubscribe(value: Omit<Subscription, "id">): boolean {
    const result = this.db
      .prepare(
        "DELETE FROM channel_subscription WHERE channel=? AND target=? AND account_id IS ? AND thread_id IS ?",
      )
      .run(
        value.channel,
        value.target,
        value.accountId ?? null,
        value.threadId ?? null,
      );
    return result.changes > 0;
  }
  subscriptions(): Subscription[] {
    return (
      this.db
        .prepare("SELECT * FROM channel_subscription ORDER BY id")
        .all() as Array<{
        id: string;
        channel: string;
        target: string;
        account_id: string | null;
        thread_id: string | null;
      }>
    ).map((row) => ({
      id: row.id,
      channel: row.channel,
      target: row.target,
      ...(row.account_id ? { accountId: row.account_id } : {}),
      ...(row.thread_id ? { threadId: row.thread_id } : {}),
    }));
  }
  enqueue(handle: string): void {
    this.db
      .prepare(
        "INSERT OR IGNORE INTO notification_delivery SELECT id,?,'pending',0,? FROM channel_subscription",
      )
      .run(handle, Date.now());
  }
  due(limit: number): Delivery[] {
    return (
      this.db
        .prepare(
          "SELECT s.*,d.handle,d.attempts FROM notification_delivery d JOIN channel_subscription s ON s.id=d.subscription_id WHERE d.state IN ('pending','error') AND d.next_attempt_at_ms<=? ORDER BY d.next_attempt_at_ms LIMIT ?",
        )
        .all(Date.now(), limit) as Array<{
        id: string;
        channel: string;
        target: string;
        account_id: string | null;
        thread_id: string | null;
        handle: string;
        attempts: number;
      }>
    ).map((row) => ({
      id: row.id,
      channel: row.channel,
      target: row.target,
      handle: row.handle,
      attempts: row.attempts,
      ...(row.account_id ? { accountId: row.account_id } : {}),
      ...(row.thread_id ? { threadId: row.thread_id } : {}),
    }));
  }
  markDelivered(subscriptionId: string, handle: string): void {
    this.db
      .prepare(
        "UPDATE notification_delivery SET state='sent',attempts=attempts+1 WHERE subscription_id=? AND handle=?",
      )
      .run(subscriptionId, handle);
  }
  markDeliveryError(
    subscriptionId: string,
    handle: string,
    attempts: number,
  ): void {
    const boundedAttempts = Math.min(attempts + 1, 8);
    const delay = Math.min(300_000, 1000 * 2 ** boundedAttempts);
    this.db
      .prepare(
        "UPDATE notification_delivery SET state='error',attempts=?,next_attempt_at_ms=? WHERE subscription_id=? AND handle=?",
      )
      .run(boundedAttempts, Date.now() + delay, subscriptionId, handle);
  }
}
