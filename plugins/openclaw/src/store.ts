import { createHash, randomBytes } from "node:crypto";
import { closeSync, existsSync, lstatSync, mkdirSync, openSync } from "node:fs";
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
const SCHEMA_VERSION = 2;

export class StateStore {
  private readonly db: DatabaseSync;
  constructor(stateDir: string) {
    const directory = path.join(stateDir, "plugins", "brokerkit");
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    assertPrivateDirectory(directory);
    const databasePath = path.join(directory, "state.sqlite");
    if (existsSync(databasePath)) assertPrivateDatabase(databasePath);
    else closeSync(openSync(databasePath, "wx", 0o600));
    this.db = new DatabaseSync(databasePath);
    this.db.exec(
      "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000",
    );
    const version = this.db.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    if (version.user_version !== 0 && version.user_version !== SCHEMA_VERSION)
      throw new Error(
        `unsupported BrokerKit state version ${version.user_version}`,
      );
    if (version.user_version === 0) this.createSchema();
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
  retainSources(sourceIds: string[]): void {
    const keep = new Set(sourceIds);
    const rows = this.db
      .prepare("SELECT source_id FROM source_cursor")
      .all() as Array<{
      source_id: string;
    }>;
    const remove = this.db.prepare(
      "DELETE FROM source_cursor WHERE source_id=?",
    );
    this.transaction(() => {
      for (const row of rows)
        if (!keep.has(row.source_id)) remove.run(row.source_id);
    });
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
    this.transaction(() => {
      this.db
        .prepare(
          "DELETE FROM request_handle WHERE source_id=? AND request_id=? AND revision<>?",
        )
        .run(sourceId, requestId, revision);
      this.db
        .prepare("INSERT INTO request_handle VALUES(?,?,?,?,?)")
        .run(handle, sourceId, requestId, revision, expiresAtMs);
    });
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
  retainRequests(sourceId: string, requestIds: Set<string>): void {
    const rows = this.db
      .prepare(
        "SELECT DISTINCT request_id FROM request_handle WHERE source_id=?",
      )
      .all(sourceId) as Array<{ request_id: string }>;
    const remove = this.db.prepare(
      "DELETE FROM request_handle WHERE source_id=? AND request_id=?",
    );
    this.transaction(() => {
      for (const row of rows)
        if (!requestIds.has(row.request_id))
          remove.run(sourceId, row.request_id);
    });
  }
  pruneExpired(now = Date.now()): void {
    this.db
      .prepare("DELETE FROM request_handle WHERE expires_at_ms<=?")
      .run(now);
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
          "SELECT s.*,d.handle,d.attempts FROM notification_delivery d JOIN channel_subscription s ON s.id=d.subscription_id WHERE d.state IN ('pending','error') AND d.attempts<8 AND d.next_attempt_at_ms<=? ORDER BY d.next_attempt_at_ms LIMIT ?",
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
  failedDeliveryCount(): number {
    const row = this.db
      .prepare(
        "SELECT count(*) AS count FROM notification_delivery WHERE state='error' AND attempts>=8",
      )
      .get() as { count: number };
    return row.count;
  }
  private transaction<T>(operation: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  private createSchema(): void {
    this.transaction(() => {
      this.db.exec(`
        CREATE TABLE source_cursor(
          source_id TEXT PRIMARY KEY,
          cursor TEXT NOT NULL CHECK(length(cursor) BETWEEN 1 AND 4096)
        );
        CREATE TABLE request_handle(
          handle TEXT PRIMARY KEY CHECK(length(handle) >= 22),
          source_id TEXT NOT NULL,
          request_id TEXT NOT NULL,
          revision INTEGER NOT NULL CHECK(revision > 0),
          expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
          UNIQUE(source_id, request_id, revision)
        );
        CREATE TABLE channel_subscription(
          id TEXT PRIMARY KEY CHECK(length(id) = 64),
          channel TEXT NOT NULL CHECK(length(channel) > 0),
          target TEXT NOT NULL CHECK(length(target) > 0),
          account_id TEXT,
          thread_id TEXT,
          UNIQUE(channel, target, account_id, thread_id)
        );
        CREATE TABLE notification_delivery(
          subscription_id TEXT NOT NULL REFERENCES channel_subscription(id)
            ON DELETE CASCADE,
          handle TEXT NOT NULL REFERENCES request_handle(handle) ON DELETE CASCADE,
          state TEXT NOT NULL CHECK(state IN ('pending', 'sent', 'error')),
          attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8),
          next_attempt_at_ms INTEGER NOT NULL CHECK(next_attempt_at_ms >= 0),
          PRIMARY KEY(subscription_id, handle)
        );
        PRAGMA user_version=${SCHEMA_VERSION};
      `);
    });
  }
}

function assertPrivateDirectory(directory: string): void {
  const stat = lstatSync(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory())
    throw new Error("BrokerKit state directory must be a real directory");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid())
    throw new Error("BrokerKit state directory has an unsafe owner");
  if ((stat.mode & 0o077) !== 0)
    throw new Error("BrokerKit state directory permissions must be 0700");
}

function assertPrivateDatabase(databasePath: string): void {
  const stat = lstatSync(databasePath);
  if (stat.isSymbolicLink())
    throw new Error("BrokerKit state database must not be a symlink");
  if (!stat.isFile())
    throw new Error("BrokerKit state database must be a regular file");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid())
    throw new Error("BrokerKit state database has an unsafe owner");
  if ((stat.mode & 0o177) !== 0)
    throw new Error("BrokerKit state database permissions must be 0600");
}
