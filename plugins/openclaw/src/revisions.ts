import { randomBytes } from "node:crypto";
import type { Snapshot, SnapshotEvent } from "./types.js";

export type SnapshotMaterial = Pick<
  Snapshot,
  "sources" | "requests" | "delivery_failures"
>;

type Waiter = {
  resolve(value: SnapshotEvent): void;
  reject(error: Error): void;
  timer: NodeJS.Timeout;
  signal?: AbortSignal;
  abort?(): void;
};

export class RevisionPublisher {
  private readonly epoch: string;
  private revision = 0;
  private material = "";
  private current?: Snapshot;
  private readonly waiters = new Set<Waiter>();

  constructor(epoch = randomBytes(16).toString("base64url")) {
    if (!/^[A-Za-z0-9_-]{22}$/u.test(epoch))
      throw new Error("invalid revision epoch");
    this.epoch = epoch;
  }

  publish(value: SnapshotMaterial): Snapshot {
    const material = JSON.stringify(value);
    if (this.current && material === this.material) return this.current;
    this.material = material;
    this.revision += 1;
    this.current = {
      api_version: "unyolo.io/operator-ui/v1",
      cursor: this.cursor(),
      synchronized_at: new Date().toISOString(),
      ...value,
    };
    for (const waiter of [...this.waiters])
      this.finish(waiter, {
        api_version: "unyolo.io/operator-ui/v1",
        cursor: this.current.cursor,
        changed: true,
      });
    return this.current;
  }

  snapshot(): Snapshot {
    if (!this.current) throw new Error("source_unavailable");
    return this.current;
  }

  wait(
    cursor: string,
    waitSeconds: number,
    signal?: AbortSignal,
  ): Promise<SnapshotEvent> {
    const observed = this.parseCursor(cursor);
    if (observed === undefined) return Promise.reject(cursorExpired());
    if (observed !== this.revision)
      return Promise.resolve({
        api_version: "unyolo.io/operator-ui/v1",
        cursor: this.cursor(),
        changed: true,
      });
    if (signal?.aborted) return Promise.reject(aborted());
    return new Promise((resolve, reject) => {
      const waiter: Waiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          this.finish(waiter, {
            api_version: "unyolo.io/operator-ui/v1",
            cursor: this.cursor(),
            changed: false,
          });
        }, waitSeconds * 1000),
        ...(signal ? { signal } : {}),
      };
      waiter.timer.unref();
      if (signal) {
        waiter.abort = () => this.fail(waiter, aborted());
        signal.addEventListener("abort", waiter.abort, { once: true });
      }
      this.waiters.add(waiter);
    });
  }

  close(): void {
    for (const waiter of [...this.waiters])
      this.fail(waiter, new Error("source_unavailable"));
  }

  private cursor(): string {
    return `${this.epoch}.${this.revision.toString(36)}`;
  }

  private parseCursor(value: string): number | undefined {
    const match = /^([A-Za-z0-9_-]{22})\.([0-9a-z]{1,13})$/u.exec(value);
    if (!match || match[1] !== this.epoch) return undefined;
    const revision = Number.parseInt(match[2] ?? "", 36);
    return Number.isSafeInteger(revision) && revision <= this.revision
      ? revision
      : undefined;
  }

  private finish(waiter: Waiter, value: SnapshotEvent): void {
    this.cleanup(waiter);
    waiter.resolve(value);
  }

  private fail(waiter: Waiter, error: Error): void {
    this.cleanup(waiter);
    waiter.reject(error);
  }

  private cleanup(waiter: Waiter): void {
    if (!this.waiters.delete(waiter)) return;
    clearTimeout(waiter.timer);
    if (waiter.signal && waiter.abort)
      waiter.signal.removeEventListener("abort", waiter.abort);
  }
}

function cursorExpired(): Error & { code: string } {
  return Object.assign(new Error("cursor_expired"), { code: "cursor_expired" });
}

function aborted(): Error {
  return new DOMException("The operation was aborted", "AbortError");
}
