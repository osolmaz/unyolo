import { describe, expect, it, vi } from "vitest";
import { RevisionPublisher } from "./revisions.js";

const empty = { sources: [], requests: [], delivery_failures: 0 };

describe("RevisionPublisher", () => {
  it("publishes only material changes and closes the snapshot/wait race", async () => {
    const revisions = new RevisionPublisher("a".repeat(22));
    const first = revisions.publish(empty);
    expect(revisions.publish(empty)).toBe(first);

    const changed = revisions.publish({ ...empty, delivery_failures: 1 });
    await expect(revisions.wait(first.cursor, 25)).resolves.toEqual({
      api_version: "unyolo.io/operator-ui/v1",
      cursor: changed.cursor,
      changed: true,
    });

    const waiting = revisions.wait(changed.cursor, 25);
    const latest = revisions.publish({ ...empty, delivery_failures: 2 });
    await expect(waiting).resolves.toMatchObject({
      cursor: latest.cursor,
      changed: true,
    });
  });

  it("coalesces rapid changes and rejects unknown epochs", async () => {
    const revisions = new RevisionPublisher("b".repeat(22));
    const first = revisions.publish(empty);
    const waiting = revisions.wait(first.cursor, 25);
    revisions.publish({ ...empty, delivery_failures: 1 });
    const latest = revisions.publish({ ...empty, delivery_failures: 2 });
    await expect(waiting).resolves.toMatchObject({ changed: true });
    await expect(revisions.wait(first.cursor, 25)).resolves.toMatchObject({
      cursor: latest.cursor,
      changed: true,
    });
    await expect(
      revisions.wait(`${"c".repeat(22)}.1`, 25),
    ).rejects.toMatchObject({ message: "cursor_expired" });
  });

  it("returns clean timeouts and aborts abandoned waits", async () => {
    vi.useFakeTimers();
    try {
      const revisions = new RevisionPublisher("d".repeat(22));
      const snapshot = revisions.publish(empty);
      const timed = revisions.wait(snapshot.cursor, 1);
      await vi.advanceTimersByTimeAsync(1000);
      await expect(timed).resolves.toMatchObject({ changed: false });

      const controller = new AbortController();
      const abandoned = revisions.wait(snapshot.cursor, 25, controller.signal);
      controller.abort();
      await expect(abandoned).rejects.toMatchObject({ name: "AbortError" });
    } finally {
      vi.useRealTimers();
    }
  });
});
