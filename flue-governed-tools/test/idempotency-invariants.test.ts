/**
 * Idempotency invariants for the in-process store.
 *
 *   - Concurrent begins for the same key elect exactly one "started"; the rest
 *     see "in_flight" (no double-execution under a burst of retries).
 *   - complete()/fail() only act on an in-flight record, so a *stale* completion
 *     (from an attempt that already failed or completed) can't resurrect or
 *     clobber the key. (Distinguishing concurrent re-claims of the same key
 *     still needs claim tokens — a documented limitation, not solved here.)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { InMemoryIdempotencyStore } from "./_all.js";

test("concurrent begins on one key elect exactly one started", async () => {
  const store = new InMemoryIdempotencyStore();
  const results = await Promise.all(
    Array.from({ length: 20 }, () => store.begin("t", "k")),
  );
  const started = results.filter((r) => r.status === "started");
  const inFlight = results.filter((r) => r.status === "in_flight");
  assert.equal(started.length, 1, "exactly one caller may execute");
  assert.equal(inFlight.length, 19);
});

test("a stale complete() after fail() does not resurrect the key", async () => {
  const store = new InMemoryIdempotencyStore();
  await store.begin("t", "k");
  await store.fail("t", "k"); // attempt failed; key released
  await store.complete("t", "k", { stale: true }); // late completion from that attempt
  // The key must still be retryable, not a replayable "completed".
  assert.equal((await store.begin("t", "k")).status, "started");
});

test("a stale duplicate complete() keeps the first result", async () => {
  const store = new InMemoryIdempotencyStore();
  await store.begin("t", "k");
  await store.complete("t", "k", "first");
  await store.complete("t", "k", "second"); // stale: record is no longer in-flight
  const replay = await store.begin("t", "k");
  assert.equal(replay.status, "replay");
  if (replay.status === "replay") assert.equal(replay.record.result, "first");
});

test("fail() only releases an in-flight record (no effect once completed)", async () => {
  const store = new InMemoryIdempotencyStore();
  await store.begin("t", "k");
  await store.complete("t", "k", "done");
  await store.fail("t", "k"); // stale failure must not un-complete it
  const replay = await store.begin("t", "k");
  assert.equal(replay.status, "replay");
});
