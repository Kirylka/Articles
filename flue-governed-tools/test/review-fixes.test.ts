/**
 * Regression tests for the security review findings. Each test pins a concrete
 * bypass that was reproducible against the pre-fix code:
 *
 *   F1 — `approval: false` satisfied the definition-time gate but disabled the
 *        runtime gate, so an ungated side effect could define and execute.
 *   F2 — concurrent audit appends raced on seq/prevHash and corrupted the chain.
 *   F3 — idempotency keys were namespaced by tenant but not by tool, so two
 *        tools sharing a key string cross-replayed each other's results.
 *   F4 — a store.complete() failure after a successful execute released the key,
 *        letting a retry duplicate an external side effect.
 *   F5 — exceptions from governance steps (scope/RBAC/authorize/...) escaped
 *        without an audit record, contradicting "every decision, hash-chained".
 *   F6 — toFlueTool could return a non-string (undefined / bigint / cyclic),
 *        violating Flue's `Promise<string>` contract.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";
import {
  createGovernedToolkit,
  InMemoryAuditLog,
  HashChainAuditLog,
  InMemoryIdempotencyStore,
  verifyChain,
  toFlueTool,
  caller,
  GovernanceConfigError,
  IdempotencyConflictError,
  type AuditInput,
  type AuditEntry,
  type IdempotencyStore,
  type FlueCompatibleTool,
  type TrustedContext,
} from "../src/index.js";

const ctx: TrustedContext = {
  actor: { id: "a1", roles: ["agent"] },
  tenantId: "acme",
  scopes: ["customer:*"],
};

// --- F1 ---------------------------------------------------------------------
test("F1: approval:false does not satisfy the side-effect authorization gate", () => {
  const toolkit = createGovernedToolkit({ context: () => ctx, audit: new InMemoryAuditLog() });
  assert.throws(
    () =>
      toolkit.defineGovernedTool({
        name: "wipe",
        description: "ungated side effect dressed up with approval:false",
        sideEffect: true,
        approval: false, // explicitly "no approval" — must NOT count as a gate
        execute: () => "done",
      }),
    GovernanceConfigError,
  );
});

test("F1: approval:true (and an approval function) still count as a gate", () => {
  const toolkit = createGovernedToolkit({ context: () => ctx, audit: new InMemoryAuditLog() });
  assert.doesNotThrow(() =>
    toolkit.defineGovernedTool({
      name: "needsApproval",
      description: "gated by a real approval policy",
      sideEffect: true,
      approval: true,
      execute: () => "done",
    }),
  );
});

// --- F2 ---------------------------------------------------------------------
test("F2: concurrent appends to InMemoryAuditLog keep the chain valid", async () => {
  const log = new InMemoryAuditLog();
  const one = (i: number): AuditInput => ({
    actorId: "a",
    tenantId: "t",
    tool: `tool-${i}`,
    decision: "allow",
    outcome: "success",
    requestedScopes: [],
  });
  await Promise.all(Array.from({ length: 25 }, (_, i) => log.append(one(i))));
  const entries = await log.entries();
  assert.deepEqual(
    entries.map((e) => e.seq),
    Array.from({ length: 25 }, (_, i) => i),
  );
  assert.deepEqual(await verifyChain(entries), { valid: true });
});

test("F2: concurrent appends to the file-backed log keep the chain valid", async () => {
  const path = join(tmpdir(), `audit-race-${Date.now()}-${Math.random()}.jsonl`);
  try {
    const log = new HashChainAuditLog({ path });
    await Promise.all(
      Array.from({ length: 25 }, (_, i) =>
        log.append({
          actorId: "a",
          tenantId: "t",
          tool: `tool-${i}`,
          decision: "allow",
          outcome: "success",
          requestedScopes: [],
        }),
      ),
    );
    assert.deepEqual(await log.verify(), { valid: true });
    assert.equal((await log.entries()).length, 25);
  } finally {
    rmSync(path, { force: true });
  }
});

// --- F3 ---------------------------------------------------------------------
test("F3: the same idempotency key in two tools does not cross-replay", async () => {
  const toolkit = createGovernedToolkit({ context: () => ctx, audit: new InMemoryAuditLog() });
  const one = toolkit.defineGovernedTool({
    name: "one",
    description: "",
    sideEffect: true,
    unsafeAllowUnauthorized: true,
    idempotency: { key: () => "same" },
    execute: () => "ONE",
  });
  const two = toolkit.defineGovernedTool({
    name: "two",
    description: "",
    sideEffect: true,
    unsafeAllowUnauthorized: true,
    idempotency: { key: () => "same" },
    execute: () => "TWO",
  });
  assert.equal(await one.execute({}), "ONE");
  assert.equal(await two.execute({}), "TWO");
});

test("F3: the same tool with the same key still replays (real idempotency intact)", async () => {
  const toolkit = createGovernedToolkit({ context: () => ctx, audit: new InMemoryAuditLog() });
  let runs = 0;
  const tool = toolkit.defineGovernedTool({
    name: "charge",
    description: "",
    sideEffect: true,
    unsafeAllowUnauthorized: true,
    idempotency: { key: () => "k1" },
    execute: () => {
      runs += 1;
      return `run-${runs}`;
    },
  });
  assert.equal(await tool.execute({}), "run-1");
  assert.equal(await tool.execute({}), "run-1"); // replayed, not re-run
  assert.equal(runs, 1);
});

// --- F4 ---------------------------------------------------------------------
test("F4: a completion failure after a successful execute does not duplicate the side effect", async () => {
  // A store whose first complete() throws (e.g. a transient backend error) after
  // the external side effect has already happened.
  const inner = new InMemoryIdempotencyStore();
  let completeCalls = 0;
  const store: IdempotencyStore = {
    begin: (t, k, ttl) => inner.begin(t, k, ttl),
    complete: async (t, k, r) => {
      completeCalls += 1;
      if (completeCalls === 1) throw new Error("store write failed");
      return inner.complete(t, k, r);
    },
    fail: (t, k) => inner.fail(t, k),
    get: (t, k) => inner.get(t, k),
  };

  let sideEffects = 0;
  const toolkit = createGovernedToolkit({
    context: () => ctx,
    audit: new InMemoryAuditLog(),
    idempotencyStore: store,
  });
  const tool = toolkit.defineGovernedTool({
    name: "pay",
    description: "",
    sideEffect: true,
    unsafeAllowUnauthorized: true,
    idempotency: { key: () => "pay:1" },
    execute: () => {
      sideEffects += 1; // the irreversible external action
      return { paid: true };
    },
  });

  // First call: execute succeeds, completion fails -> error surfaces.
  await assert.rejects(() => tool.execute({}));
  assert.equal(sideEffects, 1);

  // Retry: must NOT run the side effect again. The key is still held, so the
  // retry is refused as a conflict rather than silently duplicating the payment.
  await assert.rejects(() => tool.execute({}), IdempotencyConflictError);
  assert.equal(sideEffects, 1, "the external side effect must not be duplicated");
});

// --- F5 ---------------------------------------------------------------------
test("F5: an exception thrown by a governance step is audited before it propagates", async () => {
  const audit = new InMemoryAuditLog();
  const toolkit = createGovernedToolkit({ context: () => ctx, audit });
  const tool = toolkit.defineGovernedTool<{ accountId: string }>({
    name: "reset",
    description: "",
    sideEffect: true,
    authorize: caller(() => {
      throw new Error("auth backend down");
    }),
    execute: () => "ok",
  });

  await assert.rejects(() => tool.execute({ accountId: "x" }), /auth backend down/);
  const entries = await audit.entries();
  assert.equal(entries.length, 1, "the infrastructure failure must leave a record");
  assert.equal(entries[0]!.decision, "deny");
  assert.equal(entries[0]!.outcome, "error");
  assert.match(entries[0]!.error ?? "", /auth backend down/);
  assert.deepEqual(await verifyChain(entries), { valid: true });
});

test("F5: an exception from scope derivation is audited too", async () => {
  const audit = new InMemoryAuditLog();
  const toolkit = createGovernedToolkit({ context: () => ctx, audit });
  const tool = toolkit.defineGovernedTool({
    name: "scoped",
    description: "",
    sideEffect: true,
    scope: () => {
      throw new Error("scope derivation blew up");
    },
    execute: () => "ok",
  });
  await assert.rejects(() => tool.execute({}), /scope derivation blew up/);
  const entries = await audit.entries();
  assert.equal(entries.length, 1);
  assert.equal(entries[0]!.outcome, "error");
});

// --- F6 ---------------------------------------------------------------------
test("F6: toFlueTool always returns a string", async () => {
  const make = (value: unknown): FlueCompatibleTool => ({
    name: "t",
    description: "",
    parameters: {},
    execute: async () => value,
  });

  const undef = toFlueTool(make(undefined));
  assert.equal(typeof (await undef.execute({})), "string");

  const big = toFlueTool(make(10n));
  const bigOut = await big.execute({});
  assert.equal(typeof bigOut, "string");
  assert.match(bigOut, /10/);

  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  const cyc = toFlueTool(make(cyclic));
  assert.equal(typeof (await cyc.execute({})), "string");

  const obj = toFlueTool(make({ ok: true }));
  assert.equal(await obj.execute({}), '{"ok":true}');
});
