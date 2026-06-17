/**
 * End-to-end tests: drive the whole stack the way Flue would — a trusted
 * context bound for the duration of a run, governed tools invoked by name, a
 * file-backed tamper-evident audit log, and a real idempotency store.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ContextStore,
  HashChainAuditLog,
  InMemoryIdempotencyStore,
  createGovernedToolkit,
  verifyChain,
  type ApprovalAdapter,
  type AuditEntry,
  type FlueCompatibleTool,
  type TrustedContext,
} from "../src/index.js";

function buildAgent(auditPath: string) {
  const contextStore = new ContextStore();
  const audit = new HashChainAuditLog({ path: auditPath });
  const approvals: ApprovalAdapter = {
    async request(req) {
      const amount = (req.args as { amount: number }).amount;
      return amount <= 200
        ? { approved: true, approver: "supervisor" }
        : { approved: false, reason: "too big" };
    },
  };
  const toolkit = createGovernedToolkit({
    context: contextStore.resolver(),
    audit,
    idempotencyStore: new InMemoryIdempotencyStore(),
    approval: approvals,
  });

  let refundsIssued = 0;
  const lookup = toolkit.defineGovernedTool({
    name: "lookup_account",
    description: "lookup",
    requireRoles: ["support_agent"],
    scope: (a: { customerId: string }) => `customer:${a.customerId}`,
    execute: (a) => ({ customerId: a.customerId }),
  });
  interface RefundArgs {
    customerId: string;
    amount: number;
    refundId: string;
  }
  const refund = toolkit.defineGovernedTool<RefundArgs>({
    name: "issue_refund",
    description: "refund",
    sideEffect: true,
    requireRoles: ["support_agent"],
    scope: (a) => `customer:${a.customerId}`,
    idempotency: {
      key: (a) => `refund:${a.customerId}:${a.refundId}`,
    },
    approval: (a) => (a.amount > 50 ? "over $50" : false),
    execute: () => {
      refundsIssued += 1;
      return { settled: true };
    },
  });

  const tools = new Map<string, FlueCompatibleTool>([
    [lookup.name, lookup],
    [refund.name, refund],
  ]);

  const runAs = <T>(ctx: TrustedContext, fn: () => Promise<T>) =>
    contextStore.run(ctx, fn);
  const call = (name: string, args: unknown) =>
    tools.get(name)!.execute(args);

  return { audit, runAs, call, refunds: () => refundsIssued };
}

test("e2e: full support-agent run enforces scope, idempotency and audit", async () => {
  const path = join(tmpdir(), `e2e-${Date.now()}-${Math.random()}.jsonl`);
  try {
    const app = buildAgent(path);
    const acme: TrustedContext = {
      actor: { id: "agent-1", roles: ["support_agent"] },
      tenantId: "acme",
      scopes: ["customer:c-100"],
    };

    await app.runAs(acme, async () => {
      await app.call("lookup_account", { customerId: "c-100" });
      await app.call("issue_refund", {
        customerId: "c-100",
        amount: 40,
        refundId: "r-1",
      });
      // duplicate -> replay, must NOT re-issue
      await app.call("issue_refund", {
        customerId: "c-100",
        amount: 40,
        refundId: "r-1",
      });
      // cross-tenant / out-of-scope -> blocked
      await assert.rejects(
        app.call("issue_refund", {
          customerId: "c-999",
          amount: 10,
          refundId: "r-9",
        }),
      );
    });

    assert.equal(app.refunds(), 1, "refund side effect runs exactly once");

    const entries = await app.audit.entries();
    assert.equal(entries.length, 4);
    assert.deepEqual(
      entries.map((e) => `${e.decision}/${e.outcome}`),
      ["allow/success", "allow/success", "allow/replayed", "deny/denied"],
    );
    assert.deepEqual(app.audit.verify(), { valid: true });
  } finally {
    rmSync(path, { force: true });
  }
});

test("e2e: tampering with the persisted audit file is detected", async () => {
  const path = join(tmpdir(), `e2e-tamper-${Date.now()}-${Math.random()}.jsonl`);
  try {
    const app = buildAgent(path);
    const acme: TrustedContext = {
      actor: { id: "agent-1", roles: ["support_agent"] },
      tenantId: "acme",
      scopes: ["customer:c-100"],
    };
    await app.runAs(acme, async () => {
      await app.call("lookup_account", { customerId: "c-100" });
      await app.call("issue_refund", {
        customerId: "c-100",
        amount: 40,
        refundId: "r-1",
      });
    });
    assert.deepEqual(app.audit.verify(), { valid: true });

    // Attacker edits the refund record on disk.
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const tampered = lines.map((line) => {
      const entry = JSON.parse(line) as AuditEntry;
      if (entry.tool === "issue_refund") entry.args = { customerId: "c-evil" };
      return JSON.stringify(entry);
    });
    writeFileSync(path, tampered.join("\n") + "\n");

    const entries = readFileSync(path, "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as AuditEntry);
    const result = verifyChain(entries);
    assert.equal(result.valid, false);
    assert.equal(result.brokenAt, 1);
  } finally {
    rmSync(path, { force: true });
  }
});

test("e2e: same idempotency key under two tenants does not collide", async () => {
  const path = join(tmpdir(), `e2e-tenant-${Date.now()}-${Math.random()}.jsonl`);
  try {
    const app = buildAgent(path);
    const mk = (tenantId: string): TrustedContext => ({
      actor: { id: "agent", roles: ["support_agent"] },
      tenantId,
      scopes: ["customer:c-1"],
    });

    await app.runAs(mk("acme"), () =>
      app.call("issue_refund", { customerId: "c-1", amount: 10, refundId: "r" }),
    );
    await app.runAs(mk("globex"), () =>
      app.call("issue_refund", { customerId: "c-1", amount: 10, refundId: "r" }),
    );

    // Different tenants -> both execute (no replay across tenant boundary).
    assert.equal(app.refunds(), 2);
  } finally {
    rmSync(path, { force: true });
  }
});
