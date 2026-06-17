/**
 * Example: a telecom support agent governed by flue-governed-tools.
 *
 * This file is runnable with zero external dependencies: a tiny `init()` mock
 * stands in for Flue so you can see the governance guarantees without wiring up
 * a real model. In a real app you would pass `tools` to Flue's `init(...)` and
 * bind the trusted context at your request boundary.
 *
 * It demonstrates the three hero guarantees:
 *   1. Tenant-scope enforcement  — a cross-tenant refund is BLOCKED.
 *   2. Idempotent external writes — a duplicate refund is REPLAYED, not re-run.
 *   3. Tamper-evident audit trail — the chain is VERIFIED at the end.
 *
 * Run:  npm run example
 */

import {
  ContextStore,
  InMemoryAuditLog,
  InMemoryIdempotencyStore,
  createGovernedToolkit,
  type ApprovalAdapter,
  type FlueCompatibleTool,
  type TrustedContext,
} from "../src/index.js";

// --- A fake downstream "billing system" with side effects we must protect. ---
let refundsIssued = 0;
const billing = {
  lookup(customerId: string) {
    return { customerId, plan: "unlimited", balance: 42.5 };
  },
  issueRefund(customerId: string, amount: number) {
    refundsIssued += 1; // the real-world side effect we must not duplicate
    return { refundId: `rf-${customerId}-${amount}`, settled: true };
  },
};

// --- Trusted context: bound by the harness, never by the model. ------------
const contextStore = new ContextStore();
const audit = new InMemoryAuditLog();

// Approve refunds up to $200; a real adapter would page a human.
const approvals: ApprovalAdapter = {
  async request(req) {
    const amount = (req.args as { amount: number }).amount;
    return amount <= 200
      ? { approved: true, approver: "supervisor@telco" }
      : { approved: false, reason: "exceeds supervisor limit" };
  },
};

const toolkit = createGovernedToolkit({
  context: contextStore.resolver(),
  audit,
  idempotencyStore: new InMemoryIdempotencyStore(),
  approval: approvals,
});

// --- Governed tools ---------------------------------------------------------
const lookupAccount = toolkit.defineGovernedTool({
  name: "lookup_account",
  description: "Look up a customer's account.",
  requireRoles: ["support_agent"],
  scope: (a: { customerId: string }) => `customer:${a.customerId}`,
  execute: (a) => billing.lookup(a.customerId),
});

const issueRefund = toolkit.defineGovernedTool({
  name: "issue_refund",
  description: "Issue a refund to a customer.",
  sideEffect: true,
  requireRoles: ["support_agent"],
  scope: (a: { customerId: string }) => `customer:${a.customerId}`,
  // One refund per (customer, refundId), even if the agent retries.
  idempotency: {
    key: (a: { customerId: string; refundId: string }) =>
      `refund:${a.customerId}:${a.refundId}`,
  },
  // Anything over $50 needs sign-off.
  approval: (a: { amount: number }) =>
    a.amount > 50 ? `refund of $${a.amount} exceeds $50` : false,
  execute: (a: { customerId: string; amount: number; refundId: string }) =>
    billing.issueRefund(a.customerId, a.amount),
});

// --- A tiny stand-in for Flue's init({ tools }). ----------------------------
function init(config: { tools: FlueCompatibleTool[] }) {
  const byName = new Map(config.tools.map((t) => [t.name, t]));
  return {
    async call(name: string, args: unknown) {
      const tool = byName.get(name);
      if (!tool) throw new Error(`unknown tool: ${name}`);
      return tool.execute(args);
    },
  };
}

const agent = init({ tools: [lookupAccount, issueRefund] });

// --- Helpers ----------------------------------------------------------------
const acmeAgent: TrustedContext = {
  actor: { id: "agent-1", roles: ["support_agent"] },
  tenantId: "acme-telco",
  scopes: ["customer:c-100"], // this agent may only touch customer c-100
  requestId: "req-1",
};

async function tryCall(label: string, name: string, args: unknown) {
  try {
    const result = await contextStore.run(acmeAgent, () =>
      agent.call(name, args),
    );
    console.log(`✅ ${label}:`, JSON.stringify(result));
  } catch (err) {
    console.log(`⛔ ${label}: ${(err as Error).constructor.name} — ${(err as Error).message}`);
  }
}

// --- Scenarios --------------------------------------------------------------
async function main() {
  console.log("\n=== telecom support agent (governed) ===\n");

  await tryCall("lookup in-scope customer", "lookup_account", {
    customerId: "c-100",
  });

  await tryCall("refund $40 (auto, under approval threshold)", "issue_refund", {
    customerId: "c-100",
    amount: 40,
    refundId: "r-1",
  });

  await tryCall("DUPLICATE refund $40 (should replay, not re-issue)", "issue_refund", {
    customerId: "c-100",
    amount: 40,
    refundId: "r-1",
  });

  await tryCall("refund $150 (needs approval -> approved)", "issue_refund", {
    customerId: "c-100",
    amount: 150,
    refundId: "r-2",
  });

  await tryCall("refund $500 (needs approval -> denied)", "issue_refund", {
    customerId: "c-100",
    amount: 500,
    refundId: "r-3",
  });

  await tryCall("CROSS-TENANT refund (out of scope -> blocked)", "issue_refund", {
    customerId: "c-999",
    amount: 10,
    refundId: "r-4",
  });

  // --- Report -------------------------------------------------------------
  console.log(`\nActual refunds hitting the billing system: ${refundsIssued}`);
  console.log("(2 expected: r-1 once despite the duplicate, and r-2)\n");

  const entries = await audit.entries();
  console.log("Audit trail:");
  for (const e of entries) {
    console.log(
      `  #${e.seq} ${e.tool} ${e.decision}/${e.outcome}` +
        (e.error ? ` (${e.error})` : "") +
        (e.approver ? ` approver=${e.approver}` : ""),
    );
  }

  const verification = audit.verify();
  console.log(
    `\nAudit chain verification: ${verification.valid ? "VALID ✅" : `BROKEN at ${verification.brokenAt} ❌`}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
