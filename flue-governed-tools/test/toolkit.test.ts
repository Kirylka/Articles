import { test } from "node:test";
import assert from "node:assert/strict";
import { createGovernedToolkit } from "../src/toolkit.js";
import { InMemoryAuditLog } from "../src/audit.js";
import { InMemoryIdempotencyStore } from "../src/idempotency.js";
import {
  AccessDeniedError,
  ApprovalDeniedError,
  AuthorizationDeniedError,
  GovernanceConfigError,
  MissingContextError,
  ScopeViolationError,
} from "../src/errors.js";
import type { ApprovalAdapter } from "../src/approval.js";
import type { TrustedContext } from "../src/types.js";

function setup(opts: { approval?: ApprovalAdapter } = {}) {
  const audit = new InMemoryAuditLog();
  const idempotencyStore = new InMemoryIdempotencyStore();
  let ctx: TrustedContext = {
    actor: { id: "a1", roles: ["agent"] },
    tenantId: "acme",
    scopes: ["customer:*"],
  };
  const toolkit = createGovernedToolkit({
    context: () => ctx,
    audit,
    idempotencyStore,
    approval: opts.approval,
  });
  return {
    audit,
    toolkit,
    setCtx: (c: Partial<TrustedContext>) => {
      ctx = { ...ctx, ...c };
    },
  };
}

test("allowed call succeeds, returns result, writes one allow/success entry", async () => {
  const { toolkit, audit } = setup();
  const tool = toolkit.defineGovernedTool({
    name: "lookup",
    description: "look up a customer",
    scope: (a: { customerId: string }) => `customer:${a.customerId}`,
    execute: (a) => ({ found: a.customerId }),
  });

  const result = await tool.execute({ customerId: "c-1" });
  assert.deepEqual(result, { found: "c-1" });

  const entries = await audit.entries();
  assert.equal(entries.length, 1);
  assert.equal(entries[0]!.decision, "allow");
  assert.equal(entries[0]!.outcome, "success");
});

test("out-of-scope call is blocked with ScopeViolationError and audited deny", async () => {
  const { toolkit, audit, setCtx } = setup();
  setCtx({ scopes: ["customer:c-1"] });
  const tool = toolkit.defineGovernedTool({
    name: "refund",
    description: "issue refund",
    sideEffect: true,
    scope: (a: { customerId: string }) => `customer:${a.customerId}`,
    execute: () => ({ ok: true }),
  });

  await assert.rejects(
    () => tool.execute({ customerId: "c-999" }),
    ScopeViolationError,
  );
  const entries = await audit.entries();
  assert.equal(entries.length, 1);
  assert.equal(entries[0]!.decision, "deny");
  assert.equal(entries[0]!.error, "scope_violation");
});

test("missing role is blocked with AccessDeniedError", async () => {
  const { toolkit, setCtx } = setup();
  setCtx({ actor: { id: "a1", roles: ["agent"] } });
  const tool = toolkit.defineGovernedTool({
    name: "close-account",
    description: "close",
    requireRoles: ["admin"],
    execute: () => ({ ok: true }),
  });
  await assert.rejects(() => tool.execute({}), AccessDeniedError);
});

test("idempotent side effect runs once and replays thereafter", async () => {
  const { toolkit, audit } = setup();
  let runs = 0;
  const tool = toolkit.defineGovernedTool({
    name: "refund",
    description: "issue refund",
    sideEffect: true,
    scope: (a: { customerId: string }) => `customer:${a.customerId}`,
    idempotency: { key: (a: { refundId: string }) => `refund:${a.refundId}` },
    execute: (a: { customerId: string; refundId: string }) => {
      runs += 1;
      return { refundId: a.refundId, processed: runs };
    },
  });

  const first = await tool.execute({ customerId: "c-1", refundId: "r-1" });
  const second = await tool.execute({ customerId: "c-1", refundId: "r-1" });

  assert.equal(runs, 1, "handler must run exactly once");
  assert.deepEqual(first, second);

  const entries = await audit.entries();
  assert.equal(entries.length, 2);
  assert.equal(entries[0]!.outcome, "success");
  assert.equal(entries[1]!.outcome, "replayed");
});

test("handler error is audited as allow/error, key released, error propagated", async () => {
  const { toolkit, audit } = setup();
  let attempts = 0;
  const tool = toolkit.defineGovernedTool({
    name: "refund",
    description: "issue refund",
    sideEffect: true,
    unsafeAllowUnauthorized: true, // this test is about error handling, not auth
    idempotency: { key: () => "refund:r-x" },
    execute: () => {
      attempts += 1;
      if (attempts === 1) throw new Error("gateway down");
      return { ok: true };
    },
  });

  await assert.rejects(() => tool.execute({}), /gateway down/);
  const entries = await audit.entries();
  assert.equal(entries[0]!.decision, "allow");
  assert.equal(entries[0]!.outcome, "error");

  // key was released on failure -> a retry executes again (not replayed)
  const retry = await tool.execute({});
  assert.deepEqual(retry, { ok: true });
  assert.equal(attempts, 2);
});

test("approval required but no adapter configured denies (fail-closed)", async () => {
  const { toolkit } = setup(); // no approval adapter
  const tool = toolkit.defineGovernedTool({
    name: "refund",
    description: "issue refund",
    approval: (a: { amount: number }) =>
      a.amount > 50 ? "exceeds $50" : false,
    execute: () => ({ ok: true }),
  });
  await assert.rejects(() => tool.execute({ amount: 100 }), ApprovalDeniedError);
  // under threshold: no approval needed, succeeds
  assert.deepEqual(await tool.execute({ amount: 10 }), { ok: true });
});

test("approval adapter decision is honored and approver recorded", async () => {
  const denying: ApprovalAdapter = {
    async request() {
      return { approved: false, reason: "policy" };
    },
  };
  const r1 = setup({ approval: denying });
  const denied = r1.toolkit.defineGovernedTool({
    name: "refund",
    description: "r",
    approval: true,
    execute: () => ({ ok: true }),
  });
  await assert.rejects(() => denied.execute({}), ApprovalDeniedError);

  const approving: ApprovalAdapter = {
    async request() {
      return { approved: true, approver: "manager@acme" };
    },
  };
  const r2 = setup({ approval: approving });
  const ok = r2.toolkit.defineGovernedTool({
    name: "refund",
    description: "r",
    approval: true,
    execute: () => ({ ok: true }),
  });
  await ok.execute({});
  const entries = await r2.audit.entries();
  assert.equal(entries[0]!.approver, "manager@acme");
});

test("missing context denies with MissingContextError and audits unknown actor", async () => {
  const audit = new InMemoryAuditLog();
  const toolkit = createGovernedToolkit({
    context: () => {
      throw new MissingContextError();
    },
    audit,
  });
  const tool = toolkit.defineGovernedTool({
    name: "lookup",
    description: "l",
    execute: () => ({ ok: true }),
  });
  await assert.rejects(() => tool.execute({}), MissingContextError);
  const entries = await audit.entries();
  assert.equal(entries.length, 1);
  assert.equal(entries[0]!.tenantId, "unknown");
  assert.equal(entries[0]!.decision, "deny");
});

test("authorize predicate blocks a call the caller isn't entitled to", async () => {
  const { toolkit, audit } = setup();
  const tool = toolkit.defineGovernedTool<{ accountId: string }>({
    name: "reset_password",
    description: "send a reset link",
    sideEffect: true,
    // The caller may only reset their own account.
    authorize: (a, ctx) => a.accountId === ctx.actor.id,
    execute: () => ({ sent: true }),
  });

  await assert.rejects(
    () => tool.execute({ accountId: "victim" }),
    AuthorizationDeniedError,
  );
  await tool.execute({ accountId: "a1" }); // a1 is the actor in setup()

  const entries = await audit.entries();
  assert.equal(entries[0]!.decision, "deny");
  assert.equal(entries[0]!.error, "authorization_denied");
  assert.equal(entries[1]!.decision, "allow");
});

test("a side-effect tool with no authorization gate is rejected at definition", () => {
  const { toolkit } = setup();
  assert.throws(
    () =>
      toolkit.defineGovernedTool({
        name: "danger",
        description: "ungated side effect",
        sideEffect: true,
        execute: () => ({ ok: true }),
      }),
    GovernanceConfigError,
  );
});

test("unsafeAllowUnauthorized opts out of the side-effect gate requirement", () => {
  const { toolkit } = setup();
  assert.doesNotThrow(() =>
    toolkit.defineGovernedTool({
      name: "danger",
      description: "explicitly ungated",
      sideEffect: true,
      unsafeAllowUnauthorized: true,
      execute: () => ({ ok: true }),
    }),
  );
});

test("an opaque host schema (e.g. Valibot) is passed through, not parsed", async () => {
  const { toolkit, audit } = setup();
  // A Valibot-style schema object: no `.parse` method, not a function.
  const valibotLike = { kind: "object", entries: { customerId: "string" } };
  let received: unknown;
  const tool = toolkit.defineGovernedTool<{ customerId: string }>({
    name: "lookup",
    description: "l",
    parameters: valibotLike,
    scope: (a) => `customer:${a.customerId}`,
    execute: (a) => {
      received = a;
      return { ok: true };
    },
  });

  // Flue would parse args first; here the args arrive and pass through intact.
  await tool.execute({ customerId: "c-1" });
  assert.deepEqual(received, { customerId: "c-1" });
  // The schema is exposed verbatim for Flue's defineTool to consume.
  assert.equal(tool.parameters, valibotLike);
  assert.equal((await audit.entries())[0]!.outcome, "success");
});

test("the returned object is a Flue-compatible tool", () => {
  const { toolkit } = setup();
  const tool = toolkit.defineGovernedTool({
    name: "lookup",
    description: "desc",
    parameters: { parse: (x) => x as { customerId: string } },
    execute: () => ({}),
  });
  assert.equal(tool.name, "lookup");
  assert.equal(tool.description, "desc");
  assert.equal(typeof tool.execute, "function");
  assert.ok("parameters" in tool);
});
