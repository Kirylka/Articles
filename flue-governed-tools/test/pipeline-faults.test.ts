/**
 * Pipeline fault matrix.
 *
 * Two invariants, exhaustively:
 *   1. A fault in any governance step (RBAC, scope, authorize, a trusted source,
 *      approval, idempotency) propagates the ORIGINAL error, never runs the
 *      handler, and leaves an audit record.
 *   2. A failure in the *recording* path (an audit append, or store.fail) must
 *      not mask the real error — the handler error, or the governance denial,
 *      is what the caller sees. Recording is best-effort; enforcement is not.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createGovernedToolkit,
  InMemoryAuditLog,
  InMemoryIdempotencyStore,
  caller,
  trusted,
  AuthorizationDeniedError,
  type AuditLog,
  type IdempotencyStore,
  type RbacAdapter,
  type ApprovalAdapter,
  type TrustedContext,
  type FlueCompatibleTool,
} from "./_all.js";

const ctx: TrustedContext = {
  actor: { id: "a1", roles: ["agent"] },
  tenantId: "acme",
  scopes: ["customer:*"],
};
const boom = () => {
  throw new Error("BOOM");
};

// --- 1. Every pre-execute governance fault -------------------------------------
interface FaultCase {
  name: string;
  make: (audit: AuditLog, run: () => unknown) => FlueCompatibleTool;
}

const preExecuteFaults: FaultCase[] = [
  {
    name: "RBAC adapter throws",
    make: (audit, run) => {
      const rbac: RbacAdapter = { can: boom };
      const gov = createGovernedToolkit({ context: () => ctx, audit, rbac });
      return gov.defineGovernedTool({
        name: "t", description: "", sideEffect: true,
        authorize: caller(() => true), execute: run,
      });
    },
  },
  {
    name: "scope derivation throws",
    make: (audit, run) => {
      const gov = createGovernedToolkit({ context: () => ctx, audit });
      return gov.defineGovernedTool({
        name: "t", description: "", sideEffect: true, scope: boom, execute: run,
      });
    },
  },
  {
    name: "authorize check throws",
    make: (audit, run) => {
      const gov = createGovernedToolkit({ context: () => ctx, audit });
      return gov.defineGovernedTool({
        name: "t", description: "", sideEffect: true,
        authorize: caller(boom), execute: run,
      });
    },
  },
  {
    name: "trusted source throws",
    make: (audit, run) => {
      const gov = createGovernedToolkit({
        context: () => ctx, audit, trustedSources: { s: boom },
      });
      return gov.defineGovernedTool({
        name: "t", description: "", sideEffect: true,
        authorize: trusted("s", () => true), execute: run,
      });
    },
  },
  {
    name: "approval policy throws",
    make: (audit, run) => {
      const gov = createGovernedToolkit({ context: () => ctx, audit });
      return gov.defineGovernedTool({
        name: "t", description: "", sideEffect: true, approval: boom, execute: run,
      });
    },
  },
  {
    name: "approval adapter throws",
    make: (audit, run) => {
      const approval: ApprovalAdapter = { request: boom };
      const gov = createGovernedToolkit({ context: () => ctx, audit, approval });
      return gov.defineGovernedTool({
        name: "t", description: "", sideEffect: true, approval: true, execute: run,
      });
    },
  },
  {
    name: "idempotency key throws",
    make: (audit, run) => {
      const gov = createGovernedToolkit({ context: () => ctx, audit });
      return gov.defineGovernedTool({
        name: "t", description: "", sideEffect: true, unsafeAllowUnauthorized: true,
        idempotency: { key: boom }, execute: run,
      });
    },
  },
  {
    name: "idempotency store.begin throws",
    make: (audit, run) => {
      const store: IdempotencyStore = {
        begin: boom,
        complete: async () => {},
        fail: async () => {},
        get: async () => undefined,
      };
      const gov = createGovernedToolkit({ context: () => ctx, audit, idempotencyStore: store });
      return gov.defineGovernedTool({
        name: "t", description: "", sideEffect: true, unsafeAllowUnauthorized: true,
        idempotency: { key: () => "k" }, execute: run,
      });
    },
  },
];

for (const c of preExecuteFaults) {
  test(`fault: ${c.name} → original error surfaces, handler never runs, recorded`, async () => {
    const audit = new InMemoryAuditLog();
    let runs = 0;
    const tool = c.make(audit, () => {
      runs += 1;
      return "ok";
    });
    await assert.rejects(() => tool.execute({}), /BOOM/);
    assert.equal(runs, 0, "the handler must not run on a pre-execute fault");
    const entries = await audit.entries();
    assert.ok(entries.length >= 1, "the fault must leave an audit record");
    assert.ok(entries.every((e) => e.outcome !== "success"));
  });
}

// --- 2. Recording failures must not mask the real error ------------------------

test("handler error is not masked when store.fail also throws", async () => {
  const inner = new InMemoryIdempotencyStore();
  const store: IdempotencyStore = {
    begin: (t, k, ttl) => inner.begin(t, k, ttl),
    complete: (t, k, r) => inner.complete(t, k, r),
    fail: boom, // releasing the key fails
    get: (t, k) => inner.get(t, k),
  };
  const gov = createGovernedToolkit({
    context: () => ctx, audit: new InMemoryAuditLog(), idempotencyStore: store,
  });
  const tool = gov.defineGovernedTool({
    name: "t", description: "", sideEffect: true, unsafeAllowUnauthorized: true,
    idempotency: { key: () => "k" },
    execute: () => {
      throw new Error("HANDLER");
    },
  });
  await assert.rejects(() => tool.execute({}), /HANDLER/); // not /BOOM/
});

test("handler error is not masked when the error-audit append fails", async () => {
  const inner = new InMemoryAuditLog();
  const audit: AuditLog = {
    append: (input) => {
      if (input.outcome === "error") throw new Error("AUDIT_DOWN");
      return inner.append(input);
    },
    entries: () => inner.entries(),
  };
  const gov = createGovernedToolkit({ context: () => ctx, audit });
  const tool = gov.defineGovernedTool({
    name: "t", description: "", sideEffect: true, unsafeAllowUnauthorized: true,
    execute: () => {
      throw new Error("HANDLER");
    },
  });
  await assert.rejects(() => tool.execute({}), /HANDLER/); // not /AUDIT_DOWN/
});

test("a denial is not masked when its audit append fails (sink down)", async () => {
  const audit: AuditLog = {
    append: () => {
      throw new Error("AUDIT_DOWN");
    },
    entries: async () => [],
  };
  const gov = createGovernedToolkit({ context: () => ctx, audit });
  const tool = gov.defineGovernedTool({
    name: "t", description: "", sideEffect: true,
    authorize: caller(() => false), // a denial
    execute: () => "ok",
  });
  // The caller must see the denial, not the audit-sink failure.
  await assert.rejects(() => tool.execute({}), AuthorizationDeniedError);
});

test("a side effect is never run when its intent cannot be recorded", async () => {
  const inner = new InMemoryAuditLog();
  const audit: AuditLog = {
    append: (input) => {
      if (input.outcome === "executing") throw new Error("INTENT_DOWN");
      return inner.append(input);
    },
    entries: () => inner.entries(),
  };
  const gov = createGovernedToolkit({ context: () => ctx, audit });
  let runs = 0;
  const tool = gov.defineGovernedTool({
    name: "t", description: "", sideEffect: true, unsafeAllowUnauthorized: true,
    execute: () => {
      runs += 1;
      return "ok";
    },
  });
  await assert.rejects(() => tool.execute({}));
  assert.equal(runs, 0, "fail closed: no side effect if the intent isn't recorded");
});
