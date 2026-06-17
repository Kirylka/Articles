# flue-governed-tools

> Open-source, in-process governance for [Flue](https://github.com/badlogic/flue)
> tools: **tenant-scoped execution, idempotent external writes, and
> tamper-evident audit logs.**

Flue is a sandbox agent framework with real harness control — tools, skills,
sessions, sandboxing, MCP adapters, workflows, observability. It gates *what* an
agent can do by harness state. But when a tool causes a **real-world side
effect** — a refund, an appointment, an account change, a ticket update — teams
still need application-level guarantees about *who* may do it, *for which
tenant*, with *what side-effect guarantee*.

`flue-governed-tools` is a small library that adds exactly that, **in-process**,
without routing your tool execution through an external platform.

| Layer | Controls |
| --- | --- |
| **Flue** | *What* the agent can do in a harness / session / state |
| **flue-governed-tools** | *Who* may do it, *for which tenant*, with *what side-effect guarantee* |

> Flue can gate tools by harness state. `flue-governed-tools` gates side effects
> by identity, tenant scope, idempotency policy, and audit guarantees.

## Why not a managed control plane?

Platforms like TrueFoundry are managed control planes/gateways: governance,
approvals, and PII guardrails added by routing tool execution through an
external service. This is the opposite shape — **a small OSS, Flue-native,
in-process library** for teams that want governance inside their own harness
with no external routing. Approval gates are becoming a standard primitive, so
here they are a thin *adapter*, not the product. The hero is the combination of
trusted tenant scope + idempotency + tamper-evidence.

## Install

```bash
npm install flue-governed-tools
```

Zero runtime dependencies. Node.js ≥ 20, TypeScript-first. MIT licensed.

## Quickstart

```ts
import {
  createGovernedToolkit,
  ContextStore,
  HashChainAuditLog,
  InMemoryIdempotencyStore,
} from "flue-governed-tools";

// Trusted context is bound by your harness — never by the model.
const contextStore = new ContextStore();

const toolkit = createGovernedToolkit({
  context: contextStore.resolver(),
  audit: new HashChainAuditLog({ path: "audit.jsonl" }),
  idempotencyStore: new InMemoryIdempotencyStore(),
});

const issueRefund = toolkit.defineGovernedTool({
  name: "issue_refund",
  description: "Issue a refund to a customer.",
  sideEffect: true,
  requireRoles: ["support_agent"],
  // The scope this call touches — checked against the actor's allowed scopes.
  scope: (a: { customerId: string }) => `customer:${a.customerId}`,
  // One refund per logical operation, even if the agent retries.
  idempotency: { key: (a: { refundId: string }) => `refund:${a.refundId}` },
  // Anything over $50 needs sign-off (delegated to your approval adapter).
  approval: (a: { amount: number }) => a.amount > 50 && "exceeds $50",
  execute: (a, ctx) => billing.refund(ctx.tenantId, a.customerId, a.amount),
});

// `issueRefund` is a plain Flue tool — pass it straight to init():
const agent = await init({ model, tools: [issueRefund] });

// Bind the trusted context for the duration of the run:
await contextStore.run(
  {
    actor: { id: "agent-1", roles: ["support_agent"] },
    tenantId: "acme",
    scopes: ["customer:c-100"],
  },
  () => agent.run(prompt),
);
```

A cross-tenant call is **blocked**, a duplicate refund is **replayed** (the
side effect runs once), and every call appends a chained, verifiable audit
record.

## What each governed tool gives you

The pipeline runs in a fixed order on every call:

```
context → validate → RBAC → scope → approval → idempotency → execute → audit
```

- **Tenant-scope enforcement** — calls outside the actor's allowed scopes are
  denied before the handler runs.
- **Idempotent external writes** — at-most-once per idempotency key, with replay.
- **Tamper-evident audit trail** — one hash-chained record per call;
  `verifyChain()` detects any after-the-fact edit.
- **RBAC**, **approval**, and **PII redaction** as swappable adapters.

Everything cross-cutting is a pluggable interface with an in-process default:
`ContextResolver`, `RbacAdapter`, `ApprovalAdapter`, `IdempotencyStore`,
`AuditLog`, `Redactor`. Supply your own (Redis/Postgres idempotency, a WORM
audit sink, an external policy provider) without touching tool code.

## Hardening & integrations

**Keyed (HMAC) audit chain.** Plain SHA-256 chaining detects edits to history;
an HMAC key additionally stops an attacker who can rewrite the whole file from
forging a valid chain. Still zero-dependency:

```ts
new HashChainAuditLog({ path: "audit.jsonl", hmacKey: process.env.AUDIT_KEY });
// verify later with the same key:
verifyChain(entries, process.env.AUDIT_KEY);
```

**Deeper PII redaction.** The default redactor covers common cases. For richer
coverage, adapt any string-based redaction library (e.g.
[OpenRedaction](https://openredaction.com/),
[`@redactpii/node`](https://www.npmjs.com/package/@redactpii/node)) — no hard
dependency added:

```ts
import { redactString } from "@redactpii/node";
const toolkit = createGovernedToolkit({
  redaction: textRedactor((s) => redactString(s)),
  /* ... */
});
```

## Example

A runnable telecom support agent (with a mock `init()` standing in for Flue):

```bash
npm run example
```

It demonstrates scope blocking, idempotent replay, approval, and audit-chain
verification end to end.

## Design docs

- [`BUSINESS_REQUIREMENTS.md`](./BUSINESS_REQUIREMENTS.md)
- [`FUNCTIONAL_REQUIREMENTS.md`](./FUNCTIONAL_REQUIREMENTS.md)
- [`TECH_ARCHITECTURE.md`](./TECH_ARCHITECTURE.md)
- [`TASK_SPECS.md`](./TASK_SPECS.md)

## License

[MIT](./LICENSE)
