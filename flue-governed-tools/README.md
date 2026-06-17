# flue-governed-tools

*In-process governance for [Flue](https://github.com/withastro/flue) tools:
tenant-scoped execution, idempotent external writes, and a tamper-evident audit
trail.*

---

## The night the refund bot went sideways

You built a support agent on Flue. It's good. A customer types "you charged me
twice for April," the agent looks up the account, confirms the double charge,
and calls your `issue_refund` tool. Demo goes great. You ship it.

Three weeks later, three things have happened that nobody demoed:

1. A customer on **tenant A** asked about **tenant B's** invoice (they pasted
   the wrong link). The model, trying to be helpful, called `issue_refund` with
   tenant B's customer id. The refund went through. Two companies' data just
   touched in a way your org chart says can never happen.

2. The agent issued a refund, the upstream gateway timed out, the agent
   *retried* — and the customer got refunded **twice**. The tool ran twice
   because, to the model, retrying a failed step is just good sense.

3. Finance emails: "Can you show us every refund the bot issued last month, and
   prove the log wasn't edited?" You have... console logs. In CloudWatch.
   Interleaved with everything else. Unsigned.

None of these are Flue's fault. Flue gave you sandboxing, sessions, MCP, tools,
and it'll happily gate a tool by harness state. But "this customer's agent must
never act on another tenant," "this refund must happen at most once," and "this
log must be provably unaltered" aren't harness-state questions. They're
**application** questions, and they live right at the tool boundary.

That's the gap this library fills.

> Flue gates tools by *what the agent can do in a given state*.
> `flue-governed-tools` gates side effects by *who's asking, for which tenant,
> with what guarantee.*

---

## The fix is one wrapper

Here's the tool you already have, on Flue:

```ts
import { defineTool, init } from "@flue/runtime";
import * as v from "valibot";

const issueRefund = defineTool({
  name: "issue_refund",
  description: "Issue a refund to a customer.",
  parameters: v.object({
    customerId: v.string(),
    amount: v.number(),
    refundId: v.string(),
  }),
  execute: (a) => billing.refund(a.customerId, a.amount),
});

const agent = await init({ model, tools: [issueRefund] });
```

Here's the same tool, governed. Same shape, a few extra lines that each map to
one of the three things that went wrong:

```ts
import { defineTool, init } from "@flue/runtime";
import * as v from "valibot";
import {
  createGovernedToolkit,
  ContextStore,
  HashChainAuditLog,
  InMemoryIdempotencyStore,
} from "flue-governed-tools";

// The trusted context — who the agent is acting for — is bound by YOU,
// at the edge of the request. The model never sees it and can never set it.
const ctx = new ContextStore();

const toolkit = createGovernedToolkit({
  context: ctx.resolver(),
  audit: new HashChainAuditLog({ path: "audit.jsonl" }), // #3: tamper-evident
  idempotencyStore: new InMemoryIdempotencyStore(),       // #2: at-most-once
});

const issueRefund = defineTool(
  toolkit.defineGovernedTool<{ customerId: string; amount: number; refundId: string }>({
    name: "issue_refund",
    description: "Issue a refund to a customer.",
    parameters: v.object({
      customerId: v.string(),
      amount: v.number(),
      refundId: v.string(),
    }),
    sideEffect: true,

    // #1: this call may only touch the customer it names — and the actor must
    // be allowed that scope, or it's denied before billing is ever called.
    scope: (a) => `customer:${a.customerId}`,

    // #2: one refund per refundId, even if the agent retries ten times.
    idempotency: { key: (a) => `refund:${a.refundId}` },

    execute: (a, gctx) => billing.refund(gctx.tenantId, a.customerId, a.amount),
  }),
);
```

And at the edge, where you actually know who the request is for, you bind the
context for the whole run:

```ts
await ctx.run(
  {
    actor: { id: "agent-1", roles: ["support_agent"] },
    tenantId: "tenant-a",
    scopes: ["customer:c-100"], // this run may only act on customer c-100
  },
  () => init({ model, tools: [issueRefund] }),
);
```

Now replay those three nights:

1. The agent tries to refund tenant B's customer `c-999`. The scope it needs
   (`customer:c-999`) isn't in this run's allowed scopes. **Denied before
   `billing.refund` runs**, and the denial is written to the audit log.
2. The gateway times out, the agent retries the same `refundId`. The second
   call **replays the first result** instead of charging again. `billing` sees
   one refund.
3. Finance gets `audit.jsonl`: one hash-chained line per call, decision and
   outcome included. Change any past line and `verifyChain()` tells you exactly
   where. Add an HMAC key and a full rewrite can't be forged either.

---

## What you actually control

The one idea worth slowing down for: **the model controls the arguments; you
control the context.**

- `parameters` (the `customerId`, the `amount`) come from the model. Treat them
  as untrusted — that's the whole point.
- The **trusted context** (`actor`, `tenantId`, `scopes`) comes from your
  authenticated request and rides along out-of-band via `ContextStore`
  (`AsyncLocalStorage`). The model can't read it, can't forge it, can't argue
  with it.

`scope(args, ctx)` is where the two meet: you derive *what this call wants to
touch* from the arguments, and the library checks it against *what this actor is
allowed to touch* from the context. That single check is your tenant wall.

---

## The pipeline, in order

Every governed call runs the same gauntlet before (and after) your handler:

```
context → validate → RBAC → scope → approval → idempotency → execute → audit
```

Each step can stop the call, and exactly one audit record is written no matter
what happens — allow or deny, success, replay, or error.

- **Scope / tenant** — the wall between customers and tenants.
- **Idempotency** — at-most-once external writes, with replay on retry.
- **Audit** — one tamper-evident, hash-chained record per call.
- **RBAC**, **approval**, and **PII redaction** — there when you need them, as
  swappable adapters rather than the main event.

## When you outgrow the defaults

Everything cross-cutting is an interface with an in-process default you can
replace without touching a single tool:

| Concern | Default (in-process) | Swap in |
| --- | --- | --- |
| Idempotency | `InMemoryIdempotencyStore` | Redis / Postgres with atomic claim |
| Audit sink | `HashChainAuditLog` (JSONL) | a DB / WORM / object-store backend |
| Approval | *(none — fail closed)* | Slack, a ticket, Flue session state |
| RBAC | any-of role match | OPA / your permissions service |
| Redaction | regex defaults | OpenRedaction, `@redactpii/node` via `textRedactor` |

Two small hardening switches worth knowing about:

```ts
// Keyed audit: a full-file rewrite can't forge a valid chain without the key.
new HashChainAuditLog({ path: "audit.jsonl", hmacKey: process.env.AUDIT_KEY });

// Deeper PII redaction without taking a dependency here:
import { redactString } from "@redactpii/node";
createGovernedToolkit({ redaction: textRedactor((s) => redactString(s)), /* … */ });
```

---

## See it run

There's a runnable telecom support agent (a tiny mock stands in for the model,
so it runs with zero setup):

```bash
npm run example
```

You'll watch a cross-tenant refund get blocked, a duplicate refund get replayed
instead of re-issued, an over-threshold refund wait for approval, and the audit
chain verify clean at the end.

---

## Status & design

Early and honest: this is a pre-release library, built and tested against the
governance behavior end-to-end (50+ unit/e2e tests, including on-disk tamper
detection). The Flue integration targets `@flue/runtime` (1.0.0-beta.1), whose
own API is still in beta.

If you want the reasoning, not just the code:

- [`BUSINESS_REQUIREMENTS.md`](./BUSINESS_REQUIREMENTS.md) — the wedge and why it exists
- [`FUNCTIONAL_REQUIREMENTS.md`](./FUNCTIONAL_REQUIREMENTS.md) — what it must do
- [`TECH_ARCHITECTURE.md`](./TECH_ARCHITECTURE.md) — how it's built
- [`TASK_SPECS.md`](./TASK_SPECS.md) — the work, broken down

## License

[MIT](./LICENSE). As free as it gets.
