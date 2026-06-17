# flue-governed-tools

In-process governance for [Flue](https://github.com/withastro/flue) tools:
tenant-scoped execution, idempotent external writes, and an audit log you can
actually prove wasn't edited.

---

## A real example, because we just got one

In spring 2026, attackers took over more than 20,000 Instagram accounts without
breaking into anything. They asked.

Meta had an AI support agent called High Touch Support that helped locked-out
users get back into their accounts. One of its tools could trigger a password
reset. The tool worked. The problem was what it didn't do: it never checked that
the person asking actually owned the account they were asking about. So you
could point it at someone else's account, get a reset link, and walk in. Even
accounts without 2FA. The campaign ran for about seven weeks before anyone
noticed, and the list of victims included a White House handle and a senior US
Space Force account.

(Reporting: [BleepingComputer](https://www.bleepingcomputer.com/news/security/meta-ai-support-data-breach-affects-20-000-instagram-accounts/),
[TechCrunch](https://techcrunch.com/2026/06/01/hackers-hijacked-instagram-accounts-by-tricking-meta-ai-support-chatbot-into-granting-access/),
[SecurityWeek](https://www.securityweek.com/meta-says-20000-instagram-accounts-hacked-via-ai-tool-abuse/).)

The model wasn't jailbroken. There was no clever prompt injection. The agent did
a normal thing it was allowed to do, and the only thing standing between "help a
user" and "hand over 20,000 accounts" was a check that lived nowhere. Not in the
prompt, because prompts aren't security. It needed to live at the exact spot
where the tool does the dangerous part: *is the person asking allowed to touch
this account?*

That check is the whole reason this library exists.

## Where this fits with Flue

Flue gives you a real agent harness: sandboxing, sessions, MCP, tools, the works.
It can already say "this tool is only callable when the agent is in this state."
That's useful, and it's not what bit Meta.

The questions that bit Meta are different. "Is this caller allowed to act on
*this* account?" "Did we already do this once, so don't do it again on a retry?"
"Can we hand finance a log of every account change and show it hasn't been
touched?" Those aren't questions about harness state. They're questions about
the specific call, the specific caller, and the specific record. They belong
right next to the tool, and that's where this library puts them.

Short version: Flue decides what the agent can do. This decides who it's allowed
to do it to, whether it's safe to do twice, and whether you can prove what it
did.

## The fix is a wrapper

Here's a support tool on plain Flue. It resets a password:

```ts
import { createAgent, defineTool } from "@flue/runtime";
import * as v from "valibot";

const resetPassword = defineTool({
  name: "reset_password",
  description: "Send a password reset link for an account.",
  parameters: v.object({ accountId: v.string() }),
  execute: async (a) => {
    await accounts.sendResetLink(a.accountId);
    return `Sent a reset link for ${a.accountId}.`;
  },
});

const agent = createAgent(() => ({ model, tools: [resetPassword] }));
```

This is the High Touch Support bug in miniature. Nothing checks that the caller
is allowed to reset *that* account.

Two things change the moment you wrap it with this library.

First, the tool above won't even define. A `sideEffect: true` tool with no
authorization gate throws a `GovernanceConfigError` at startup and tells you to
add one. The exact HTS failure — a dangerous tool with the check living nowhere
— isn't something you can ship by accident.

Second, here's where the check goes. For account recovery the honest gate is
"does the caller actually control this account," which a static list can't
capture, so it lives in `authorize`:

```ts
import { createAgent, defineTool } from "@flue/runtime";
import * as v from "valibot";
import {
  createGovernedToolkit,
  ContextStore,
  HashChainAuditLog,
  InMemoryIdempotencyStore,
  toFlueTool,
} from "flue-governed-tools";

// You set who the caller is, from your own auth — not the model, ever.
const ctx = new ContextStore();

const toolkit = createGovernedToolkit({
  context: ctx.resolver(),
  audit: new HashChainAuditLog({ path: "audit.jsonl" }),
  idempotencyStore: new InMemoryIdempotencyStore(),
});

const resetPassword = defineTool(
  toFlueTool(
    toolkit.defineGovernedTool<{ accountId: string }>({
      name: "reset_password",
      description: "Send a password reset link for an account.",
      parameters: v.object({ accountId: v.string() }),
      sideEffect: true,

      // The check HTS never made: does this caller actually control the
      // account they're asking about? Runs before any link is sent; a false
      // answer stops the call and logs the refusal.
      authorize: (a, gctx) => accounts.isControlledBy(a.accountId, gctx.actor.id),

      // A retry won't send a second reset link.
      idempotency: { key: (a) => `reset:${a.accountId}` },

      execute: async (a) => {
        await accounts.sendResetLink(a.accountId);
        return `Sent a reset link for ${a.accountId}.`;
      },
    }),
  ),
);

const agent = createAgent(() => ({ model, tools: [resetPassword] }));
```

The caller's identity comes from your own auth, never the model. You set it once
for the conversation, reading it off `FlueContext`'s request:

```ts
await ctx.run(
  { actor: { id: "user-7", roles: ["account_holder"] }, tenantId: "app", scopes: [] },
  () => harness.prompt("I'm locked out, can you reset my password?"),
);
```

Now a request to reset someone else's account is refused before `sendResetLink`
runs, and the refusal lands in the audit log. The library doesn't write
`isControlledBy` for you — that ownership check is your business logic, and it's
the part HTS got wrong. What it guarantees is that the check exists, runs every
time before the side effect, and can't be quietly dropped.

## The one idea to take away

The model controls the arguments. You control the context.

The `accountId` in the call comes from the model, which means it can be anything
the conversation talked it into. Treat it as a claim, not a fact. The trusted
context — who the caller is, which accounts they've proven they own — comes from
your authenticated request and travels separately, through `ContextStore`
(`AsyncLocalStorage`). The model can't read it and can't set it.

`scope(args, ctx)` is where those two meet. You say what the call wants to touch,
the library checks it against what the caller is allowed to touch, and that
comparison is your wall.

## What runs on every call

```
context → validate → RBAC → scope → approval → idempotency → execute → audit
```

Any step can stop the call, and exactly one record gets written either way:
allowed or refused, succeeded, replayed, or errored.

- **Scope** keeps a call to one account or one tenant, and keeps callers off
  accounts that aren't theirs.
- **Idempotency** means a retry replays the first result instead of doing the
  thing twice.
- **Audit** is one hash-chained line per call. Edit any past line and
  `verifyChain()` tells you which one. Add an HMAC key and a from-scratch
  rewrite won't pass either.
- **RBAC**, **approval**, and **PII redaction** are there when you want them, as
  adapters rather than the main story.

## When the defaults aren't enough

Every moving part is an interface with a working in-process default. Swap any of
them without touching a tool:

| Piece | Default | What you'd swap in |
| --- | --- | --- |
| Idempotency | `InMemoryIdempotencyStore` | Redis or Postgres with an atomic claim |
| Audit | `HashChainAuditLog` (JSONL file) | a database, WORM, or object-store sink |
| Approval | none (calls that need it are refused) | Slack, a ticket queue, Flue session state |
| RBAC | any-of role match | OPA or your own permissions service |
| Redaction | regex defaults | OpenRedaction or `@redactpii/node` via `textRedactor` |

Two switches worth knowing:

```ts
// Keyed audit: a full-file rewrite can't forge a valid chain without the key.
new HashChainAuditLog({ path: "audit.jsonl", hmacKey: process.env.AUDIT_KEY });

// Heavier PII redaction without taking on the dependency here:
import { redactString } from "@redactpii/node";
createGovernedToolkit({ redaction: textRedactor((s) => redactString(s)), /* … */ });
```

## See it run

There's a small support-agent example with a mock model, so it runs with no
setup and no API key:

```bash
npm run example
```

It's the same `reset_password` tool from above plus a refund tool, and it walks
through the whole story: defining an ungated side-effect tool is refused;
resetting your own account works but resetting someone else's is blocked (the
Meta case); a duplicate refund replays instead of paying twice; an
over-threshold refund waits for approval; a cross-customer refund is denied; and
the audit chain verifies clean at the end.

## Is this real yet

It's pre-release, and honest about it. The governance behavior is covered by 60
unit and end-to-end tests, including on-disk tamper detection and tests that run
a governed tool through the actual `@flue/runtime` `defineTool` and valibot
rather than a stand-in. Flue's own API is still in beta (`@flue/runtime`
1.0.0-beta.1), so expect some churn there.

If you want the reasoning instead of just the code:

- [`BUSINESS_REQUIREMENTS.md`](./BUSINESS_REQUIREMENTS.md) — why it exists
- [`FUNCTIONAL_REQUIREMENTS.md`](./FUNCTIONAL_REQUIREMENTS.md) — what it has to do
- [`TECH_ARCHITECTURE.md`](./TECH_ARCHITECTURE.md) — how it's built
- [`TASK_SPECS.md`](./TASK_SPECS.md) — the work, broken down

## License

[MIT](./LICENSE).
