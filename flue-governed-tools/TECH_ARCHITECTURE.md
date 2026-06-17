# flue-governed-tools — Technical Architecture

**Status:** Draft v0.1 (design — contracts and structure, not implementation)
**Last updated:** 2026-06-17
**Companion to:** `BUSINESS_REQUIREMENTS.md`, `FUNCTIONAL_REQUIREMENTS.md`
**Traceability:** Components reference the functional requirements (FR-*) and
constraints (C-*) they satisfy.

---

## 1. Architectural principles

1. **Wrap, don't replace.** A governed tool is an ordinary Flue tool with a
   governance pipeline in front of its handler. (C-2, FR-1.2)
2. **Framework-agnostic core, thin Flue adapter.** All governance logic is
   independent of Flue; the only Flue-aware code is a small adapter that shapes
   the output object and resolves context from the host call. (C-3)
3. **Trusted context is server-authoritative.** Identity/tenant/scope enter
   from the host, never from model output. (C-5, FR-2.1)
4. **Fail-closed by default.** Missing context, missing approval adapter, or an
   unmatched scope deny. (C-6, FR-2.3, FR-5.3)
5. **Everything cross-cutting is a pluggable interface** with an in-process
   default: context resolver, RBAC, approval, idempotency store, audit sink,
   redactor. (C-4, FR-4.2/5.2/6.6/7.5/8.2)

---

## 2. Component overview

```
                          ┌─────────────────────────────────────────────┐
   Flue init({ tools }) ──▶  GovernedTool (Flue-compatible: name, desc,   │
                          │   parameters, execute)                        │
                          └───────────────────┬─────────────────────────┘
                                              │ execute(args, hostCtx)
                                              ▼
                          ┌─────────────────────────────────────────────┐
                          │            Governance Pipeline                │
                          │  (deterministic order, FR-9.2)                │
                          │                                               │
   ContextResolver ──────▶  1. resolve trusted context  ──┐              │
   (AsyncLocalStorage)    │                               │ deny→audit   │
                          │  2. validate args (schema)    │              │
   RbacAdapter ──────────▶  3. RBAC check                 │              │
   ScopeMatcher ─────────▶  4. scope / tenant check       │              │
   ApprovalAdapter ──────▶  5. approval (side-effect)     │              │
   IdempotencyStore ─────▶  6. idempotency claim/replay   │              │
                          │  7. execute(handler)          │              │
   Redactor ─────────────▶  8. append audit record  ◀─────┘              │
   AuditLog (hash chain)  │                                               │
                          └─────────────────────────────────────────────┘
```

The **`GovernedToolkit`** is the composition root. It is constructed once with
the cross-cutting collaborators (context resolver, audit log, idempotency
store, and optional RBAC/approval/redaction adapters) and exposes
`defineGovernedTool(spec)`. Tools created from one toolkit share its
collaborators, so a developer configures governance once and gets it on every
tool. (FR-1.1, FR-2.2)

---

## 3. Module layout

```
flue-governed-tools/
├── src/
│   ├── index.ts          Public surface (re-exports)
│   ├── types.ts          TrustedContext, ExecutionContext, specs, tool shape
│   ├── errors.ts         GovernanceError hierarchy (FR-9.1)
│   ├── context.ts        ContextStore (AsyncLocalStorage), ContextResolver
│   ├── toolkit.ts        createGovernedToolkit + defineGovernedTool pipeline
│   ├── scope.ts          Wildcard scope matching (FR-3)
│   ├── rbac.ts           RbacAdapter + default any-of adapter (FR-4)
│   ├── approval.ts       ApprovalAdapter + ApprovalPolicy (FR-5)
│   ├── idempotency.ts    IdempotencyStore + in-memory default (FR-6)
│   ├── audit.ts          AuditLog, hash chain, verifyChain (FR-7)
│   ├── redaction.ts      Redactor + default PII redactor (FR-8)
│   └── flue.ts           Flue adapter: shape + host-context resolution (C-2/3)
├── examples/
│   └── support-agent.ts                             (FR-10.1)
└── test/
```

The core (`scope`, `rbac`, `approval`, `idempotency`, `audit`, `redaction`,
`toolkit`) has **no Flue import**. `flue.ts` is the only Flue-coupled module,
keeping C-3 enforceable by inspection.

---

## 4. Key contracts (design-level interfaces)

These define the boundaries; they are design contracts, not implementation.

```ts
// Trusted, harness-injected. Never built from model output. (FR-2.1, C-5)
interface TrustedContext {
  actor: { id: string; roles: string[] };
  tenantId: string;
  scopes: string[];                 // e.g. ["customer:c-123", "ticket:*"]
  requestId?: string;
  attributes?: Record<string, unknown>;
}

// What the tool handler receives. (FR-2.4)
interface ExecutionContext extends TrustedContext {
  authorizedScopes: string[];       // scopes this call was checked against
  host?: unknown;                   // raw Flue context passthrough
}

// The spec a developer authors. (FR-1.1)
interface GovernedToolSpec<TArgs, TResult> {
  name: string;
  description: string;
  parameters?: ArgValidator<TArgs>;            // zod-like or fn; optional (C-9)
  sideEffect?: boolean;                        // (FR-1.3)
  requireRoles?: string[];                     // (FR-4.1)
  scope?: (a: TArgs, c: TrustedContext) => string | string[];   // (FR-3.1)
  idempotency?: {                              // (FR-6.1)
    key: (a: TArgs, c: TrustedContext) => string;
    ttlMs?: number;
  };
  approval?: ApprovalPolicy<TArgs>;            // (FR-5.1)
  redact?: Redactor;                           // per-tool override (FR-8.2)
  execute: (a: TArgs, c: ExecutionContext) => Promise<TResult> | TResult;
}

// Pluggable collaborators (all have in-process defaults). (C-4)
type ContextResolver  = (hostCtx?: unknown) => TrustedContext | Promise<TrustedContext>;
interface RbacAdapter        { can(r): boolean | Promise<boolean>; }
interface ApprovalAdapter    { request(r): Promise<{ approved: boolean; approver?: string; reason?: string }>; }
interface IdempotencyStore   { begin(t, k, ttl?); complete(t, k, res); fail(t, k); get(t, k); }
interface AuditLog           { append(input): Promise<AuditEntry>; entries(): Promise<AuditEntry[]>; }
type Redactor                = (value: unknown) => unknown;

// Toolkit composition root. (FR-1.1, FR-2.2)
function createGovernedToolkit(opts: {
  context: ContextResolver;
  audit: AuditLog;
  idempotencyStore?: IdempotencyStore;
  rbac?: RbacAdapter;
  approval?: ApprovalAdapter;
  redaction?: Redactor;
  clock?: () => number;                        // injectable for tests (FR-6.2)
}): { defineGovernedTool<TArgs, TResult>(spec): FlueCompatibleTool };
```

---

## 5. Execution pipeline (normative order — FR-9.2)

For each `execute(rawArgs, hostCtx)`:

1. **Resolve context** via `ContextResolver`. None ⇒ `MissingContextError`
   (deny). (FR-2.3)
2. **Validate args** with the schema (identity if none). (C-9)
3. **RBAC**: `requireRoles` vs adapter. Fail ⇒ `AccessDeniedError`. (FR-4.3)
4. **Scope**: derive requested scopes; any not covered by `ctx.scopes` ⇒
   `ScopeViolationError`. (FR-3.2)
5. **Authorize** (only if declared): `authorize(args, ctx)` falsy ⇒
   `AuthorizationDeniedError`. Expresses dynamic checks scope lists can't, e.g.
   ownership. (FR-3.5)
6. **Approval** (only if policy triggers): adapter decides; required but
   unconfigured or denied ⇒ `ApprovalDeniedError`. (FR-5.3/5.4)
7. **Idempotency** (only if policy present): `begin(tenant, key, ttl)`:
   - `replay` ⇒ skip handler, return stored result, outcome `replayed`. (FR-6.2/6.5)
   - `in_flight` ⇒ `IdempotencyConflictError`. (FR-6.3)
   - `started` ⇒ proceed; `complete` on success, `fail` on throw. (FR-6.4)
8. **Execute** the handler with `ExecutionContext`.
9. **Audit**: append exactly one chained record with the decision + outcome,
   redacted args/result/error. Denials in steps 1–6 jump straight to this step
   with `decision: "deny"`. Handler throws ⇒ `decision: "allow"`,
   `outcome: "error"`, error re-propagated. (FR-7.1, FR-9.3)

Decision/outcome matrix recorded: `allow|deny` × `success|error|denied|replayed`.

---

## 6. Tamper-evident audit design (FR-7)

- **One record per call**, appended in order. (A-3)
- Each record stores `prevHash`; `hash = SHA-256(canonical(body_including_prevHash))`.
  Genesis `prevHash` = 64 zeros. (FR-7.2)
- **Canonical serialization** = recursive key-sort before hashing, so order of
  fields never changes the hash. (FR-7.3)
- **`verifyChain(entries)`** rewalks seq + prevHash + recomputed hash and
  reports the first break. Verification reads persisted state, not in-memory
  pointers. (FR-7.4, C-7)
- Default sinks: `HashChainAuditLog` (append-only JSONL file) and
  `InMemoryAuditLog`; `AuditLog` is an interface for DB/WORM/S3 backends. (FR-7.5)
- **Optional HMAC keying:** `hashEntry`/`verifyChain` and both log
  implementations accept an `hmacKey`. With a key, hashing is HMAC-SHA256, so an
  attacker who can rewrite the entire file *still* cannot forge a valid chain
  without the key. Zero added dependencies. (Verification must use the same key.)
- **Threat covered:** silent after-the-fact edit/deletion of history; with an
  `hmacKey`, also full-file re-forging without key knowledge.
  **Residual:** an attacker who obtains the HMAC key — mitigate by also
  exporting/anchoring the head hash externally (roadmap).

---

## 7. Trusted-context propagation (FR-2.2)

- Default: `ContextStore` backed by `AsyncLocalStorage`. Bind once at the run
  boundary: `contextStore.run(trustedCtx, () => agent.run(prompt))`; the
  resolver reads the current store on each tool call. (A-2)
- Alternative: a custom `ContextResolver` that reads the trusted context out of
  the host/Flue context object passed to `execute`, for runtimes where ALS is
  unavailable. The Flue adapter forwards `hostCtx` to the resolver to enable
  this. (C-2/3)
- The model-supplied `args` and the trusted context are kept in separate
  parameters throughout; they are never merged before authorization. (C-5)

---

## 8. Idempotency design (FR-6)

- Records keyed by `(tenantId, key)` — tenant-namespaced to prevent collision
  or cross-tenant leakage. (FR-3.4)
- States: `in_flight → completed | failed`, with optional TTL anchored at
  completion. `begin` returns `started | replay | in_flight`.
- Default `InMemoryIdempotencyStore` (single instance, C-10). Durable/shared
  guarantees come from a user-supplied store implementing the same interface
  (e.g. Redis/Postgres with atomic claim) — that is where multi-instance
  at-most-once is actually enforced. The library documents this boundary
  explicitly so the default's guarantee is not overstated.

---

## 9. Flue integration adapter (`flue.ts`)

Validated against `@flue/runtime` v1.0.0-beta.1 by reading its `.d.ts` and
running a governed tool through the real `defineTool` (A-1 resolved). The exact
`ToolDefinition`:

```ts
interface ToolDefinition<TParams> {
  name: string;
  description: string;
  parameters: TParams;                 // valibot schema OR raw JSON Schema object
  execute: (args, signal?: AbortSignal) => Promise<string>;
}
```

- Tools are listed in `createAgent(() => ({ model, tools }))`'s
  `AgentRuntimeConfig.tools`, alongside MCP (`connectMcpServer().tools`) and
  command (`defineCommand`) tools. (There is no top-level `init`; `init` is a
  method on the workflow context.)
- `toFlueTool(governed)` bridges our tool to this contract: it coerces the
  handler result to a **string** (`JSON.stringify` for non-strings) and drops
  the `AbortSignal` so it is never read as context. Consumed as
  `defineTool(toFlueTool(toolkit.defineGovernedTool(...)))`. (FR-1.2)
- `parameters` (valibot/JSON Schema) is opaque to us and converted to JSON
  Schema by Flue at define time; Flue `safeParse`s model arguments against it
  (throwing `ToolInputValidationError`) before our pipeline runs. Our internal
  validator is therefore identity for opaque schemas, active only for
  function/`{parse}` validators. (C-9)
- The 2nd `execute` argument is an **AbortSignal**, not context. `FlueContext`
  (`{ id, payload, env, req, log, init }`) is available at the agent/workflow
  boundary (notably `req` for auth), so trusted context is derived there and
  propagated via `ContextStore` (AsyncLocalStorage). `hostContextResolver`
  remains a helper for non-Flue runtimes that pass a context to `execute`.
  (FR-2.4, A-2)
- The adapter is the single Flue-coupled point; the core is insulated, so a
  future Flue API change is contained here.

---

## 10. Technology choices & constraints

| Area | Choice | Rationale / constraint |
| --- | --- | --- |
| Language/runtime | TypeScript, Node.js ≥ 20 ESM | Flue ecosystem; ship `.d.ts`. (C-8) |
| Dependencies | Runtime primitives only (`node:crypto`, `node:fs`, `node:async_hooks`) | "Small OSS library" footprint. (C-1, C-12) |
| Schema | Accept zod-like (`.parse`) or a function; optional | Reuse existing schemas, no hard zod dep. (C-9) |
| Persistence | In-memory + JSONL file defaults; interfaces for the rest | In-process, no external service required. (C-1, C-10) |
| License | MIT | As free/permissive as possible, widely trusted. (C-13) |

---

## 11. Performance & failure modes

- **Overhead (C-11):** all default checks are in-memory map/regex/hash ops —
  sub-millisecond, negligible against model/tool latency. The hot path adds one
  SHA-256 per call.
- **Audit append failure:** treated as a hard failure of the call (fail-closed
  on the integrity guarantee) rather than silently dropping a record — a
  governed action that cannot be recorded must not be reported as done.
- **Idempotency store failure:** a side-effect tool whose store is unavailable
  fails closed (no execution) rather than risk a duplicate.
- **Approval adapter timeout/error:** treated as not-approved (deny). (C-6)

---

## 12. Trade-offs & alternatives considered

- **One audit record per call** vs. pre-decision + post-outcome pair: chose one
  for a simpler chain and lower write amplification; revisit if a use case needs
  to prove intent independently of outcome. (A-3)
- **ALS context** vs. explicit threading: ALS keeps tool authoring clean and
  removes a class of "forgot to pass context" bugs; explicit resolver remains
  available for non-ALS runtimes.
- **In-process defaults** vs. shipping a durable backend: keeping durability in
  user-supplied adapters preserves the in-process differentiator (C-1) and
  avoids over-promising distributed guarantees from a single-node default.
- **Library** vs. middleware/proxy: a wrapper library (not a gateway) is the
  whole positioning wedge versus managed control planes.

---

## 13. Roadmap hooks (post-v0.1, non-binding)

- External anchoring/export of the audit head hash (strengthen §6 threat model).
- Reference durable adapters (Redis/Postgres idempotency, DB/WORM audit sink).
- Optional policy-provider adapter (e.g. OPA) behind the existing RBAC seam.
- Pre/post audit record split if intent-vs-outcome separation is required.
