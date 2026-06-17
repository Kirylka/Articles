# flue-governed-tools — Functional Requirements & Constraints

**Status:** Draft v0.1 (requirements only — no implementation)
**Last updated:** 2026-06-17
**Companion to:** `BUSINESS_REQUIREMENTS.md`
**Traceability:** Each functional requirement references the business
requirement(s) it satisfies (BR-1 … BR-7).

---

## 1. Functional requirements

### 1.1 Governed tool definition

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-1.1** | The library MUST expose `defineGovernedTool(spec)` that takes a tool spec (name, description, argument schema, side-effect flag, governance policies, `execute` handler) and returns a tool object usable wherever a plain Flue tool is used. | BR-1..7 |
| **FR-1.2** | The returned tool MUST be Flue-compatible: it MUST carry `name`, `description`, a parameter/argument schema, and an `execute(args, hostContext?)` function so it can be passed in Flue's `init({ tools })`. | BR-1 |
| **FR-1.3** | A governed tool MUST declare whether it produces an external side effect. Side-effect tools are the ones eligible for idempotency and (optionally) approval. | BR-2, BR-5 |
| **FR-1.4** | Defining a governed tool MUST NOT require modifying or forking Flue; integration is via a thin adapter only. | BR-1 |

### 1.2 Trusted context

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-2.1** | The library MUST provide a mechanism to inject a **trusted context** (actor identity, roles, tenant id, allowed resource scopes, request id) that is resolved from the host/harness and is **never** derived from model output or tool arguments. | BR-1 |
| **FR-2.2** | The trusted context MUST be available to every governed tool invocation triggered within a single agent run, without the developer threading it through each call manually. | BR-1 |
| **FR-2.3** | If a governed tool is invoked with no resolvable trusted context, the call MUST be denied (fail-closed) and recorded. | BR-1, BR-3 |
| **FR-2.4** | The `execute` handler MUST receive the trusted context (incl. the scopes it was authorized against) so it can make tenant-bound calls to downstream systems. | BR-1 |

### 1.3 Scope / tenant enforcement

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-3.1** | A governed tool MUST be able to derive, from the call arguments and trusted context, the resource scope(s) the call will touch (e.g. `customer:c-123`). | BR-1 |
| **FR-3.2** | Before executing, the library MUST verify that every requested scope is permitted by the actor's allowed scopes; if any is not, the call MUST be denied with a scope-violation decision. | BR-1 |
| **FR-3.3** | Scope matching MUST support a wildcard so coarse grants (e.g. `customer:*`) and exact grants both work. | BR-1 |
| **FR-3.4** | Idempotency keys and audit records MUST be namespaced by tenant so they cannot collide or leak across tenants. | BR-1, BR-2, BR-3 |

### 1.4 RBAC (supporting)

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-4.1** | A governed tool MUST be able to declare required roles; the default adapter MUST grant access when the actor holds at least one (any-of). | BR-4 |
| **FR-4.2** | The RBAC decision MUST be delegable to a swappable adapter so teams can call an external policy provider. | BR-4, BR-7 |
| **FR-4.3** | A denied RBAC check MUST prevent execution and be recorded as a denial. | BR-3, BR-4 |

### 1.5 Approval (supporting)

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-5.1** | A governed tool MUST be able to require approval, either always or conditionally based on arguments/context (e.g. "refund exceeds threshold"). | BR-5 |
| **FR-5.2** | The approval decision MUST be delegated to a swappable adapter (the team's own workflow). The library MUST NOT implement an approval UI/workflow itself. | BR-5, BR-7 |
| **FR-5.3** | If approval is required but no adapter is configured, the call MUST be denied (fail-closed). | BR-5 |
| **FR-5.4** | The approval outcome (granted/denied, approver) MUST be recorded in the audit trail. | BR-3, BR-5 |

### 1.6 Idempotency

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-6.1** | A side-effect tool MUST be able to declare an idempotency policy that derives a stable key per logical operation from arguments/context. | BR-2 |
| **FR-6.2** | For a given key, the underlying `execute` MUST run **at most once** within the policy's optional TTL; later calls MUST replay the recorded result without re-executing the side effect. | BR-2 |
| **FR-6.3** | A concurrent call holding the same in-flight key MUST be rejected (no double-execution) rather than silently duplicating. | BR-2 |
| **FR-6.4** | A failed execution MUST release the key so the operation can be retried. | BR-2 |
| **FR-6.5** | A replayed result MUST be distinguishable in the audit trail from a fresh execution. | BR-2, BR-3 |
| **FR-6.6** | The idempotency store MUST be an interface with a default in-process implementation; teams MUST be able to supply their own (e.g. durable/shared) implementation. | BR-2, BR-7 |

### 1.7 Tamper-evident audit trail

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-7.1** | Every governed tool call MUST append exactly one immutable audit record containing at least: timestamp, actor, tenant, tool, requested scopes, governance decision (allow/deny), outcome (success/error/denied/replayed), idempotency key (if any), and redacted arguments/result/error. | BR-3 |
| **FR-7.2** | Each record MUST cryptographically chain to the previous one (store the prior record's hash) so that altering or removing any historical record is detectable. | BR-3 |
| **FR-7.3** | Record hashing MUST be deterministic regardless of field ordering (canonical serialization). | BR-3 |
| **FR-7.4** | The library MUST provide a function to verify a chain and report the first inconsistency. | BR-3 |
| **FR-7.5** | A default append-only JSONL (file) implementation and an in-memory implementation MUST be provided; the audit sink MUST be an interface for custom backends. | BR-3, BR-7 |

### 1.8 PII redaction

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-8.1** | The library MUST apply a redaction hook to arguments/results **before** they are written to the audit trail, without changing the values passed to the real `execute`. | BR-6 |
| **FR-8.2** | A default redactor MUST mask common sensitive field names and obvious PII patterns; redaction MUST be overridable per tool and per toolkit. | BR-6, BR-7 |

### 1.9 Decision & error semantics

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-9.1** | Governance rejections (missing context, RBAC, scope, approval, idempotency conflict) MUST raise typed errors distinguishable from ordinary handler failures. | BR-1..5 |
| **FR-9.2** | The evaluation order MUST be deterministic and documented: context → RBAC → scope → approval → idempotency → execute → record. | BR-1..6 |
| **FR-9.3** | A handler error MUST be recorded as an `error` outcome (not a governance denial) and the original error propagated. | BR-3 |

### 1.10 Reference example

| ID | Requirement | Traces |
| --- | --- | --- |
| **FR-10.1** | The repo MUST include a runnable **telecom support agent** example demonstrating: a scoped read, an idempotent refund, a blocked cross-tenant action, and audit-chain verification. | BR-1..3 |

---

## 2. Constraints

### 2.1 Architectural
- **C-1 (In-process):** v0.1 MUST run entirely in-process with no mandatory
  external service, network call, or platform dependency. This is the core
  differentiator versus managed control planes.
- **C-2 (Flue-native, non-invasive):** Integration MUST be additive — wrapping
  tools — and MUST NOT require patching Flue internals.
- **C-3 (Framework-agnostic core):** Governance logic MUST be decoupled from
  Flue specifics so the Flue binding is a thin, replaceable adapter.
- **C-4 (Pluggable adapters):** RBAC, approval, redaction, idempotency store,
  and audit sink MUST all be interfaces with sane defaults and override points.

### 2.2 Security
- **C-5 (Trusted context is server-authoritative):** Identity, tenant, and
  scopes MUST originate from the host and MUST be unreachable from model output
  or tool arguments.
- **C-6 (Fail-closed):** Any ambiguity — missing context, required-but-absent
  approval adapter, unmatched scope — MUST deny rather than allow.
- **C-7 (Audit integrity):** The audit chain MUST be verifiable independently
  of the writing process; the verification MUST not trust in-memory state alone.

### 2.3 Technical / platform
- **C-8 (Runtime):** Target Node.js (LTS, ≥ 20) and TypeScript; ship types.
  v0.1 relies only on runtime primitives (no heavy dependencies).
- **C-9 (Schema interop):** Argument schemas MUST accept zod-like validators so
  teams can reuse existing schemas; a schema MUST be optional.
- **C-10 (Single-instance default stores):** The default idempotency and audit
  implementations assume a single instance. Multi-instance/durable guarantees
  are delivered by user-supplied adapters, not promised by the defaults.

### 2.4 Operational / project
- **C-11 (Performance):** Per-call governance overhead MUST be negligible
  relative to model/tool latency (target sub-millisecond for in-memory checks).
- **C-12 (Footprint):** The package MUST stay small and dependency-light to keep
  the "small OSS library" positioning credible.
- **C-13 (Licensing):** License MUST be permissive and compatible with the Flue
  ecosystem (Apache-2.0 assumed, pending confirmation — see open questions).
- **C-14 (Scope discipline):** Approvals and RBAC remain supporting adapters in
  v0.1; the library MUST NOT grow into a policy engine or approval-workflow
  product.

---

## 3. Assumptions to validate before design

- **A-1:** Flue tools are plain objects accepted by `init({ tools })` with a
  name, description, schema, and `execute` — confirm against the current Flue
  tool API.
- **A-2:** `AsyncLocalStorage` (or an equivalent the host provides) is an
  acceptable mechanism for propagating trusted context within a run.
- **A-3:** A single audit record per call (covering decision + outcome) is
  sufficient for target compliance needs; pre/post split is deferred.

## 4. Out of scope (v0.1)

Distributed/durable stores, a hosted dashboard, non-JS runtimes, a formal
policy DSL, and a built-in human-approval UI. (Mirrors `BUSINESS_REQUIREMENTS.md`
§8.)
