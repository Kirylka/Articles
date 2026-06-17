/**
 * The governance pipeline and its composition root.
 *
 * `createGovernedToolkit` is constructed once with the cross-cutting
 * collaborators (trusted-context resolver, audit log, and optional idempotency
 * store / RBAC / approval / redaction adapters). The `defineGovernedTool` it
 * returns wraps a tool spec so that every invocation runs through the same
 * deterministic pipeline before (and after) the real handler:
 *
 *   context -> validate -> RBAC -> scope -> authorize -> approval
 *           -> idempotency -> execute -> audit
 *
 * Audit records: denials, replays, and approval-deferrals write a single
 * record. A side-effecting call writes an `executing` intent record *before*
 * the handler runs (so a side effect can never run unrecorded) and an outcome
 * record after; non-side-effecting calls write the single outcome record.
 * Governance rejections raise a `GovernanceError` subclass (including
 * `ApprovalPendingError`, a suspend signal); handler failures propagate the
 * original error.
 */

import type {
  ArgValidator,
  ExecutionContext,
  FlueCompatibleTool,
  InferArgs,
  ParseValidator,
  StandardSchemaV1,
  TrustedContext,
} from "./types.js";
import type { ContextResolver, ContextStore } from "./context.js";
import type { AuditLog, AuditInput } from "./audit.js";
import { InMemoryIdempotencyStore, type IdempotencyStore } from "./idempotency.js";
import { defaultRbac, type RbacAdapter } from "./rbac.js";
import {
  type ApprovalAdapter,
  type ApprovalPolicy,
} from "./approval.js";
import { defaultRedactor, type Redactor } from "./redaction.js";
import { deniedScopes, normalizeScopes } from "./scope.js";
import { toFlueTool, type FlueToolDefinition } from "./flue.js";
import {
  AccessDeniedError,
  ApprovalDeniedError,
  ApprovalPendingError,
  AuthorizationDeniedError,
  GovernanceConfigError,
  GovernanceError,
  IdempotencyConflictError,
  ScopeViolationError,
} from "./errors.js";

/**
 * A declared trusted source: a server-side lookup whose result is a trustworthy
 * anchor to compare an (untrusted) argument against — e.g. "the email on file
 * for this account". Registered on the toolkit and referenced by name.
 */
export type TrustedSource = (
  args: any,
  ctx: TrustedContext,
) => unknown | Promise<unknown>;

/**
 * Authorization keyed to a *declared trusted anchor*, not to the arguments
 * alone — so the manifest can record the anchor honestly and the common footgun
 * (comparing an arg to nothing trusted) has no shape to be written in.
 *
 *  - `anchor: "caller"` → `check` receives the trusted execution context; key
 *    the decision to `ctx.actor` (e.g. `owns(ctx.actor.id, a.accountId)`).
 *  - `anchor: { trustedSource }` → the named source is resolved server-side and
 *    its value passed to `check` (e.g. `a.resetEmail === source`) — for
 *    anonymous-recovery-style checks where there is no authenticated actor.
 */
export type AuthorizeSpec<TArgs> =
  | {
      anchor: "caller";
      check: (args: TArgs, ctx: ExecutionContext) => boolean | Promise<boolean>;
    }
  | {
      anchor: { trustedSource: string };
      check: (args: TArgs, source: unknown) => boolean | Promise<boolean>;
    };

/**
 * Authorize keyed to the authenticated caller. The check receives the trusted
 * execution context — key the decision to `ctx.actor`. Prefer this helper over
 * the raw object: `args` is inferred (it's pinned by the tool's `parameters`),
 * and the call site reads lighter.
 *
 * ```ts
 * authorize: caller((a, ctx) => owns(ctx.actor.id, a.accountId))
 * ```
 */
export function caller<TArgs = Record<string, unknown>>(
  check: (args: TArgs, ctx: ExecutionContext) => boolean | Promise<boolean>,
): AuthorizeSpec<TArgs> {
  return { anchor: "caller", check };
}

/**
 * Authorize against a registered trusted source (resolved server-side and
 * passed to the check) — for anonymous-recovery-style checks with no
 * authenticated actor. `args` is inferred.
 *
 * ```ts
 * authorize: trusted("accountEmail", (a, email) => a.resetEmail === email)
 * ```
 */
export function trusted<TArgs = Record<string, unknown>>(
  source: string,
  check: (args: TArgs, value: unknown) => boolean | Promise<boolean>,
): AuthorizeSpec<TArgs> {
  return { anchor: { trustedSource: source }, check };
}

/** The spec a developer authors for a governed tool. */
export interface GovernedToolSpec<TArgs, TResult> {
  name: string;
  description: string;
  /** Argument schema (zod-like or a function). Optional. */
  parameters?: ArgValidator<TArgs>;
  /** Marks this tool as producing an external, real-world side effect. */
  sideEffect?: boolean;
  /** Roles required to call (any-of, via the RBAC adapter). */
  requireRoles?: string[];
  /** Derive the resource scope(s) this specific call will touch. */
  scope?: (args: TArgs, ctx: TrustedContext) => string | string[];
  /**
   * Authorization for "is this caller allowed to do this to this target?",
   * keyed to a declared trusted anchor (caller identity or a trusted source).
   * See {@link AuthorizeSpec}.
   */
  authorize?: AuthorizeSpec<TArgs>;
  /** Idempotency policy for side-effectful writes. */
  idempotency?: {
    key: (args: TArgs, ctx: TrustedContext) => string;
    ttlMs?: number;
  };
  /** Approval policy. */
  approval?: ApprovalPolicy<TArgs>;
  /** Redact args/result before they go to the audit log (per-tool override). */
  redact?: Redactor;
  /**
   * How the tool's arguments relate to its blast radius (default `"scoped"`):
   *  - `"scoped"`: structured args with a real target — fully governable
   *    in-process by scope/authorize.
   *  - `"primitive"`: a free-form payload (raw SQL, shell, arbitrary HTTP, a
   *    code interpreter). Argument scoping can't constrain it, so a
   *    side-effecting primitive must be bounded out-of-band (see
   *    {@link egressControlled}). Primitives are flagged as broad in the audit.
   */
  kind?: "scoped" | "primitive";
  /**
   * For a side-effecting `primitive`: your **attestation** that its blast radius
   * is bounded out-of-band (egress allowlist, no in-sandbox credential,
   * DB-level controls), since in-process argument scoping cannot bound it.
   *
   * This is NOT verified or enforced by the library — it can't check your egress
   * config. Setting it only lets the tool define; the containment is the
   * substrate's job. The library's contribution is to refuse to silently
   * certify a primitive as governed and to flag it broad in the audit.
   */
  egressControlled?: boolean;
  /**
   * Escape hatch: allow a `sideEffect` tool to be defined with no authorization
   * gate (scope/authorize/requireRoles/approval). Off by default — an ungated
   * side-effecting tool is how account-takeover bugs ship, so we refuse it
   * unless you say so explicitly.
   */
  unsafeAllowUnauthorized?: boolean;
  /** The real handler. Receives validated args and the execution context. */
  execute: (args: TArgs, ctx: ExecutionContext) => Promise<TResult> | TResult;
}

/**
 * The spec for {@link GovernedToolkit.tool}: same as {@link GovernedToolSpec},
 * but `parameters` is a Standard Schema (e.g. a Valibot `v.object(...)`) and the
 * argument type of every callback is **inferred** from it — no need to restate
 * it as a generic.
 */
export type GovernedFlueToolSpec<S extends StandardSchemaV1, TResult> = Omit<
  GovernedToolSpec<InferArgs<S>, TResult>,
  "parameters"
> & { parameters: S };

/** Flue's `defineTool`, injected so the core stays free of any Flue import. */
export type FlueDefineTool = (tool: FlueToolDefinition) => FlueToolDefinition;

export interface GovernedToolkitOptions {
  /**
   * Trusted-context source (never model output). Pass a {@link ContextStore}
   * directly, or a resolver function.
   */
  context: ContextStore | ContextResolver;
  /** Audit sink. */
  audit: AuditLog;
  /** Idempotency store. Defaults to a process-local in-memory store. */
  idempotencyStore?: IdempotencyStore;
  /**
   * Declared trusted sources for `authorize: { anchor: { trustedSource } }`.
   * Server-side lookups whose results are trustworthy anchors (e.g. the email
   * on file for an account). Referenced by name; an unknown name is rejected at
   * definition.
   */
  trustedSources?: Record<string, TrustedSource>;
  /**
   * Flue's `defineTool` (from `@flue/runtime`). Provide it to enable the
   * one-call {@link GovernedToolkit.tool} helper.
   */
  defineTool?: FlueDefineTool;
  /** RBAC adapter (defaults to any-of role matching). */
  rbac?: RbacAdapter;
  /** Approval adapter (fail-closed if a tool requires approval without one). */
  approval?: ApprovalAdapter;
  /** Default redactor applied to all tools (defaults to {@link defaultRedactor}). */
  redaction?: Redactor;
  /** Injectable clock for deterministic audit timestamps in tests. */
  clock?: () => number;
}

export interface GovernedToolkit {
  defineGovernedTool<TArgs = Record<string, unknown>, TResult = unknown>(
    spec: GovernedToolSpec<TArgs, TResult>,
  ): FlueCompatibleTool;
  /**
   * Derive a toolkit that resolves the trusted context from a fixed value (or a
   * given resolver) instead of the ambient one. Use this for Flue's dispatched
   * / addressable-agent pattern, where tool calls run detached from the caller
   * so `ContextStore` (AsyncLocalStorage) can't reach them: bind the context
   * per invocation inside `createAgent`, derived from `ctx.payload`/`ctx.env`.
   * All other collaborators (audit, idempotency, adapters) are shared.
   */
  withContext(context: TrustedContext | ContextResolver): GovernedToolkit;
  /**
   * One-call helper: define a governed tool and return a ready-to-use Flue
   * `ToolDefinition` (equivalent to `defineTool(toFlueTool(defineGovernedTool(
   * spec)))`). Argument types are inferred from `parameters`. Requires
   * `defineTool` to have been passed to {@link createGovernedToolkit}.
   */
  tool<S extends StandardSchemaV1, TResult = unknown>(
    spec: GovernedFlueToolSpec<S, TResult>,
  ): FlueToolDefinition;
}

function makeValidator<T>(v?: ArgValidator<T>): (input: unknown) => T {
  if (!v) return (input) => input as T;
  if (typeof v === "function") return v as (input: unknown) => T;
  const maybeParse = (v as { parse?: unknown }).parse;
  if (typeof maybeParse === "function") {
    return (input) => (v as ParseValidator<T>).parse(input);
  }
  // Opaque host schema (e.g. Flue/Valibot, TypeBox): the host validates it;
  // arguments arrive already parsed, so pass them through unchanged.
  return (input) => input as T;
}

function errorCode(err: unknown): string {
  if (err instanceof GovernanceError) return err.code;
  return err instanceof Error ? err.message : String(err);
}

/** Resolve whether an approval policy is triggered for this call. */
function evaluateApproval<TArgs>(
  policy: ApprovalPolicy<TArgs> | undefined,
  args: TArgs,
  ctx: TrustedContext,
): { needed: boolean; reason?: string } {
  if (policy === undefined || policy === false) return { needed: false };
  if (policy === true) return { needed: true };
  const result = policy(args, ctx);
  if (typeof result === "string") return { needed: true, reason: result };
  return { needed: Boolean(result) };
}

export function createGovernedToolkit(
  options: GovernedToolkitOptions,
): GovernedToolkit {
  const rbac = options.rbac ?? defaultRbac;
  const baseRedactor = options.redaction ?? defaultRedactor;
  const idempotencyStore =
    options.idempotencyStore ?? new InMemoryIdempotencyStore();
  const defineToolFn = options.defineTool;
  const timestamp = (): string | undefined =>
    options.clock ? new Date(options.clock()).toISOString() : undefined;

  // Build a toolkit bound to a specific context resolver; `withContext` derives
  // siblings that share everything else but resolve the context differently.
  const build = (resolveContext: ContextResolver): GovernedToolkit => {
    const withContext = (
      context: TrustedContext | ContextResolver,
    ): GovernedToolkit =>
      build(typeof context === "function" ? context : () => context);

    const tool = <S extends StandardSchemaV1, TResult = unknown>(
      spec: GovernedFlueToolSpec<S, TResult>,
    ): FlueToolDefinition => {
      if (!defineToolFn) {
        throw new GovernanceConfigError(
          spec.name,
          "toolkit.tool() needs Flue's defineTool. Pass `defineTool` to " +
            "createGovernedToolkit, or use defineGovernedTool + toFlueTool.",
        );
      }
      return defineToolFn(
        toFlueTool(
          defineGovernedTool(
            spec as unknown as GovernedToolSpec<InferArgs<S>, TResult>,
          ),
        ),
      );
    };

    return { defineGovernedTool, withContext, tool };

    function defineGovernedTool<TArgs, TResult>(
      spec: GovernedToolSpec<TArgs, TResult>,
    ): FlueCompatibleTool {
    // `authorize` is keyed to a declared anchor (caller or a trusted source),
    // so there's no arg-only shape to reject. We only check that a referenced
    // trusted source actually exists.
    if (
      spec.authorize &&
      typeof spec.authorize.anchor === "object" &&
      !(spec.authorize.anchor.trustedSource in (options.trustedSources ?? {}))
    ) {
      throw new GovernanceConfigError(
        spec.name,
        `authorize for "${spec.name}" references unknown trusted source ` +
          `"${spec.authorize.anchor.trustedSource}". Register it in ` +
          "createGovernedToolkit({ trustedSources }).",
      );
    }

    // Fail closed at definition time: a side-effecting tool must be gated.
    // The required gate differs by `kind` (the structural answer to both "the
    // check lived nowhere" and "general primitives can't be arg-scoped").
    if (spec.sideEffect && !spec.unsafeAllowUnauthorized) {
      if ((spec.kind ?? "scoped") === "primitive") {
        // A free-form payload (raw SQL, shell, arbitrary HTTP) can't be bound
        // by in-process argument scoping — enforcement must live out-of-band.
        if (!spec.egressControlled) {
          throw new GovernanceConfigError(
            spec.name,
            `Side-effecting primitive "${spec.name}" can't be governed by ` +
              "argument scoping — its payload is free-form. Bound its blast " +
              "radius out-of-band (egress allowlist / no in-sandbox credential " +
              "/ DB-level controls) and set egressControlled: true, or set " +
              "unsafeAllowUnauthorized: true to acknowledge the risk.",
          );
        }
      } else {
        const gated =
          Boolean(spec.scope) ||
          Boolean(spec.authorize) ||
          (spec.requireRoles?.length ?? 0) > 0 ||
          spec.approval !== undefined;
        if (!gated) {
          throw new GovernanceConfigError(
            spec.name,
            `Side-effecting tool "${spec.name}" has no authorization gate. ` +
              "Declare scope, authorize, requireRoles, or approval, or set " +
              "unsafeAllowUnauthorized: true to acknowledge the risk.",
          );
        }
      }
    }

    const validate = makeValidator(spec.parameters);
    const redactor = spec.redact ?? baseRedactor;
    const audit = (input: AuditInput) =>
      options.audit.append({ ...input, ts: input.ts ?? timestamp() });

    const execute = async (
      rawArgs: unknown,
      hostContext?: unknown,
      signal?: AbortSignal,
    ): Promise<unknown> => {
      // 1. Resolve trusted context (fail-closed; we still record the denial).
      let ctx: TrustedContext;
      try {
        ctx = await resolveContext(hostContext);
      } catch (err) {
        await audit({
          actorId: "unknown",
          tenantId: "unknown",
          tool: spec.name,
          decision: "deny",
          outcome: "denied",
          requestedScopes: [],
          error: errorCode(err),
        });
        throw err;
      }

      const base = {
        actorId: ctx.actor.id,
        tenantId: ctx.tenantId,
        tool: spec.name,
        requestId: ctx.requestId,
        // Flag broad tools in the audit; omit for the common scoped case so
        // existing entries are unchanged.
        ...(spec.kind === "primitive" ? { kind: "primitive" as const } : {}),
      };

      // 2. Validate arguments.
      let args: TArgs;
      try {
        args = validate(rawArgs);
      } catch (err) {
        await audit({
          ...base,
          decision: "deny",
          outcome: "denied",
          requestedScopes: [],
          args: redactor(rawArgs),
          error: `invalid_arguments: ${errorCode(err)}`,
        });
        throw err;
      }

      const redactedArgs = redactor(args);
      const requested = normalizeScopes(spec.scope?.(args, ctx));
      const execCtx: ExecutionContext = {
        ...ctx,
        authorizedScopes: requested,
        host: hostContext,
        signal,
      };

      const denyAudit = (error: string, extra: Partial<AuditInput> = {}) =>
        audit({
          ...base,
          decision: "deny",
          outcome: "denied",
          requestedScopes: requested,
          args: redactedArgs,
          error,
          ...extra,
        });

      // 3. RBAC.
      const requiredRoles = spec.requireRoles ?? [];
      if (!(await rbac.can({ tool: spec.name, requiredRoles, ctx }))) {
        await denyAudit("access_denied");
        throw new AccessDeniedError(spec.name, requiredRoles);
      }

      // 4. Scope / tenant isolation.
      const denied = deniedScopes(requested, ctx.scopes);
      if (denied.length > 0) {
        await denyAudit("scope_violation");
        throw new ScopeViolationError(spec.name, denied, ctx.scopes);
      }

      // 5. Authorization, keyed to a declared trusted anchor.
      if (spec.authorize) {
        const a = spec.authorize;
        const ok =
          a.anchor === "caller"
            ? await a.check(args, execCtx)
            : await a.check(
                args,
                await options.trustedSources![a.anchor.trustedSource]!(args, ctx),
              );
        if (!ok) {
          await denyAudit("authorization_denied");
          throw new AuthorizationDeniedError(spec.name);
        }
      }

      // 6. Approval (only when a policy is declared and triggered).
      let approver: string | undefined;
      const approval = evaluateApproval(spec.approval, args, ctx);
      if (approval.needed) {
        if (!options.approval) {
          await denyAudit("approval_denied");
          throw new ApprovalDeniedError(
            spec.name,
            "no approval adapter configured",
          );
        }
        const decision = await options.approval.request({
          tool: spec.name,
          args,
          ctx,
          reason: approval.reason,
        });
        if (decision.pending) {
          // Suspend, don't block: record the deferral and let the harness pause
          // and resume (which re-invokes the tool). No side effect runs.
          await audit({
            ...base,
            decision: "defer",
            outcome: "pending",
            requestedScopes: requested,
            args: redactedArgs,
            approver: decision.approver,
            error: decision.ref ? `approval_pending:${decision.ref}` : undefined,
          });
          throw new ApprovalPendingError(
            spec.name,
            decision.ref,
            decision.reason ?? approval.reason,
          );
        }
        if (!decision.approved) {
          await denyAudit("approval_denied", { approver: decision.approver });
          throw new ApprovalDeniedError(
            spec.name,
            decision.reason ?? approval.reason,
          );
        }
        approver = decision.approver;
      }

      // For side effects, record an intent BEFORE executing. If this append
      // fails we throw here, so a side effect can never run unrecorded. The
      // outcome record is written after. (Non-side-effect tools write only the
      // single outcome record.)
      const writeIntent = (idempotencyKey?: string): Promise<unknown> =>
        spec.sideEffect
          ? audit({
              ...base,
              decision: "allow",
              outcome: "executing",
              requestedScopes: requested,
              args: redactedArgs,
              approver,
              idempotencyKey,
            })
          : Promise.resolve(undefined);

      const runAndAudit = async (
        idempotencyKey?: string,
      ): Promise<TResult> => {
        await writeIntent(idempotencyKey);
        try {
          const result = await spec.execute(args, execCtx);
          await audit({
            ...base,
            decision: "allow",
            outcome: "success",
            requestedScopes: requested,
            args: redactedArgs,
            result: redactor(result),
            approver,
            idempotencyKey,
          });
          return result;
        } catch (err) {
          await audit({
            ...base,
            decision: "allow",
            outcome: "error",
            requestedScopes: requested,
            args: redactedArgs,
            error: errorCode(err),
            approver,
            idempotencyKey,
          });
          throw err;
        }
      };

      // 7. Idempotency (only when declared and a store is configured).
      const key = spec.idempotency?.key(args, ctx);
      if (key) {
        const store = idempotencyStore;
        const begin = await store.begin(
          ctx.tenantId,
          key,
          spec.idempotency?.ttlMs,
        );

        if (begin.status === "replay") {
          await audit({
            ...base,
            decision: "allow",
            outcome: "replayed",
            requestedScopes: requested,
            args: redactedArgs,
            result: redactor(begin.record.result),
            approver,
            idempotencyKey: key,
          });
          return begin.record.result;
        }

        if (begin.status === "in_flight") {
          await denyAudit("idempotency_conflict", { idempotencyKey: key });
          throw new IdempotencyConflictError(spec.name, key);
        }

        // status === "started": execute once, recording completion/failure.
        try {
          await writeIntent(key);
        } catch (err) {
          // Intent record failed — release the key so it can be retried, and
          // abort before any side effect runs.
          await store.fail(ctx.tenantId, key);
          throw err;
        }
        try {
          const result = await spec.execute(args, execCtx);
          await store.complete(ctx.tenantId, key, result);
          await audit({
            ...base,
            decision: "allow",
            outcome: "success",
            requestedScopes: requested,
            args: redactedArgs,
            result: redactor(result),
            approver,
            idempotencyKey: key,
          });
          return result;
        } catch (err) {
          await store.fail(ctx.tenantId, key);
          await audit({
            ...base,
            decision: "allow",
            outcome: "error",
            requestedScopes: requested,
            args: redactedArgs,
            error: errorCode(err),
            approver,
            idempotencyKey: key,
          });
          throw err;
        }
      }

      // 8. No idempotency: execute and audit.
      return runAndAudit();
    };

    return {
      name: spec.name,
      description: spec.description,
      parameters: spec.parameters,
      execute,
    };
    }
  };

  const resolver: ContextResolver =
    typeof options.context === "function"
      ? options.context
      : options.context.resolver();
  return build(resolver);
}
