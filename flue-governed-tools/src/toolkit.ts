/**
 * The governance pipeline and its composition root.
 *
 * `createGovernedToolkit` is constructed once with the cross-cutting
 * collaborators (trusted-context resolver, audit log, and optional idempotency
 * store / RBAC / approval / redaction adapters). The `defineGovernedTool` it
 * returns wraps a tool spec so that every invocation runs through the same
 * deterministic pipeline before (and after) the real handler:
 *
 *   context -> validate -> RBAC -> scope -> approval -> idempotency
 *           -> execute -> audit
 *
 * Exactly one audit entry is appended per call. Governance rejections raise a
 * `GovernanceError` subclass; handler failures propagate the original error.
 */

import type {
  ArgValidator,
  ExecutionContext,
  FlueCompatibleTool,
  ParseValidator,
  TrustedContext,
} from "./types.js";
import type { ContextResolver } from "./context.js";
import type { AuditLog, AuditInput } from "./audit.js";
import type { IdempotencyStore } from "./idempotency.js";
import { defaultRbac, type RbacAdapter } from "./rbac.js";
import {
  type ApprovalAdapter,
  type ApprovalPolicy,
} from "./approval.js";
import { defaultRedactor, type Redactor } from "./redaction.js";
import { deniedScopes, normalizeScopes } from "./scope.js";
import {
  AccessDeniedError,
  ApprovalDeniedError,
  GovernanceError,
  IdempotencyConflictError,
  ScopeViolationError,
} from "./errors.js";

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
  /** Idempotency policy for side-effectful writes. */
  idempotency?: {
    key: (args: TArgs, ctx: TrustedContext) => string;
    ttlMs?: number;
  };
  /** Approval policy. */
  approval?: ApprovalPolicy<TArgs>;
  /** Redact args/result before they go to the audit log (per-tool override). */
  redact?: Redactor;
  /** The real handler. Receives validated args and the execution context. */
  execute: (args: TArgs, ctx: ExecutionContext) => Promise<TResult> | TResult;
}

export interface GovernedToolkitOptions {
  /** Resolves the trusted context for each call (never from model output). */
  context: ContextResolver;
  /** Audit sink. */
  audit: AuditLog;
  /** Idempotency store (required for tools that declare an idempotency key). */
  idempotencyStore?: IdempotencyStore;
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
  const timestamp = (): string | undefined =>
    options.clock ? new Date(options.clock()).toISOString() : undefined;

  function defineGovernedTool<TArgs, TResult>(
    spec: GovernedToolSpec<TArgs, TResult>,
  ): FlueCompatibleTool {
    const validate = makeValidator(spec.parameters);
    const redactor = spec.redact ?? baseRedactor;
    const audit = (input: AuditInput) =>
      options.audit.append({ ...input, ts: input.ts ?? timestamp() });

    const execute = async (
      rawArgs: unknown,
      hostContext?: unknown,
    ): Promise<unknown> => {
      // 1. Resolve trusted context (fail-closed; we still record the denial).
      let ctx: TrustedContext;
      try {
        ctx = await options.context(hostContext);
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

      // 5. Approval (only when a policy is declared and triggered).
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
        if (!decision.approved) {
          await denyAudit("approval_denied", { approver: decision.approver });
          throw new ApprovalDeniedError(
            spec.name,
            decision.reason ?? approval.reason,
          );
        }
        approver = decision.approver;
      }

      const execCtx: ExecutionContext = {
        ...ctx,
        authorizedScopes: requested,
        host: hostContext,
      };

      const runAndAudit = async (
        idempotencyKey?: string,
      ): Promise<TResult> => {
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

      // 6. Idempotency (only when declared and a store is configured).
      const key = spec.idempotency?.key(args, ctx);
      if (key && options.idempotencyStore) {
        const store = options.idempotencyStore;
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

      // 7. No idempotency: execute and audit.
      return runAndAudit();
    };

    return {
      name: spec.name,
      description: spec.description,
      parameters: spec.parameters,
      execute,
    };
  }

  return { defineGovernedTool };
}
