/**
 * Flue integration adapter.
 *
 * This is the ONLY module that is aware of how Flue calls a tool; the
 * governance core has no Flue dependency.
 *
 * Flue (`@flue/runtime`) defines tools with `defineTool({ name, description,
 * parameters, execute })`, where `parameters` is a Valibot/TypeBox schema that
 * Flue converts to JSON Schema and validates model arguments against before
 * calling `execute(args)`. A governed tool produced by
 * {@link createGovernedToolkit} has exactly that shape, so you pass it straight
 * through Flue's `defineTool` and into `init({ tools })`:
 *
 * ```ts
 * import { defineTool, init } from "@flue/runtime";
 * import * as v from "valibot";
 * import { createGovernedToolkit, ContextStore, HashChainAuditLog }
 *   from "flue-governed-tools";
 *
 * const ctx = new ContextStore();
 * const toolkit = createGovernedToolkit({
 *   context: ctx.resolver(),
 *   audit: new HashChainAuditLog({ path: "audit.jsonl" }),
 * });
 *
 * const refund = defineTool(
 *   toolkit.defineGovernedTool({
 *     name: "issue_refund",
 *     description: "Issue a refund.",
 *     parameters: v.object({ customerId: v.string(), amount: v.number() }),
 *     sideEffect: true,
 *     scope: (a) => `customer:${a.customerId}`,
 *     execute: (a, gctx) => billing.refund(gctx.tenantId, a.customerId, a.amount),
 *   }),
 * );
 *
 * // Bind trusted context for the run; the model never sees or sets it.
 * await ctx.run(trustedContext, () => init({ model, tools: [refund] }));
 * ```
 *
 * Flue's `FlueContext` (`{ id, payload, env, req, log, ... }`) lives in the
 * surrounding `run` scope, which is why `ContextStore` (AsyncLocalStorage) is
 * the recommended way to supply trusted context. If your runtime instead hands
 * a context object to `execute`, use {@link hostContextResolver}.
 */

import type { ContextResolver } from "./context.js";
import { MissingContextError } from "./errors.js";
import type { TrustedContext } from "./types.js";

/**
 * Build a {@link ContextResolver} that derives the trusted context from the
 * host object Flue passes into `execute`. Throws {@link MissingContextError}
 * (fail-closed) if no host context is available.
 */
export function hostContextResolver<H>(
  extract: (host: H) => TrustedContext | Promise<TrustedContext>,
): ContextResolver {
  return (hostContext?: unknown) => {
    if (hostContext == null) throw new MissingContextError();
    return extract(hostContext as H);
  };
}
