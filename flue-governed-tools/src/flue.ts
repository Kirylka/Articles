/**
 * Flue integration adapter.
 *
 * This is the ONLY module that is aware of how Flue calls a tool; the
 * governance core has no Flue dependency. A governed tool produced by
 * {@link createGovernedToolkit} is already shaped for Flue's
 * `init({ tools: [...] })` — `{ name, description, parameters, execute }` — so
 * it can be passed alongside MCP and command tools without adaptation.
 *
 * The one Flue-specific concern handled here is resolving the trusted context
 * from the host object Flue passes as the second argument to `execute` (e.g. a
 * session derived from the authenticated request that started the run). Use
 * {@link hostContextResolver} when you prefer reading context off that host
 * object instead of using `ContextStore`/`AsyncLocalStorage`.
 *
 * Usage:
 * ```ts
 * const toolkit = createGovernedToolkit({
 *   context: hostContextResolver((host) => deriveTrustedContext(host)),
 *   audit: new HashChainAuditLog({ path: "audit.jsonl" }),
 * });
 * const tools = [toolkit.defineGovernedTool(refundSpec)];
 * const agent = await init({ model, tools });
 * ```
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
