/**
 * Shared types for flue-governed-tools.
 *
 * The design separates two things frameworks like Flue keep coupled:
 *   - The LLM-facing **arguments** of a tool call (the model controls these).
 *   - The **trusted context** of the caller — actor, tenant, allowed scopes —
 *     which is injected by your harness and can never be set by the model.
 *
 * Flue gates *what* a tool can do by harness state. This library gates *who*
 * may do it, *for which tenant*, with *what side-effect guarantee*.
 */

/** The trusted, harness-injected execution context for a tool call. */
export interface TrustedContext {
  /** The principal on whose behalf the agent is acting. */
  actor: {
    id: string;
    /** Roles used by the default RBAC adapter. */
    roles: string[];
  };
  /** The tenant this run is bound to. Used for hard multi-tenant isolation. */
  tenantId: string;
  /**
   * Resource scopes the actor is permitted to touch, e.g.
   * `["customer:c-123", "ticket:*"]`. A `*` matches any run of characters.
   */
  scopes: string[];
  /** Correlation id for the surrounding request/run. */
  requestId?: string;
  /** Free-form attributes available to tool handlers and adapters. */
  attributes?: Record<string, unknown>;
}

/**
 * A validator for tool arguments. Anything zod-like (an object with a `parse`
 * method) works directly, and a plain function is also accepted. Omitting a
 * validator passes arguments through unchanged.
 */
export type ArgValidator<T> =
  | { parse: (input: unknown) => T }
  | ((input: unknown) => T);

/** The context handed to a governed tool's `execute` handler. */
export interface ExecutionContext extends TrustedContext {
  /** The resource scopes this specific call was authorized against. */
  authorizedScopes: string[];
  /** The raw context object passed in by the host framework, if any. */
  host?: unknown;
}

/** Result of a governance decision, recorded in the audit log. */
export type Decision = "allow" | "deny";

/** Outcome of a tool invocation, recorded in the audit log. */
export type Outcome = "success" | "error" | "denied" | "replayed";

/**
 * A tool object shaped to be accepted by Flue's `init({ tools })` (and most
 * MCP-style runtimes): a name, a description, a parameter schema and an
 * `execute` function.
 */
export interface FlueCompatibleTool {
  name: string;
  description: string;
  parameters: unknown;
  execute: (args: unknown, hostContext?: unknown) => Promise<unknown>;
}
