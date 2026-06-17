/**
 * Error types raised by the governance layer.
 *
 * All extend {@link GovernanceError} so callers (and the agent harness) can
 * distinguish a governance rejection from an ordinary handler failure.
 */

export class GovernanceError extends Error {
  /** Machine-readable code, e.g. `"scope_violation"`. */
  readonly code: string;
  /** The tool the decision applied to, when known. */
  readonly tool?: string;

  constructor(code: string, message: string, tool?: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.tool = tool;
  }
}

/** No trusted context was available when a governed tool was invoked. */
export class MissingContextError extends GovernanceError {
  constructor(tool?: string) {
    super(
      "missing_context",
      "No trusted context was resolved for this tool call. A governed tool " +
        "must run inside a context (see ContextStore.run / the toolkit's " +
        "`context` resolver).",
      tool,
    );
  }
}

/** The actor lacked a required role. */
export class AccessDeniedError extends GovernanceError {
  readonly requiredRoles: string[];

  constructor(tool: string, requiredRoles: string[]) {
    super(
      "access_denied",
      `Actor is not permitted to call "${tool}". Requires one of: ` +
        requiredRoles.join(", "),
      tool,
    );
    this.requiredRoles = requiredRoles;
  }
}

/** The call targeted a resource outside the actor's allowed scopes. */
export class ScopeViolationError extends GovernanceError {
  readonly requested: string[];
  readonly allowed: string[];

  constructor(tool: string, requested: string[], allowed: string[]) {
    super(
      "scope_violation",
      `"${tool}" attempted to act on scope(s) [${requested.join(", ")}] ` +
        `outside the actor's allowed scopes [${allowed.join(", ")}].`,
      tool,
    );
    this.requested = requested;
    this.allowed = allowed;
  }
}

/** Human (or external) approval was required and not granted. */
export class ApprovalDeniedError extends GovernanceError {
  constructor(tool: string, reason?: string) {
    super(
      "approval_denied",
      `"${tool}" requires approval which was not granted` +
        (reason ? `: ${reason}` : "."),
      tool,
    );
  }
}

/** A concurrent call holds the same idempotency key. */
export class IdempotencyConflictError extends GovernanceError {
  readonly key: string;

  constructor(tool: string, key: string) {
    super(
      "idempotency_conflict",
      `Another in-flight call to "${tool}" already holds idempotency key ` +
        `"${key}".`,
      tool,
    );
    this.key = key;
  }
}
