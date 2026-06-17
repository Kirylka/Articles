import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GovernanceError,
  MissingContextError,
  AccessDeniedError,
  ScopeViolationError,
  ApprovalDeniedError,
  IdempotencyConflictError,
} from "../src/errors.js";

test("all governance errors extend GovernanceError and carry a code", () => {
  const errors: GovernanceError[] = [
    new MissingContextError("t"),
    new AccessDeniedError("t", ["admin"]),
    new ScopeViolationError("t", ["customer:b"], ["customer:a"]),
    new ApprovalDeniedError("t", "too big"),
    new IdempotencyConflictError("t", "k1"),
  ];
  for (const err of errors) {
    assert.ok(err instanceof GovernanceError);
    assert.ok(err instanceof Error);
    assert.equal(typeof err.code, "string");
    assert.ok(err.code.length > 0);
    assert.equal(err.tool, "t");
  }
});

test("errors expose machine codes and structured fields", () => {
  assert.equal(new MissingContextError().code, "missing_context");
  assert.equal(new AccessDeniedError("t", ["a"]).code, "access_denied");

  const scope = new ScopeViolationError("refund", ["customer:b"], ["customer:a"]);
  assert.equal(scope.code, "scope_violation");
  assert.deepEqual(scope.requested, ["customer:b"]);
  assert.deepEqual(scope.allowed, ["customer:a"]);

  const conflict = new IdempotencyConflictError("refund", "key-1");
  assert.equal(conflict.code, "idempotency_conflict");
  assert.equal(conflict.key, "key-1");
});
