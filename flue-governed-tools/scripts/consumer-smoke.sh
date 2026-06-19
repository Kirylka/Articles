#!/usr/bin/env bash
# Packed-tarball consumer smoke test.
#
# Packs the package and installs the *tarball* (not the working tree) into a
# throwaway consumer project alongside only its real dependencies, then both
# type-checks and runs a consumer against the published `exports` map. This
# catches what `npm test` (which runs against src) can't: a broken export map, a
# missing dist file, types that don't resolve for a consumer, or an accidental
# reliance on a dev dependency.
set -euo pipefail

pkg_dir="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$pkg_dir"
# `npm pack` runs prepack (build); grab the tarball name from stdout.
tarball="$pkg_dir/$(npm pack --silent | tail -n1)"
echo "packed: $(basename "$tarball")"

cd "$work"
npm init -y >/dev/null
npm pkg set type=module >/dev/null
# Install the tarball plus only the documented peer/runtime deps — no dev deps.
npm install --no-audit --no-fund --loglevel=error \
  "$tarball" @flue/runtime valibot typescript >/dev/null
echo "installed tarball + peers into a clean consumer"

# Shared consumer body (no type annotations, so it runs as plain ESM too).
read -r -d '' BODY <<'JS' || true
import * as v from "valibot";
import { govern, caller, AuthorizationDeniedError } from "flue-governed-tools";
import { InMemoryAuditLog } from "flue-governed-tools/testing";
import { verifyChain } from "flue-governed-tools/audit";
import { toFlueTool } from "flue-governed-tools/adapters";
import assert from "node:assert/strict";

void toFlueTool; // proves the /adapters subpath resolves

const audit = new InMemoryAuditLog();
const gov = govern({ audit });

const reset = gov.tool({
  name: "reset_password",
  description: "Send a password reset link.",
  parameters: v.object({ accountId: v.string() }),
  sideEffect: true,
  authorize: caller((a, ctx) => a.accountId === ctx.actor.id),
  execute: (a) => `sent:${a.accountId}`,
});

const ok = await gov.run(
  { actor: { id: "u1", roles: [] }, tenantId: "t" },
  () => reset.execute({ accountId: "u1" }),
);
assert.equal(ok, "sent:u1");

let denied = false;
try {
  await gov.run(
    { actor: { id: "u1", roles: [] }, tenantId: "t" },
    () => reset.execute({ accountId: "victim" }),
  );
} catch (err) {
  denied = err instanceof AuthorizationDeniedError;
}
assert.ok(denied, "a cross-account reset must be denied");

const result = await verifyChain(await audit.entries());
assert.ok(result.valid, "the audit chain must verify");

console.log("consumer smoke: OK");
JS

printf '%s\n' "$BODY" > consumer.mjs
printf '%s\n' "$BODY" > consumer.ts

cat > tsconfig.json <<'JSON'
{
  "compilerOptions": {
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "target": "ES2022",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true,
    "types": ["node"]
  },
  "include": ["consumer.ts"]
}
JSON

# 1) Types resolve for a consumer through the package's exports map.
echo "type-checking the consumer..."
npx --no-install tsc -p tsconfig.json

# 2) The quickstart actually runs from the installed tarball.
echo "running the consumer..."
node consumer.mjs

echo "✅ packed-tarball consumer smoke test passed"
