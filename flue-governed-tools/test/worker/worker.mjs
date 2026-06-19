/**
 * A Cloudflare Worker that exercises the governance core end to end, so the test
 * harness can prove it runs on the real workerd runtime under `nodejs_compat`:
 *   - the built-in ContextStore / gov.run path → node:async_hooks (AsyncLocalStorage)
 *   - the hash-chained audit → Web Crypto (crypto.subtle)
 *   - authorize gating + a tamper-evident chain that verifies
 *
 * Imports the built dist directly (no @flue/runtime), to isolate this package's
 * own edge compatibility from Flue's.
 */
import {
  createGovernedToolkit,
  caller,
  AuthorizationDeniedError,
} from "../../dist/src/index.js";
import { InMemoryAuditLog } from "../../dist/src/testing.js";
import { verifyChain } from "../../dist/src/audit.js";

export default {
  async fetch() {
    const audit = new InMemoryAuditLog();
    const gov = createGovernedToolkit({ audit }); // built-in AsyncLocalStorage store

    const reset = gov.defineGovernedTool({
      name: "reset_password",
      description: "Send a reset link.",
      sideEffect: true,
      authorize: caller((a, ctx) => a.accountId === ctx.actor.id),
      idempotency: { key: (a) => a.accountId },
      execute: (a) => `sent:${a.accountId}`,
    });

    const principal = { actor: { id: "u1", roles: [] }, tenantId: "t" };

    const ok = await gov.run(principal, () => reset.execute({ accountId: "u1" }));

    let denied = false;
    try {
      await gov.run(principal, () => reset.execute({ accountId: "victim" }));
    } catch (err) {
      denied = err instanceof AuthorizationDeniedError;
    }

    const chain = await verifyChain(await audit.entries());

    return Response.json({
      ok,
      denied,
      chainValid: chain.valid,
      entries: (await audit.entries()).length,
      // Present only on the real Workers runtime — proves we're on workerd.
      runtime: globalThis.navigator?.userAgent ?? "unknown",
    });
  },
};
