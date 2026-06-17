import { test } from "node:test";
import assert from "node:assert/strict";
import { hostContextResolver } from "../src/flue.js";
import { createGovernedToolkit } from "../src/toolkit.js";
import { InMemoryAuditLog } from "../src/audit.js";
import { MissingContextError } from "../src/errors.js";
import type { TrustedContext } from "../src/types.js";

test("hostContextResolver extracts trusted context from a runtime host object", async () => {
  // For non-Flue runtimes that pass a context object into execute as 2nd arg.
  // (Flue itself passes an AbortSignal, so under Flue you'd use ContextStore.)
  interface RuntimeHost {
    session: { userId: string; tenant: string };
  }
  const resolver = hostContextResolver<RuntimeHost>((host) => ({
    actor: { id: host.session.userId, roles: ["agent"] },
    tenantId: host.session.tenant,
    scopes: ["customer:*"],
  }));

  const audit = new InMemoryAuditLog();
  const toolkit = createGovernedToolkit({ context: resolver, audit });
  const tool = toolkit.defineGovernedTool({
    name: "lookup",
    description: "l",
    execute: (_a, ctx) => ({ tenant: ctx.tenantId, actor: ctx.actor.id }),
  });

  const host: RuntimeHost = { session: { userId: "u-7", tenant: "globex" } };
  const result = (await tool.execute({}, host)) as TrustedContext extends never
    ? never
    : { tenant: string; actor: string };
  assert.deepEqual(result, { tenant: "globex", actor: "u-7" });

  const entries = await audit.entries();
  assert.equal(entries[0]!.tenantId, "globex");
  assert.equal(entries[0]!.actorId, "u-7");
});

test("hostContextResolver throws if no host context is provided", () => {
  const resolver = hostContextResolver<{ x: number }>((h) => ({
    actor: { id: "a", roles: [] },
    tenantId: String(h.x),
    scopes: [],
  }));
  assert.throws(() => resolver(undefined), MissingContextError);
});
