/**
 * Runtime-parity check: boot the worker on the real workerd runtime (via
 * wrangler's unstable_dev) with `nodejs_compat`, and assert the governance core
 * actually runs there — not just on Node. Kept out of the default `npm test`
 * (it downloads/launches workerd); run it with `npm run test:worker`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { unstable_dev } from "wrangler";

test("governance core runs on workerd under nodejs_compat", async () => {
  const worker = await unstable_dev("test/worker/worker.mjs", {
    experimental: { disableExperimentalWarning: true },
    compatibilityDate: "2024-09-23",
    compatibilityFlags: ["nodejs_compat"],
  });
  try {
    const res = await worker.fetch("http://example.com/");
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, "sent:u1", "own-account reset runs (AsyncLocalStorage works)");
    assert.equal(body.denied, true, "cross-account reset is denied");
    assert.equal(body.chainValid, true, "Web Crypto hash chain verifies on workerd");
    assert.match(body.runtime, /Cloudflare-Workers/, "actually ran on workerd");
  } finally {
    await worker.stop();
  }
});
