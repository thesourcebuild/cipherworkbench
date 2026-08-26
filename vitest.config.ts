import { defineConfig } from "vitest/config";

/**
 * One suite at the repo root, exercising every package through its public entry
 * point rather than reaching into `src/`. That means the tests break if an export
 * is dropped from a package's index, which is exactly the contract the apps depend on.
 *
 * `environment: "node"` is fine even though the compute code targets browsers:
 * Node 20+ exposes `globalThis.crypto` (WebCrypto), which is the only host API
 * any algorithm here is allowed to reach for.
 */
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    reporters: ["default"],
    /**
     * Raised from the 5s default, because several tests here walk *every registered tool*.
     *
     * `tests/registry.test.ts` loads all 273 lazily-imported definitions and computes each one; on its
     * own that is about three seconds, and under the contention of the whole suite running in parallel
     * it crossed five. The failure was a timeout rather than an assertion, which reads as a broken test
     * rather than a slow one -- and the number of tools only goes up.
     *
     * Per-file timeouts were the alternative and are worse: the tests that need this are spread across
     * files and the list would drift. Nothing here is expected to take minutes, so a generous ceiling
     * costs nothing and a genuine hang still fails.
     */
    testTimeout: 60_000,
  },
});
