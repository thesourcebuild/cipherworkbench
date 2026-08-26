import { defineConfig } from "tsup";

/**
 * Main and preload are bundled rather than compiled file-by-file. That lets them
 * import the workspace packages as TypeScript source with no per-package build
 * step, and sidesteps ESM/CJS interop entirely.
 *
 * Both outputs are CJS: a sandboxed preload script MUST be CommonJS, and there is
 * nothing to gain from ESM in the main process here.
 *
 * `electron` is the only external. Unlike the command generator this shell is
 * adapted from, there is no native module to leave outside the bundle — this app
 * spawns nothing and has no `node-pty`, so `external` is a one-item list and
 * electron-builder needs no `asarUnpack` at all.
 */
const shared = {
  outDir: "dist",
  // Not `as const`: tsup's `Options.format` is a mutable `Format[]`, and a readonly
  // tuple is not assignable to it.
  format: ["cjs"] as ("cjs" | "esm" | "iife")[],
  platform: "node" as const,
  target: "node20",
  // tsup externalises package.json `dependencies` by default, which would leave
  // the output require()-ing the workspace packages' raw TS source.
  external: ["electron"],
  noExternal: [/^@ocs\//, "zod"],
  outExtension: () => ({ js: ".cjs" }),
  sourcemap: true,
  // Cleaning is done by the npm script: these two configs run concurrently, so
  // letting either one clean `dist` can delete the other's freshly written output.
  clean: false,
  bundle: true,
};

export default defineConfig([
  { ...shared, entry: { "main/index": "src/main/index.ts" } },
  { ...shared, entry: { "preload/index": "src/preload/index.ts" } },
]);
