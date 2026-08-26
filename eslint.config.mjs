import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

/**
 * Two project-specific bans carry real weight here, and both exist for the
 * same reason: every algorithm in this repo must produce identical bytes in a
 * browser tab, in an Electron renderer, and under vitest in Node.
 *
 *  - `node:crypto` / `crypto` would satisfy the typechecker and pass the test
 *    suite while breaking the web build outright. Compute code uses `@noble/*`,
 *    `@scure/*`, `@ocs/algos`, or `globalThis.crypto` (WebCrypto — present in
 *    all three hosts) instead.
 *  - `Math.random` is not a CSPRNG. Keys, IVs, nonces, salts and generated
 *    passwords come from `crypto.getRandomValues`, never from it. The ban is
 *    scoped to the packages that actually generate such material so UI jitter
 *    or a test fixture elsewhere is unaffected.
 */
export default tseslint.config(
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/out/**",
      "**/.next/**",
      "**/renderer/**",
      "**/release/**",
      "**/*.d.ts",
      // Vendored third-party source. Kept diffable against upstream rather than reformatted or
      // relinted; the two files carry `/* eslint-disable */` as well, and this makes it explicit.
      "packages/encodings/src/vendor/**",
    ],
  },
  ...tseslint.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/consistent-type-imports": "warn",
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "electron",
              message:
                "Renderer and shared packages must never import electron. Use @ocs/platform.",
            },
            {
              name: "child_process",
              message: "This app computes in-process. It never spawns anything.",
            },
            {
              name: "node:child_process",
              message: "This app computes in-process. It never spawns anything.",
            },
            {
              name: "crypto",
              message:
                "Node's crypto module does not exist in a browser. Use @noble/*, @scure/*, @ocs/algos, or globalThis.crypto (WebCrypto).",
            },
            {
              name: "node:crypto",
              message:
                "Node's crypto module does not exist in a browser. Use @noble/*, @scure/*, @ocs/algos, or globalThis.crypto (WebCrypto).",
            },
          ],
        },
      ],
    },
  },
  {
    /**
     * Two hook rules, not the plugin's whole recommended set.
     *
     * `exhaustive-deps` is the one that earns its place: `use-compute.ts`
     * deliberately depends on a serialised spec rather than the object, and
     * deliberately omits the spec from the file-input effect so that changing a
     * setting does not re-read a multi-gigabyte file. Both are real decisions, and
     * with this rule on they have to be written down as justified `eslint-disable`
     * lines instead of being invisible. The rest of the v7 rule set is
     * React-Compiler guidance this codebase has not opted into.
     */
    files: ["apps/web/**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
    },
  },
  {
    // Where key/IV/nonce/salt material is actually produced.
    files: [
      "packages/algos/**/*.ts",
      "packages/tools/**/*.ts",
      "packages/cipher-engine/**/*.ts",
    ],
    rules: {
      "no-restricted-properties": [
        "error",
        {
          object: "Math",
          property: "random",
          message:
            "Math.random is not cryptographically secure. Use randomBytes() from @ocs/engine, which wraps crypto.getRandomValues.",
        },
      ],
      /**
       * The DOM, banned by rule rather than by the absence of its types.
       *
       * These packages used to be typechecked without `lib.dom`, which made reaching
       * for `document` a compile error for free. That stopped being possible when
       * @ocs/asymmetric needed SubtleCrypto's types — `CryptoKey`, `RsaPssParams`,
       * `JsonWebKey` — which TypeScript declares in lib.dom and @types/node does not.
       * Widening the lib brought the whole DOM with it, so the guard moves here.
       *
       * `crypto` is deliberately absent from this list: WebCrypto is present in a
       * browser tab, an Electron renderer and Node 20+ alike, and is the sanctioned
       * source of random bytes and of RSA.
       */
      "no-restricted-globals": [
        "error",
        {
          name: "document",
          message: "Compute code must not touch the DOM. It also runs in a Worker and in Node.",
        },
        {
          name: "window",
          message: "Compute code must not touch the DOM. It also runs in a Worker and in Node.",
        },
        {
          name: "localStorage",
          message: "Persistence belongs to the app layer, not to a tool package.",
        },
        {
          name: "navigator",
          message: "A tool's output must not depend on the host it happens to run in.",
        },
      ],
    },
  },
  {
    /**
     * `tests/` may import `node:crypto`, and only as a differential oracle.
     *
     * The global ban exists because `node:crypto` does not exist in a browser and the same
     * bundle has to run in both. A test does not ship, runs only under vitest in Node, and
     * has the same standing as the `xxhash-wasm` and `@noble/hashes`-hmac oracles already
     * used here: an independent implementation to check ours against. Node's is OpenSSL,
     * which makes it the best available reference for exactly the algorithms OpenSSL names
     * — see `tests/openssl-parity.test.ts`.
     *
     * The scope is the point. Nothing under `packages/` or `apps/` gets this exemption, so
     * an import copied out of a test into real code still fails.
     */
    files: ["tests/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "crypto",
              message:
                "Use the explicit node:crypto specifier in tests, so the Node-only dependency is visible at a glance.",
            },
            {
              name: "child_process",
              message: "This app computes in-process. It never spawns anything.",
            },
            {
              name: "node:child_process",
              message: "This app computes in-process. It never spawns anything.",
            },
          ],
        },
      ],
    },
  },
  {
    /**
     * The Electron main and preload processes are the one place electron may be
     * imported, and the one place `node:crypto` is legitimate.
     *
     * The global ban on `node:crypto` exists because it does not exist in a browser
     * and the same bundle has to run in both — a reason that simply does not apply
     * to the main process, which is Node and only Node. It is used there for exactly
     * one thing: hashing the renderer's inline `<script>` bodies so the CSP can
     * allowlist them by digest instead of falling back to 'unsafe-inline'. No
     * algorithm the *app* offers is ever computed here.
     *
     * `child_process` stays banned even here.
     */
    files: ["apps/desktop/src/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "child_process",
              message: "No process spawning anywhere in this project.",
            },
            {
              name: "node:child_process",
              message: "No process spawning anywhere in this project.",
            },
          ],
        },
      ],
    },
  },
  {
    /**
     * `.cjs` build configuration, where `require` is the only import there is.
     *
     * One file: `apps/desktop/electron-builder.config.cjs`. It is `.cjs` rather than YAML so the
     * output directory can be redirected with an environment variable, and it reads the root
     * `version` file so the installer name and `app.getVersion()` cannot disagree with it -- both of
     * which need `node:fs` and `node:path` at config-load time. `no-require-imports` is aimed at the
     * ESM sources that make up the rest of the repo; here it forbids the only syntax available.
     *
     * Scoped to `*.cjs` rather than disabled inline so a second such config gets the same treatment
     * without a comment, and so nothing else can quietly become CommonJS to escape the rule.
     */
    files: ["**/*.cjs"],
    rules: {
      "@typescript-eslint/no-require-imports": "off",
    },
  },
);
