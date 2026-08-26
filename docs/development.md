# Development

## Requirements

- **Node.js**: `>=20.11` (developed and verified against Node 24.x)
- **pnpm**: `10.x` — pinned via `packageManager` (`pnpm@10.34.5`). Install `pnpm` if you have not done already:
  ```sh
  npm install -g pnpm@10
  ```

## Commands

| Command | What it does |
|---|---|
| `pnpm install` | Install the monorepo workspace dependencies |
| `pnpm test` | Vitest over [`tests/`](../tests/) (3,924 tests across 84 files) |
| `pnpm test:watch` | Run Vitest in interactive watch mode |
| `pnpm typecheck` | `tsc --noEmit` across all workspace packages and `tests/` |
| `pnpm lint` | ESLint across the monorepo |
| `pnpm build` | Web static export to `apps/web/out`, then desktop bundle |
| `pnpm web` | Next.js dev server on http://localhost:3000 |
| `pnpm desktop` | Electron against the dev server (`pnpm web`), with HMR |
| `pnpm win:version` | Sync all workspace `package.json` manifests to root `version` file (`-Set X.Y.Z` to bump, `-Check` to verify) |
| `pnpm sh:version` | Linux/macOS version sync (`--set X.Y.Z` to bump, `--check` to verify) |
| `pnpm win:verify` | Run script check, typecheck, lint, test, build, and desktop smoke check |
| `pnpm win:package` | Create Windows installers and web zip into `dist/<version>/` |
| `pnpm sh:package` | Create Linux packages (.AppImage, .deb), web zip, and source zip |
| `pnpm --filter @ocs/desktop smoke` | Headless check that the packaged desktop renderer loads |

### Tests

The entire test suite lives in [`tests/`](../tests/) at the repository root. Tests consume shared packages (`@ocs/engine`, `@ocs/algos`, `@ocs/contracts`, `@ocs/registry`, `@ocs/cipher`, `@ocs/hash`, etc.) through public entry points to ensure exported APIs remain unbroken.

### Ground Truth & Differential Oracles

Cipher Workbench verifies algorithms against reference implementations and native oracles:

- **OpenSSL Parity (`tests/openssl-parity.test.ts`)**: Differential testing against `node:crypto` (OpenSSL) covering 55 hash digests, HMACs, and RSA signatures across 15 hashes.
- **Reference WASM Oracles (`tests/algos-xxhash-oracle.test.ts`)**: Differential verification of XXH3-64 and XXH3-128 against reference `hash-wasm` output across 600 length cases.
- **RevEng CRC Catalogue (`tests/crc-tool.test.ts` & `tests/algos-crc.test.ts`)**: Validates 113 named CRC models and widths 3 to 82 against RevEng definitions.
- **NIST & Standard Test Vectors (`tests/algos-*.test.ts`)**: Test vectors for FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), AEAD modes, Argon2, scrypt, and NIST LWC finalists.

The monorepo build order is **web export → renderer copy → desktop main bundle**. `@ocs/web` is declared as a devDependency of `apps/desktop` so Turborepo enforces build ordering.

## Things that will bite you

**Version mismatches across manifests.** The root `version` file is the single source of truth. Manually editing `version` leaves the 22 workspace `package.json` files out of sync, causing `pnpm win:version -Check` to fail in CI. Always bump using `pnpm win:version -Set X.Y.Z` (or `pnpm sh:version --set X.Y.Z`), or run `pnpm win:version` after updating the `version` file.

**`ELECTRON_RUN_AS_NODE`.** VS Code's extension host exports this, and it leaks into the integrated terminal. With it set, `electron .` runs as plain Node, `require("electron")` returns a stub, and the app dies with `Cannot read properties of undefined (reading 'registerSchemesAsPrivileged')`. `apps/desktop/scripts/run-electron.mjs` strips it, which is why every Electron launcher goes through that script.

**Electron's binary download & tsup build.** electron 43 ships no postinstall script — the binary is fetched the first time something `require("electron")`s it. `apps/desktop/scripts/ensure-electron.mjs` runs electron's idempotent `install.js` once before tsup starts to prevent parallel build watchers from racing each other during download.

**Extensionless relative imports.** Shared packages are consumed as TypeScript source. Relative imports omit extensions and rely on `moduleResolution: "bundler"`.

**`pnpm approve-builds`.** pnpm blocks postinstall scripts unless a package is listed in `pnpm-workspace.yaml`. `electron`, `esbuild`, `vitest`, and `@img/sharp` native bindings are approved in `pnpm-workspace.yaml`.

**Antivirus vs. electron-builder.** On Windows machines, real-time scanning can hold a lock on extracted Electron binaries inside the project tree, failing with `EPERM: rename ... win-unpacked.tmp`. Packaging sets `OCS_RELEASE_DIR` to a versioned folder under `TEMP` so electron-builder builds outside the repository tree.

**Installers are not code-signed.** electron-builder produces unsigned installers by default. Every release writes a `SHA256SUMS.txt` and `RELEASE.md` into `dist/<version>/` so recipients can verify installer integrity.

## Engine & Cryptographic Safety

- **Text Character Encodings**: Text inputs support 40 character encodings (UTF-8, UTF-16, ISO-8859 set, Windows code pages, Shift_JIS, GBK, EUC-KR) so digests over non-ASCII text match exact byte expectations.
- **Unbiased Randomness**: Random numbers and random bytes use `crypto.getRandomValues` with rejection sampling, avoiding modulo bias.
- **Diagnostic Engine Rules**: Diagnostics flag insecure key lengths, zero IVs, unauthenticated cipher modes, and CRC model parameter mismatches with rule codes (e.g. C001, H002, CRC001, K007).
