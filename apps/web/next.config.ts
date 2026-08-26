import fs from "node:fs";
import path from "node:path";
import type { NextConfig } from "next";

/**
 * The root `version` file is the single source of truth for the project version.
 *
 * Read here rather than through `process.env.npm_package_version`, which is whichever manifest the
 * runner happened to be launched in -- `pnpm build` at the root gives the root's, `pnpm --filter
 * @ocs/web build` gives this package's -- so the number in the footer depended on how the build was
 * started. And the `?? "0.1.0"` fallback it had was worse than the ambiguity: a literal that could
 * not be bumped and would silently disagree with the installer beside it.
 *
 * This is a build config rather than a tool package, so `node:fs` is fine here.
 */
const projectVersion = fs.readFileSync(path.join(__dirname, "../../version"), "utf8").trim();

/**
 * One static bundle serves both targets: a browser loads it from a static host,
 * Electron loads the same `out/` directory over its own app:// protocol. Because
 * the desktop shell registers a real origin rather than using file://, no
 * assetPrefix divergence is needed and there is only one build of the UI.
 *
 * That constraint is what makes the whole architecture work, and it is why every
 * algorithm in this repo is pure ESM with no native module anywhere: a bundle
 * that needed a `.node` binary could not be the same bundle in both places.
 */
/**
 * The GitHub Pages subpath, and it is *only* ever set for the web deploy.
 *
 * A Pages project site is served from `https://<user>.github.io/<repo>/`, so every asset URL needs that
 * prefix or the page loads a bare HTML document with 404s for all of its JavaScript. `basePath` is how
 * Next adds it -- and it is exactly what the desktop build must not have, because the Electron shell
 * serves the same `out/` directory from `app://bundle/` with no prefix at all.
 *
 * So it is an environment variable, empty by default. `pnpm build` produces the bundle Electron loads;
 * the Pages workflow sets `NEXT_PUBLIC_BASE_PATH=/CipherWorkbench` and produces the one the site loads.
 * One config, one codebase, two invocations -- which keeps the "one static bundle serves both targets"
 * property above true in the only sense that matters: nothing about the *application* differs.
 *
 * If the site ever moves to a custom domain or a `<user>.github.io` repository, this goes back to empty
 * and nothing else changes.
 */
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

const config: NextConfig = {
  output: "export",
  reactStrictMode: true,
  /**
   * Directory-style URLs, which is what a static host serves without rewrites.
   *
   * `/tools/sha256/` becomes `out/tools/sha256/index.html`, and GitHub Pages resolves that with no
   * configuration. Without it the export writes `tools/sha256.html`, which Pages will serve only at
   * that exact `.html` path -- so every canonical URL and every sitemap entry would have to carry the
   * extension, and a link without one would 404.
   */
  trailingSlash: true,
  ...(BASE_PATH === "" ? {} : { basePath: BASE_PATH, assetPrefix: BASE_PATH }),
  images: { unoptimized: true },
  transpilePackages: [
    "@ocs/algos",
    "@ocs/asymmetric",
    "@ocs/checksum",
    "@ocs/cipher",
    "@ocs/classical",
    "@ocs/contracts",
    "@ocs/crc",
    "@ocs/encoding",
    "@ocs/encodings",
    "@ocs/engine",
    "@ocs/format",
    "@ocs/hash",
    "@ocs/kdf",
    "@ocs/mac",
    "@ocs/parity",
    "@ocs/platform",
    "@ocs/registry",
    "@ocs/ui",
  ],
  env: {
    NEXT_PUBLIC_APP_VERSION: projectVersion,
  },
  /**
   * Next 16 writes `AGENTS.md` and a `CLAUDE.md` pointing at it into this directory on every dev
   * run, unasked. Turned off because those files are actively harmful here, not merely noise:
   * a `CLAUDE.md` is read as project instructions by anything working in `apps/web`, and Next's
   * generic Next guidance would sit *closer* to the files being edited than the repo's own
   * `CLAUDE.md` at the root — which is the one that knows about the manifest/definition split,
   * the `--webpack` pin and why this app has no per-tool React. Two sets of instructions where
   * the wrong one wins by proximity is worse than one.
   */
  agentRules: false,
};

export default config;
