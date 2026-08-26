/**
 * electron-builder configuration.
 *
 * JS rather than YAML so the output directory can be redirected with
 * OCS_RELEASE_DIR. That matters on machines where real-time antivirus holds a lock
 * on the freshly extracted Electron binaries inside the project tree —
 * electron-builder then fails with `EPERM: rename win-unpacked.tmp` — and it lets CI
 * put artifacts wherever it wants without editing tracked config.
 */
const fs = require("node:fs");
const path = require("node:path");

/**
 * The root `version` file is the single source of truth for the project version.
 *
 * Without `extraMetadata` electron-builder reads the version from *this* package's package.json, so
 * the installer name, `app.getVersion()` -- which is what the footer and the About box show -- and
 * the release folder `create-package.ps1` writes into could all disagree with each other. Overriding
 * it here means one file decides all three, and it holds even when electron-builder is invoked
 * directly rather than through the packaging script.
 */
const projectVersion = fs.readFileSync(path.join(__dirname, "../../version"), "utf8").trim();

module.exports = {
  appId: "com.cipherworkbench.app",
  extraMetadata: { version: projectVersion },
  productName: "Cipher Workbench",
  // Same year and holder as the renderer's footer, which is a pinned constant for this reason.
  copyright: "Copyright © 2026 Muhammad Hassaan Shah",

  directories: {
    output: process.env.OCS_RELEASE_DIR || "release",
    buildResources: "resources",
  },

  /**
   * The bundled main/preload and the copied static renderer, and nothing else.
   *
   * There is no `node_modules` entry and no `asarUnpack`, which is worth noticing:
   * this app has no native module to leave outside the archive. Every algorithm is
   * pure ESM, so tsup inlines the entire dependency graph and the shipped tree is
   * just JavaScript plus the static export.
   */
  files: ["dist/**/*", "renderer/**/*", "package.json"],

  asar: true,

  win: {
    target: [{ target: "nsis", arch: ["x64", "arm64"] }],
    // Deliberately not ${productName}: keeping the artifact name free of spaces
    // keeps the .blockmap paired with its installer, which auto-update relies on,
    // and avoids quoting problems in URLs and CI scripts.
    artifactName: "cipherworkbench-setup-${version}-${arch}.${ext}",
  },

  nsis: {
    oneClick: false,
    allowToChangeInstallationDirectory: true,
    perMachine: false,
  },

  mac: {
    category: "public.app-category.utilities",
    target: [
      { target: "dmg", arch: ["arm64", "x64"] },
      { target: "zip", arch: ["arm64", "x64"] },
    ],
    // Required for a notarised build; harmless before signing is configured.
    hardenedRuntime: true,
    gatekeeperAssess: false,
  },

  linux: {
    category: "Utility",
    target: [
      { target: "AppImage", arch: ["x64"] },
      { target: "deb", arch: ["x64"] },
    ],
  },
};
