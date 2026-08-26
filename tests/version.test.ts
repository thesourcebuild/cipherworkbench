import { readFileSync, readdirSync, existsSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

/**
 * The root `version` file is the single source of truth for the project version.
 *
 * Four things read it, and the point of the file is that they cannot disagree:
 *
 *  - `Get-ProjectVersion` in `scripts/lib/common.ps1`, which names the release folder, the source
 *    and web zips, the checksum file and the release notes.
 *  - `apps/web/next.config.ts`, which puts it in `NEXT_PUBLIC_APP_VERSION` -- and therefore in the
 *    footer and the About box when the app is a web page.
 *  - `apps/desktop/electron-builder.config.cjs`, through `extraMetadata`, which is what makes
 *    `app.getVersion()`, the installer name and the artifact name agree -- and therefore the footer
 *    and the About box when the app is packaged.
 *  - `Sync-PackageJsonVersions`, which brings the twenty-one workspace manifests in line.
 *
 * This file is the gate for the last of those, because it is the one that can drift silently: every
 * internal dependency is `workspace:*`, so nothing resolves a manifest version and a stale one
 * breaks no build. It just puts a number on screen with nothing behind it.
 *
 * It is a test rather than only a step in `check_scripts.ps1` for a plain reason: the suite runs on
 * every change and on any platform, where the PowerShell checks run on Windows when someone
 * remembers. The fix when this fails is `pnpm win:version`.
 */

const repoRoot = path.join(__dirname, "..");
const read = (...parts: string[]): string =>
  readFileSync(path.join(repoRoot, ...parts), "utf8");

/**
 * Source with its comments removed, for the assertions below that say a construct is *absent*.
 *
 * Needed because the comment above `projectVersion` in `next.config.ts` spells
 * `process.env.npm_package_version` out in order to explain why it is not used -- so a plain text
 * search cannot tell the rejected expression from the sentence rejecting it, and asserting on the
 * raw text would forbid documenting the decision. Crude on purpose: it only has to handle the two
 * build configs, which contain no string holding a `//`.
 */
const codeOnly = (text: string): string =>
  text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|\s)\/\/.*$/gm, "$1");

/** Every workspace manifest, in the three places `pnpm-workspace.yaml` looks. */
function workspaceManifests(): string[] {
  const found = ["package.json"];
  for (const dir of ["apps", "packages", path.join("packages", "tools")]) {
    const base = path.join(repoRoot, dir);
    if (!existsSync(base)) continue;
    for (const entry of readdirSync(base, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const candidate = path.join(dir, entry.name, "package.json");
      if (existsSync(path.join(repoRoot, candidate))) found.push(candidate);
    }
  }
  return found;
}

describe("the root version file", () => {
  it("is a single semver line", () => {
    const raw = read("version");
    expect(raw.trim()).toMatch(/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/);
    // One line, so nothing downstream has to decide which of several to believe.
    expect(raw.trim().split("\n")).toHaveLength(1);
    // And a trailing newline, like every other text file here.
    expect(raw.endsWith("\n")).toBe(true);
  });

  /**
   * The assertion that catches a half-finished bump.
   *
   * Twenty-one manifests, and the failure message names the offenders rather than only the count --
   * "1 of 21 disagree" would send someone grepping.
   */
  it("is what every workspace package.json says", () => {
    const version = read("version").trim();
    const manifests = workspaceManifests();
    // A guard on the guard: if the discovery above broke, this test would pass by checking nothing.
    expect(manifests.length).toBeGreaterThan(15);

    const wrong: string[] = [];
    for (const relative of manifests) {
      const parsed = JSON.parse(read(relative)) as { version?: string };
      if (parsed.version !== version) wrong.push(`${relative} reads ${String(parsed.version)}`);
    }
    expect(wrong, `expected ${version} everywhere`).toEqual([]);
  });

  /**
   * The three build-time readers must actually read the file.
   *
   * Asserted as source text because there is no other way in: `next.config.ts` and the
   * electron-builder config are consumed by their own tools, not importable from here, and what
   * matters is that neither has quietly gone back to a package.json version or a literal. Both did
   * before -- `next.config.ts` read `npm_package_version ?? "0.1.0"`, which meant the number in the
   * footer depended on which directory the build was launched from and fell back to a literal that
   * could not be bumped.
   */
  it("is read by the web build, electron-builder and the packaging scripts", () => {
    const nextConfig = read("apps", "web", "next.config.ts");
    expect(nextConfig).toContain('"../../version"');
    expect(nextConfig).toContain("NEXT_PUBLIC_APP_VERSION: projectVersion");
    expect(codeOnly(nextConfig)).not.toMatch(/npm_package_version/);

    const builder = read("apps", "desktop", "electron-builder.config.cjs");
    expect(builder).toContain('"../../version"');
    // Without this electron-builder reads apps/desktop/package.json instead, and the installer
    // name, app.getVersion() and the release folder can all disagree.
    expect(builder).toContain("extraMetadata: { version: projectVersion }");

    const common = read("scripts", "lib", "common.ps1");
    expect(common).toContain("Join-Path $RepoRoot 'version'");
    // It used to read the root package.json. That is what this guards against coming back, since it
    // would make the manifests authoritative again and the sync test above vacuous. Matched as the
    // whole expression, so the doc comment explaining why the sync avoids ConvertFrom-Json is free
    // to name it.
    expect(common).not.toContain("(Join-Path $RepoRoot 'package.json') | ConvertFrom-Json");
  });
});

/**
 * The scripts folder's shape, which the `pnpm win:*` scripts and every dot-source depend on.
 *
 * `check_scripts.ps1` covers ASCII and PowerShell parsing; what it cannot see is a `.bat` wrapper
 * pointing at a `.ps1` that moved, or a `win:*` entry naming a path that no longer exists -- both of
 * which fail only when someone runs them, which on this repo may be weeks later. The layout mirrors
 * the sibling command generator's (`scripts/{lib,launch,build-helpers,package}`), deliberately,
 * because the two get read side by side.
 */
describe("the scripts folder", () => {
  const expected: Record<string, string[]> = {
    ".": ["check_scripts.bat", "check_scripts.ps1", "check_scripts.sh"],
    lib: ["common.ps1", "common.sh"],
    launch: [
      "launch_desktop.bat",
      "launch_desktop.ps1",
      "launch_desktop.sh",
      "launch_web.bat",
      "launch_web.ps1",
      "launch_web.sh",
    ],
    "build-helpers": [
      "build_all.bat",
      "build_all.ps1",
      "build_all.sh",
      "build_desktop.bat",
      "build_desktop.ps1",
      "build_desktop.sh",
      "build_web.bat",
      "build_web.ps1",
      "build_web.sh",
    ],
    package: [
      "create-package.bat",
      "create-package.ps1",
      "create-package.sh",
      "make_icon.bat",
      "make_icon.ps1",
      "make_icon.sh",
      "sync_version.bat",
      "sync_version.ps1",
      "sync_version.sh",
    ],
  };

  it("holds exactly the files each area is meant to", () => {
    for (const [area, files] of Object.entries(expected)) {
      const dir =
        area === "." ? path.join(repoRoot, "scripts") : path.join(repoRoot, "scripts", area);
      const found = readdirSync(dir, { withFileTypes: true })
        .filter((entry) => entry.isFile())
        .map((entry) => entry.name)
        .sort();
      expect(found, `scripts/${area}`).toEqual(files);
    }
  });

  /**
   * Every `.ps1` has a `.sh` beside it, and vice versa.
   *
   * The pair is the point: a Linux user reaching for the equivalent of `pnpm win:build` should find
   * one, and a Windows user should not discover that a script exists only on the other platform. The
   * file set above already pins the names, so this asserts the *relationship* -- which is what fails
   * usefully when somebody adds a script to one side only.
   */
  it("pairs every .ps1 with a .sh of the same name", () => {
    for (const [area, files] of Object.entries(expected)) {
      for (const file of files.filter((f) => f.endsWith(".ps1"))) {
        expect(files, `scripts/${area}/${file}`).toContain(file.replace(/\.ps1$/, ".sh"));
      }
      for (const file of files.filter((f) => f.endsWith(".sh"))) {
        expect(files, `scripts/${area}/${file}`).toContain(file.replace(/\.sh$/, ".ps1"));
      }
    }
  });

  /**
   * Every `.sh` in a subfolder reaches `common.sh` one level up, and starts with a bash shebang.
   *
   * The shell analogue of the `common.ps1` dot-source check below, and it fails the same way: a
   * stale relative path parses perfectly under `bash -n` and dies at run time with "No such file or
   * directory", which is exactly what a parse check cannot see.
   */
  it("sources common.sh by its real path", () => {
    for (const area of ["launch", "build-helpers", "package"]) {
      for (const file of expected[area]!.filter((f) => f.endsWith(".sh"))) {
        const text = read("scripts", area, file);
        /*
         * The relationship, not the spelling. Two forms are in use and both are correct --
         * `$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh` where the script needs nothing else, and
         * `$here/../lib/common.sh` where it already resolved its own directory to pass to a sibling
         * script. A regex pinning one of them would fail on the other, which is a test asserting a
         * style rather than a fact.
         */
        expect(text, `scripts/${area}/${file}`).toContain('/../lib/common.sh"');
        // `startsWith` rather than splitting on a newline: the shebang must be the very first
        // bytes of the file, which is the thing that actually matters, and it needs no escape.
        expect(text.startsWith("#!/usr/bin/env bash"), `scripts/${area}/${file}`).toBe(true);
      }
    }
    // And the two cross-script calls name their real homes, as the PowerShell pair do.
    for (const file of ["build_all.sh", "build_desktop.sh"]) {
      expect(read("scripts", "build-helpers", file)).toContain("/../package/create-package.sh");
    }
    expect(read("scripts", "build-helpers", "build_all.sh")).toContain("/../check_scripts.sh");
    expect(read("scripts", "package", "create-package.sh")).toContain("/../check_scripts.sh");
  });

  /**
   * Every `sh:*` entry names a file that exists, and goes through an explicit `bash`.
   *
   * The prefix is not decoration: pnpm runs a script through cmd.exe on Windows, which cannot exec a
   * `.sh` at all -- `pnpm sh:check` failed with "'scripts' is not recognized" until it was added. It
   * costs nothing on Linux and makes the whole set usable from Git Bash.
   */
  it("wires every sh:* script to a file that exists", () => {
    const scripts = JSON.parse(read("package.json")).scripts as Record<string, string>;
    const entries = Object.entries(scripts).filter(([name]) => name.startsWith("sh:"));
    expect(entries.length, "there should be one sh:* entry per win:* entry").toBe(
      Object.keys(scripts).filter((name) => name.startsWith("win:")).length,
    );
    for (const [name, command] of entries) {
      const parts = command.split(" ");
      expect(parts[0], `${name} must go through bash`).toBe("bash");
      expect(existsSync(path.join(repoRoot, parts[1]!)), `${name} -> ${parts[1]}`).toBe(true);
    }
  });

  it("gives every .bat a .ps1 of the same name beside it", () => {
    for (const [area, files] of Object.entries(expected)) {
      for (const file of files.filter((f) => f.endsWith(".bat"))) {
        const sibling = file.replace(/\.bat$/, ".ps1");
        expect(files, `scripts/${area}/${file}`).toContain(sibling);
        // And the wrapper must invoke it from its own directory, which is what `%~dp0` means.
        const dir = area === "." ? ["scripts"] : ["scripts", area];
        expect(read(...dir, file)).toContain(`%~dp0${sibling}`);
      }
    }
  });

  /**
   * Every `.ps1` in a subfolder reaches `common.ps1` one level up, and the two cross-script calls
   * name their new homes. A stale `$PSScriptRoot\common.ps1` parses perfectly and fails at run time
   * with "The term is not recognized", which is the kind of break a parse check cannot see.
   */
  it("dot-sources common.ps1 by its real path", () => {
    for (const area of ["launch", "build-helpers", "package"]) {
      for (const file of expected[area]!.filter((f) => f.endsWith(".ps1"))) {
        const text = read("scripts", area, file);
        expect(text, `scripts/${area}/${file}`).toContain(
          '. "$PSScriptRoot\\..\\lib\\common.ps1"',
        );
      }
    }
    expect(read("scripts", "build-helpers", "build_all.ps1")).toContain(
      '"$PSScriptRoot\\..\\check_scripts.ps1"',
    );
    expect(read("scripts", "package", "create-package.ps1")).toContain(
      '"$PSScriptRoot\\..\\check_scripts.ps1"',
    );
    for (const file of ["build_all.ps1", "build_desktop.ps1"]) {
      expect(read("scripts", "build-helpers", file)).toContain(
        '"$PSScriptRoot\\..\\package\\create-package.ps1"',
      );
    }
  });

  /**
   * `check_scripts.ps1` must recurse, or it silently narrows to the one file left beside it --
   * itself -- and reports success having checked nothing. That is the failure this reorganisation
   * made possible, and it would have passed every other check in the repo.
   */
  it("checks its subfolders", () => {
    const text = read("scripts", "check_scripts.ps1");
    expect(text).toMatch(/Get-ChildItem -LiteralPath \$PSScriptRoot -File -Recurse/);
  });

  it("is reachable through every pnpm win: script", () => {
    const manifest = JSON.parse(read("package.json")) as { scripts: Record<string, string> };
    const winScripts = Object.entries(manifest.scripts).filter(([name]) =>
      name.startsWith("win:"),
    );
    expect(winScripts.length).toBeGreaterThan(5);
    for (const [name, command] of winScripts) {
      // The first token is the path; anything after it is arguments.
      const target = command.split(" ")[0]!.replace(/\\/g, path.sep);
      expect(existsSync(path.join(repoRoot, target)), `${name} -> ${target}`).toBe(true);
    }
  });
});

/**
 * The smoke test's probe bodies, which are TypeScript template literals holding JavaScript.
 *
 * A backtick anywhere inside one closes the string early. The failure is a parse error at a column in
 * the middle of English prose -- `',' expected` somewhere in a comment -- which reads as anything but
 * what it is, and it is caught only by a typecheck of that one package, after a build.
 *
 * This is a gate rather than a note because the mistake is *attractive*: the natural way to write a
 * comment in this repo is to put code identifiers in backticks, and every other file rewards that.
 * Four separate edits to `smoke.ts` in one sitting hit it. Cheap to check, so it is checked.
 */
describe("the smoke probes", () => {
  const smokePath = path.join(repoRoot, "apps", "desktop", "src", "main", "smoke.ts");

  it("has no backtick inside a probe body", () => {
    const lines = readFileSync(smokePath, "utf8").split("\n");
    /*
     * A probe body opens with a line ending in the template-literal start and closes on the line that
     * ends it. Tracked by depth rather than by a regex over the whole file, because the file is mostly
     * ordinary TypeScript that uses backticks legitimately -- the failure messages built with
     * `${...}` interpolation outside the probes are fine and must stay allowed.
     */
    const offenders: string[] = [];
    let inProbe = false;
    lines.forEach((line, index) => {
      if (!inProbe) {
        // `(async () => {  or  `(() => ({   -- the two shapes the probes open with.
        if (/`\((?:async )?\(\) =>/.test(line)) inProbe = true;
        return;
      }
      // The closing line, which legitimately carries the backtick that ends the literal.
      if (/^\s*\}\)\(\)`|^\s*\}\)\)\(\)`/.test(line)) {
        inProbe = false;
        return;
      }
      /*
       * Escaped backticks are fine and are used deliberately: five probes build their failure
       * message with an inner template literal, which is legal inside the outer one as long as
       * every backtick is escaped. What breaks the file is a *bare* one, so those are removed
       * before looking. Interpolation is likewise legal and untouched.
       */
      const bare = line.replace(/\\\`/g, "");
      if (bare.includes("`")) offenders.push(`${index + 1}: ${line.trim().slice(0, 80)}`);
    });
    expect(offenders, "a backtick inside a probe body closes the template literal").toEqual([]);
  });

  /** And the detector has to find the probes at all, or the check above passes over nothing. */
  it("finds the probe bodies it is meant to be scanning", () => {
    const text = readFileSync(smokePath, "utf8");
    const opens = text.match(/`\((?:async )?\(\) =>/g) ?? [];
    expect(
      opens.length,
      "no probe bodies found; the opening pattern has changed",
    ).toBeGreaterThan(10);
  });
});
