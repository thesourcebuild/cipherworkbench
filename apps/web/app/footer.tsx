"use client";

import { useEffect, useState } from "react";
import type { PlatformEnvironment } from "@ocs/contracts";
import { cn } from "@ocs/ui";
import { platform } from "@ocs/platform";

/**
 * The repository these links point at.
 *
 * One constant rather than three URLs, because the whole set moving together is the only sane way
 * for them to move -- and because every one of them has to stay on `github.com`. The desktop main
 * process hands a clicked link to the system browser only if it matches `EXTERNAL_ALLOWLIST` in
 * `window.ts`, so a link to any other host is not blocked with a message, it simply does nothing.
 * That is this repo's most-repeated defect shape, and the smoke test's `checkFooter` probe is what
 * stops it: it reads the rendered hrefs and requires all three to be github.com URLs.
 */
const REPO = "https://github.com/thesourcebuild/CipherWorkbench";

/**
 * Pinned rather than `new Date().getFullYear()`.
 *
 * It has to agree with electron-builder's `copyright` field, which is a build-time string in
 * `electron-builder.config.cjs`; a footer that rolled over on New Year's Day while the installer's
 * metadata did not would make the two disagree for a year. Bump both together.
 */
const COPYRIGHT_YEAR = 2026;
const COPYRIGHT_HOLDER = "Muhammad Hassaan Shah";

const LINKS: readonly { label: string; href: string; title: string; accent?: boolean }[] = [
  {
    label: "Docs",
    href: `${REPO}/blob/master/README.md#further-reading`,
    title: "What each family is for, and which standard it follows",
  },
  { label: "GitHub", href: REPO, title: "Source, vectors and release notes" },
  {
    // The only one of the three that asks something of the reader, so it is the only one coloured
    // as a link. Two references and one call to action reads better than three identical greys.
    accent: true,
    label: "Report an issue",
    href: `${REPO}/issues/new`,
    title: "A wrong digest, a refused vector, or a control that does nothing",
  },
];

/**
 * A thin bar at the bottom of the shell: what this is, and where to go about it.
 *
 * Modelled on the command generator's footer, which is the sibling this app is laid out against --
 * the same product-name-and-version group on one side and the same three links on the other, so the
 * two read as one family. It differs in placement: that is a scrolling page and puts its footer at
 * the end of the document, whereas this shell is a fixed-height three-column app whose middle column
 * scrolls on its own. A footer inside that column would be reachable only by scrolling past a
 * workbench of unbounded length, so this is a sibling of the header instead and mirrors it.
 *
 * The version comes from `PlatformEnvironment` rather than from `process.env`, because that is where
 * the About box reads it -- and the desktop app's version is the packaged app's, which is not
 * necessarily the number the web bundle was built with. Two places showing different versions of the
 * same running program is worse than either number alone.
 */
export function Footer() {
  const [environment, setEnvironment] = useState<PlatformEnvironment | undefined>();

  useEffect(() => {
    let cancelled = false;
    void platform()
      .environment()
      .then((env) => {
        if (!cancelled) setEnvironment(env);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <footer
      data-ocs-footer=""
      className="flex shrink-0 flex-wrap items-center justify-between gap-x-4 gap-y-1 border-t border-slate-200 px-4 py-1.5 text-[11px] text-slate-500 dark:border-slate-800 dark:text-slate-400"
    >
      <p className="flex items-center gap-2">
        <span className="font-medium text-slate-600 dark:text-slate-300">Cipher Workbench</span>
        {/*
          The version is absent for one frame while `environment()` resolves. A dash holds its width
          so the row does not jump, rather than the name sliding left and back.
        */}
        <span data-ocs-footer-version="">v{environment?.appVersion ?? "—"}</span>
        <Separator />
        <span>
          © {COPYRIGHT_YEAR} {COPYRIGHT_HOLDER}
        </span>
      </p>

      <nav className="flex items-center gap-2">
        {LINKS.map((link, index) => (
          <span key={link.href} className="flex items-center gap-2">
            {index > 0 && <Separator />}
            <a
              href={link.href}
              title={link.title}
              // `_blank` so the desktop app's window-open handler sees it and passes it to the
              // system browser; a same-window navigation would be caught by `will-navigate`
              // instead, which does the same thing but only after cancelling a navigation the
              // renderer had already started.
              target="_blank"
              rel="noreferrer noopener"
              className={cn(
                "rounded transition-colors hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600",
                link.accent
                  ? "text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                  : "hover:text-slate-900 dark:hover:text-slate-100",
              )}
            >
              {link.label}
            </a>
          </span>
        ))}
      </nav>
    </footer>
  );
}

/** The pipe the sibling project separates these with. `aria-hidden` — it is punctuation. */
function Separator() {
  return (
    <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">
      |
    </span>
  );
}
