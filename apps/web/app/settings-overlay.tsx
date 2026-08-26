"use client";

import { useEffect, useState, type ReactNode } from "react";
import type { PlatformEnvironment } from "@ocs/contracts";
import { toAppPlatform } from "@ocs/contracts";
import { platform } from "@ocs/platform";
import { Button, Dialog, cn } from "@ocs/ui";
import { useTheme } from "./use-theme";
import type { ThemePreference } from "./theme-constants";

const THEMES: readonly { id: ThemePreference; label: string }[] = [
  { id: "light", label: "Light" },
  { id: "dark", label: "Dark" },
  { id: "system", label: "System" },
];

const PLATFORM_LABEL = {
  web: "Browser",
  windows: "Windows desktop",
  macos: "macOS desktop",
  linux: "Linux desktop",
} as const;

interface SettingsCategory {
  id: string;
  label: string;
  /** One line under the pane's heading. Says what the category is for, not what is in it. */
  summary: string;
  content: ReactNode;
}

/**
 * Settings, in the Eclipse-preferences shape: categories on the left, the selected one on the right.
 *
 * The same shape as the command generator this app is modelled on, and for the same reason it uses
 * it there: one long scrolling page works until it does not, and the point at which it stops working
 * is unpredictable and late. Three categories do not need a sidebar; the version of this that had
 * them stacked was perfectly readable. But adding a fourth to a stack means re-reading the whole
 * page to find anything, whereas adding a fourth here is one more entry in a list — and a reader
 * moving between the two apps should not have to relearn where preferences live.
 *
 * Built on the shared `Dialog`, which already owns the backdrop, the Escape key and the click-out.
 * `p-0` and a fixed height come through `className`, since `cn` runs tailwind-merge and a later
 * padding wins: the two-pane layout needs the card to have no padding of its own.
 */
export function SettingsOverlay({
  open,
  category = "appearance",
  onClose,
}: {
  open: boolean;
  /** Which category to open on. Help > About opens this on About; the gear opens Appearance. */
  category?: string;
  onClose: () => void;
}) {
  const { preference, setPreference } = useTheme();
  const [environment, setEnvironment] = useState<PlatformEnvironment | undefined>();
  const [activeId, setActiveId] = useState(category);

  /**
   * Reset to the requested category each time it opens, not just on first mount.
   *
   * Without this, `useState(category)` would honour the first open and ignore every one after it --
   * so Help > About would land on whatever category you happened to leave selected last time.
   */
  useEffect(() => {
    if (open) setActiveId(category);
  }, [open, category]);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    void platform()
      .environment()
      .then((env) => {
        if (!cancelled) setEnvironment(env);
      });
    return () => {
      cancelled = true;
    };
  }, [open]);

  /**
   * Declared inside the component rather than at module scope, unlike cmd-generator's.
   *
   * Its categories need no data; About here needs the resolved `PlatformEnvironment`, and closing
   * over it is cheaper and clearer than threading it through a prop on every category.
   */
  const categories: SettingsCategory[] = [
    {
      id: "appearance",
      label: "Appearance",
      summary: "How the app looks.",
      content: (
        <Setting
          label="Theme"
          hint='Follows your operating system unless you pick one. "System" keeps following it, including when it changes at sunset.'
        >
          <div className="flex gap-2">
            {THEMES.map((theme) => (
              <Button
                key={theme.id}
                size="sm"
                variant={preference === theme.id ? "primary" : "secondary"}
                onClick={() => setPreference(theme.id)}
              >
                {theme.label}
              </Button>
            ))}
          </div>
        </Setting>
      ),
    },
    {
      id: "privacy",
      label: "Privacy",
      summary: "Where your data goes.",
      content: (
        /*
          Stated plainly and permanently rather than as marketing. It is the single most important
          fact about a tool people paste keys and private files into, and "view source to check" is
          not an answer most users can act on -- so the claim is here, and the eslint config plus the
          absence of any network code in the repo is what backs it up.
        */
        <div className="space-y-3 text-xs text-slate-600 dark:text-slate-400">
          <p>
            <span className="font-semibold text-slate-900 dark:text-slate-100">Nowhere.</span>{" "}
            Every algorithm runs in this page, on this machine. There is no server to send
            anything to — the whole app is a static bundle, and it works with the network
            switched off. Nothing you type, and no file you choose, is uploaded, logged, or
            transmitted.
          </p>
          <p>
            Share links are the one exception, and they only ever contain what you can see in
            them. Keys and passwords are stripped out before a link is built, and the app tells
            you when it has done so.
          </p>
          <p>
            The desktop build goes further and blocks outbound requests from this window
            outright, with a content security policy and a second check in the main process. Its
            own release test opens a real external URL and requires the attempt to fail.
          </p>
        </div>
      ),
    },
    {
      id: "about",
      label: "About",
      summary: "What is running.",
      content: (
        <div className="space-y-3">
          {/* Reached from Help > About as well as from the gear, so it opens with the name and what
              the thing is -- which is what an About box is for. */}
          <div>
            <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Cipher Workbench
            </p>
            <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
              Computes and verifies hashes, checksums, CRCs, MACs, key derivations, ciphers,
              signatures and encodings.
            </p>
          </div>
          <dl className="space-y-1 text-xs">
            <Row label="Version" value={environment?.appVersion ?? "…"} />
            <Row
              label="Running in"
              value={environment ? PLATFORM_LABEL[toAppPlatform(environment)] : "…"}
            />
            {/*
              There was a "Saving files" row here, reporting whether the host lets you pick a
              location. It went with the Result panel's Save button: with nothing in the app that
              writes a file, it was answering a question about a feature that no longer exists.
            */}
          </dl>
        </div>
      ),
    },
  ];

  const active = categories.find((category) => category.id === activeId) ?? categories[0]!;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      aria-label="Settings"
      className="flex h-[520px] max-h-[calc(100vh-2rem)] w-full max-w-3xl overflow-hidden p-0"
    >
      <aside className="w-48 shrink-0 overflow-y-auto border-r border-slate-200 bg-slate-50 p-2 dark:border-slate-800 dark:bg-slate-950">
        <h2 className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
          Settings
        </h2>
        <nav className="space-y-0.5">
          {categories.map((category) => (
            <button
              key={category.id}
              type="button"
              onClick={() => setActiveId(category.id)}
              aria-current={category.id === active.id}
              className={cn(
                "block w-full rounded px-2 py-1.5 text-left text-xs transition-colors",
                category.id === active.id
                  ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900"
                  : "text-slate-700 hover:bg-slate-200 dark:text-slate-300 dark:hover:bg-slate-800",
              )}
            >
              {category.label}
            </button>
          ))}
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex shrink-0 items-start justify-between gap-4 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <div className="min-w-0">
            <h1 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {active.label}
            </h1>
            <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
              {active.summary}
            </p>
          </div>
          {/* No "Done" button: there is nothing to confirm. Escape, a click outside and this all
              close it, and a footer button would imply the choices were pending until pressed. */}
          <button
            type="button"
            onClick={onClose}
            aria-label="Close settings"
            title="Close"
            className="shrink-0 rounded p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-300"
          >
            <CloseIcon />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto p-4">{active.content}</div>
      </div>
    </Dialog>
  );
}

function Setting({
  label,
  hint,
  children,
}: {
  label: string;
  hint: string;
  children: ReactNode;
}) {
  return (
    <div>
      <p className="text-xs font-medium text-slate-700 dark:text-slate-300">{label}</p>
      <p className="mt-0.5 mb-2 text-[11px] text-slate-500 dark:text-slate-400">{hint}</p>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="text-right text-slate-900 dark:text-slate-100">{value}</dd>
    </div>
  );
}

function CloseIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}
