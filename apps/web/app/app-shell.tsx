"use client";

import { useEffect, useState } from "react";
import { ByteSourceMode, TextEncoding } from "@ocs/contracts";
import { DEFAULT_TOOL_ID, getManifest, presentFamilies, TOOL_MANIFESTS } from "@ocs/registry";
import { getDesktopBridge, platform } from "@ocs/platform";
import { Footer } from "./footer";
import { DEFAULT_INPUT, type InputState } from "./input-state";
import { parseShareLink, type ParsedShare } from "./share-link";
import { ScrollToTop } from "./scroll-to-top";
import { SettingsOverlay } from "./settings-overlay";
import { Sidebar } from "./sidebar";
import { ToolWorkbench } from "./tool-workbench";

const FAMILIES = presentFamilies();

/**
 * What survives a restart, which is now one boolean.
 *
 * `toolId` was here and is deliberately gone: every session opens on `DEFAULT_TOOL_ID`, which is
 * CRC-8. Resuming the last tool is the obvious behaviour and it is not the one asked for -- and the
 * reasoning holds up, because the two are not symmetrical. `Auto update` is a *preference*: you set
 * it once because of how you like to work, and having it reset every launch would be a bug. Which
 * tool you last had open is a *position*, and being dropped back into it is only right if you were
 * interrupted mid-task. Landing somewhere predictable is worth more than landing where you were.
 *
 * A share link still names its own tool -- see the startup effect -- because that is an explicit
 * request rather than a resumption.
 */
interface PersistedState {
  autoUpdate?: boolean;
}

/**
 * The app frame: tool list on the left, the selected tool's workbench in the
 * middle, its own rail on the right.
 *
 * Input state lives here rather than in the workbench so that switching from
 * SHA-256 to SHA-512 keeps what you typed. That is the common case — the question
 * being asked is usually "what does this input hash to under X", with X varying —
 * and losing the input on every switch would make comparing algorithms tedious.
 * The spec does *not* survive a switch: two algorithms' option catalogues have
 * nothing in common, so carrying one across would be meaningless at best.
 */
export interface AppShellProps {
  /**
   * The tool a statically exported `/tools/<id>/` page opens on.
   *
   * Absent on the home page, which opens on `DEFAULT_TOOL_ID`. A named URL is an *explicit request*,
   * exactly as a share link is, which is why it overrides the "always open somewhere predictable" rule
   * that `PersistedState` records rather than contradicting it: that rule is about not resuming a
   * position nobody asked to return to.
   *
   * A share link still wins over this, because it carries settings as well as a tool -- so somebody who
   * opens a link on top of a tool page gets the whole thing they were sent.
   */
  initialToolId?: string;
}

export function AppShell({ initialToolId }: AppShellProps = {}) {
  const [selectedId, setSelectedId] = useState(initialToolId ?? DEFAULT_TOOL_ID);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [settingsOpen, setSettingsOpen] = useState(false);
  /**
   * Which category the settings overlay opens on.
   *
   * The gear opens Appearance; Help > About opens About. Held here rather than inside the overlay
   * because the *caller* is what knows why it is being opened.
   */
  const [settingsCategory, setSettingsCategory] = useState("appearance");
  const [input, setInput] = useState<InputState>(DEFAULT_INPUT);
  /**
   * Whether what is in the box was put there by the app rather than by the reader.
   *
   * True on arrival, because `DEFAULT_INPUT` is the app's own choice, and false forever after the
   * first edit, file, Clear, share link or Test input pick. The workbench reads it to decide whether
   * switching to a tool with its own sample may replace the contents: `123456789` is not JSON, and a
   * format tool opening on a parse error looks broken -- but an input somebody typed must survive a
   * tool switch, which is the whole reason this state lives up here rather than in the workbench.
   *
   * A boolean rather than comparing the text against a list of known samples: only the *provenance*
   * of the string answers the question, and somebody who types `123456789` by hand has still typed.
   */
  const [inputIsSeeded, setInputIsSeeded] = useState(true);
  const [autoUpdate, setAutoUpdate] = useState(true);
  const [restore, setRestore] = useState<ParsedShare | undefined>();
  const [hydrated, setHydrated] = useState(false);
  /**
   * The scrolling content column, held as state rather than in a ref.
   *
   * `<main>` outlives every tool switch, so a ref would work today -- but `ScrollToTop` reads this as
   * a plain element and re-attaches when it changes, which costs nothing here and means the scroller
   * can move back inside a keyed subtree later without silently leaving the button listening to a
   * detached node.
   */
  const [workbenchScroller, setWorkbenchScroller] = useState<HTMLElement | null>(null);

  /**
   * Native menu items, dispatched from the main process over the preload bridge.
   *
   * Through `getDesktopBridge` rather than `platform()`, deliberately: an application menu is
   * something only the desktop host has, so it is on the bridge and not in `PlatformApi`. In a
   * browser there is no bridge, this subscribes to nothing, and the web build is unaffected.
   *
   * Only `menu:about` is handled. The File menu's four items -- New computation, Open input file,
   * Copy result, Save result -- are dispatched by the main process and land here unhandled, which is
   * how they arrived: the bridge and the preload forwarding were built, and nothing ever subscribed.
   * They are listed in the switch so the gap is visible in code rather than only in the menu.
   */
  useEffect(() => {
    const bridge = getDesktopBridge();
    if (!bridge) return;
    return bridge.onMenuAction((action) => {
      switch (action) {
        case "menu:about":
          setSettingsCategory("about");
          setSettingsOpen(true);
          break;
        case "menu:newComputation":
        case "menu:openInput":
        case "menu:copyResult":
        case "menu:saveResult":
          // Not wired up yet.
          break;
      }
    });
  }, []);

  // Startup, in order of precedence: a share link in the URL beats saved state,
  // because a link is an explicit request to look at something specific.
  useEffect(() => {
    let cancelled = false;

    const share = parseShareLink(window.location.hash);
    if (share && getManifest(share.toolId)) {
      setSelectedId(share.toolId);
      setRestore(share);
      if (share.input) {
        const mode = ByteSourceMode.safeParse(share.input.mode);
        const encoding = TextEncoding.safeParse(share.input.textEncoding);
        setInput({
          // A link cannot name a file, so "file" mode is not restorable.
          mode: mode.success && mode.data !== "file" ? mode.data : "text",
          text: share.input.text,
          textEncoding: encoding.success ? encoding.data : "utf-8",
        });
        // Not a seed: a link naming an input is as explicit as typing one, so nothing may replace it.
        setInputIsSeeded(false);
      }
      setHydrated(true);
      return;
    }

    void platform()
      .readSavedState()
      .then((json) => {
        if (cancelled || !json) return setHydrated(true);
        try {
          const saved = JSON.parse(json) as PersistedState;
          // Note the absence of a tool id: `selectedId` keeps its initial `DEFAULT_TOOL_ID`. See
          // `PersistedState`.
          if (typeof saved.autoUpdate === "boolean") setAutoUpdate(saved.autoUpdate);
        } catch {
          // Saved state is a convenience. A corrupt blob is not worth a broken page.
        }
        setHydrated(true);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  // Persist. Gated on `hydrated` so the first render's defaults cannot overwrite
  // what was just loaded.
  useEffect(() => {
    if (!hydrated) return;
    const state: PersistedState = {
      autoUpdate,
      // No tool id: every startup opens on the default. Writing one nothing reads would be a field
      // waiting for somebody to wire back up.
      // No input, of any kind. It was written only while "Remember input" was on, and with that
      // switch gone the alternatives were to persist it unconditionally -- which nobody asked for,
      // on a tool people paste keys into -- or to keep dead code. Neither is better than a session
      // that starts empty.
    };
    void platform().writeSavedState(JSON.stringify(state));
    // `selectedId` is no longer a dependency, so switching tools writes nothing to disk.
  }, [hydrated, autoUpdate]);

  // A share link's hash has been consumed into state by now. Clearing it stops a
  // reload from re-applying settings the user has since changed, and keeps a URL
  // containing an input out of the address bar any longer than necessary.
  const consumeRestore = () => {
    setRestore(undefined);
    if (window.location.hash !== "") {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  };

  const manifest = getManifest(selectedId);

  return (
    <div className="flex h-screen flex-col">
      <header className="flex shrink-0 items-center justify-between border-b border-slate-200 px-4 py-2 dark:border-slate-800">
        <div className="flex items-baseline gap-2">
          <span className="text-sm font-semibold tracking-tight">Cipher Workbench</span>
          <span className="hidden text-[11px] text-slate-500 sm:inline dark:text-slate-400">
            Hashes, checksums, MACs and ciphers — computed and verified
          </span>
        </div>
        <button
          type="button"
          onClick={() => {
            setSettingsCategory("appearance");
            setSettingsOpen(true);
          }}
          aria-label="Settings"
          title="Settings"
          className="rounded-md border border-slate-200 p-1.5 text-slate-500 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800"
        >
          <GearIcon />
        </button>
      </header>

      <SettingsOverlay
        open={settingsOpen}
        category={settingsCategory}
        onClose={() => setSettingsOpen(false)}
      />

      <div className="flex flex-1 overflow-hidden">
        <aside
          className={`shrink-0 overflow-hidden border-r border-slate-200 bg-white transition-[width] duration-150 dark:border-slate-800 dark:bg-slate-900 ${
            sidebarOpen ? "w-64" : "w-11"
          }`}
        >
          {sidebarOpen ? (
            <Sidebar
              manifests={TOOL_MANIFESTS}
              families={FAMILIES}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onCollapse={() => setSidebarOpen(false)}
            />
          ) : (
            <div className="flex h-full flex-col items-center pt-3">
              <button
                type="button"
                onClick={() => setSidebarOpen(true)}
                aria-label="Expand sidebar"
                title="Expand sidebar"
                className="rounded-md border border-slate-200 p-1.5 text-slate-500 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800"
              >
                <MenuIcon />
              </button>
            </div>
          )}
        </aside>

        {/*
          One scroll container for the whole content area, and its scrollbar is at the window's right
          edge where a scrollbar belongs.

          This went through two wrong shapes first, and both are worth naming. It began as this plus a
          right rail that was `sticky` with its own `max-h` and `overflow-y-auto`: two scrollbars a few
          pixels apart, the inner one moving the rail's panels and the outer one moving the rail
          itself, so which one a drag reached depended on which pixel was grabbed. Making each column
          its own scroll container fixed that and produced a third problem -- the workbench column's
          scrollbar then sat *inside* the layout, floating in the 24px gutter between the panels and
          the rail, which reads as a nested-scroll artefact rather than as the page's scrollbar.

          There is no arrangement with all three of: one scrollbar, a rail pinned while you scroll, and
          a rail taller than the viewport that stays reachable. A pinned rail must scroll itself, and
          that is the second scrollbar. So the rail is not pinned: it scrolls with everything else,
          which is what an ordinary document does and what needs no explaining to anyone.
        */}
        <main ref={setWorkbenchScroller} className="flex-1 overflow-y-auto p-6">
          {manifest ? (
            <ToolWorkbench
              // Remounting on tool change is deliberate: it discards the previous
              // tool's spec, output encoding and verify field, none of which mean
              // anything under a different algorithm.
              key={selectedId}
              toolId={selectedId}
              input={input}
              onInputChange={(next) => {
                setInput(next);
                setInputIsSeeded(false);
              }}
              inputIsSeeded={inputIsSeeded}
              // Seeding leaves the flag alone, so a tool's sample is still replaceable by the next
              // tool's. Two callbacks rather than one with a flag argument, because the two mean
              // different things and a boolean parameter at the call site says neither.
              onSeedInput={setInput}
              autoUpdate={autoUpdate}
              onAutoUpdateChange={setAutoUpdate}
              restore={restore}
              onRestoreConsumed={consumeRestore}
            />
          ) : (
            <p className="text-xs text-slate-500 dark:text-slate-400">
              No such tool: {selectedId}
            </p>
          )}
        </main>
      </div>

      {/*
        Outside the scrolling row, so it is a bar across the bottom of the app rather than something
        at the end of a document of unbounded length. The row above is `flex-1`, so this takes its
        height off that and the layout needs no other change.
      */}
      <Footer />

      <ScrollToTop container={workbenchScroller} />
    </div>
  );
}

function GearIcon() {
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
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  );
}

function MenuIcon() {
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
      <line x1="3" y1="6" x2="21" y2="6" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <line x1="3" y1="18" x2="21" y2="18" />
    </svg>
  );
}
