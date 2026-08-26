"use client";

import { useState, type ReactNode } from "react";
import { cn } from "@ocs/ui";

export interface SidebarTab {
  id: string;
  label: string;
  /** Small count or dot rendered next to the label — used for the diagnostics count. */
  badge?: { text: string; tone: "neutral" | "error" | "insecure" | "warning" };
  content: ReactNode;
}

const BADGE_TONE = {
  neutral: "bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200",
  error: "bg-(--color-severity-error) text-white",
  insecure: "bg-(--color-severity-insecure) text-white",
  warning: "bg-(--color-severity-warning) text-slate-900",
} as const;

/**
 * Right-hand rail: settings and checks — the "meta" controls for what is
 * being computed, separate from the input itself.
 *
 * `sticky` with `self-start`: the rail is rendered inside the workbench's own
 * scrolling column rather than as a sibling of `<main>`, and `self-start` is what
 * stops it stretching to the column's full height — which is what lets it stay
 * put instead of scrolling away with the (usually much taller) panels beside it.
 */
export function RightSidebar({ tabs }: { tabs: SidebarTab[] }) {
  const [activeId, setActiveId] = useState(tabs[0]?.id);
  const [collapsed, setCollapsed] = useState(false);
  const active = tabs.find((t) => t.id === activeId) ?? tabs[0];

  if (collapsed) {
    return (
      <div className="flex w-11 shrink-0 flex-col items-center pt-1">
        <button
          type="button"
          onClick={() => setCollapsed(false)}
          aria-label="Expand panel"
          title="Expand panel"
          className="rounded-md border border-slate-200 p-1.5 text-slate-500 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800"
        >
          <ChevronIcon direction="left" />
        </button>
      </div>
    );
  }

  return (
    /*
      No scroll of its own, and not `sticky`.

      It was `sticky top-6 max-h-[calc(100vh-6rem)] overflow-y-auto`, which is the standard recipe for
      a pinned rail and is exactly what put a second scrollbar a few pixels from the page's own. The
      trade is real and was made deliberately: a rail that stays put while you scroll has to scroll
      itself once it is taller than the viewport, and that is a second scrollbar. Scrolling with the
      content instead costs the pinning and buys one predictable scrollbar at the window's edge -- and
      every panel in here folds, so a long Info table can be got out of the way without scrolling at
      all.
    */
    <div className="w-72 shrink-0 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800">
        <div className="flex gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              // So the packaged smoke test can reach a tab without matching on its label.
              data-ocs-tab={tab.id}
              onClick={() => setActiveId(tab.id)}
              className={cn(
                "-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium transition-colors",
                tab.id === active?.id
                  ? "border-slate-900 text-slate-900 dark:border-slate-100 dark:text-slate-100"
                  : "border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200",
              )}
            >
              {tab.label}
              {tab.badge && (
                <span
                  className={cn(
                    "rounded-full px-1.5 text-[10px] font-semibold leading-4",
                    BADGE_TONE[tab.badge.tone],
                  )}
                >
                  {tab.badge.text}
                </span>
              )}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={() => setCollapsed(true)}
          aria-label="Collapse panel"
          title="Collapse panel"
          className="mr-1 rounded-md p-1.5 text-slate-500 transition-colors hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
        >
          <ChevronIcon direction="right" />
        </button>
      </div>
      <div className="space-y-4">{active?.content}</div>
    </div>
  );
}

function ChevronIcon({ direction }: { direction: "left" | "right" }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points={direction === "left" ? "15 18 9 12 15 6" : "9 18 15 12 9 6"} />
    </svg>
  );
}
