"use client";

import { useEffect, useState } from "react";

/**
 * Appears once the scrolling column is far enough down to make getting back annoying.
 *
 * Takes the element rather than a `RefObject`, and that is not a style choice. The column it watches
 * lives inside `ToolWorkbench`, which is remounted on every tool change -- so with a ref the effect
 * would attach its listener once, to a node that is detached the first time somebody picks a
 * different tool, and the button would silently stop appearing. An element in a state variable makes
 * the identity change visible to the dependency array, so the listener follows the live node. Same
 * defect class as the smoke probe that held a detached switch.
 */
export function ScrollToTop({ container }: { container: HTMLElement | null }) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (!container) {
      setVisible(false);
      return;
    }
    const onScroll = () => setVisible(container.scrollTop > 400);
    container.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => container.removeEventListener("scroll", onScroll);
  }, [container]);

  if (!visible) return null;

  return (
    <button
      type="button"
      onClick={() => container?.scrollTo({ top: 0, behavior: "smooth" })}
      aria-label="Scroll to top"
      title="Scroll to top"
      className="fixed bottom-6 right-6 z-40 rounded-full border border-slate-300 bg-white p-2.5 shadow-lg transition-colors hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:hover:bg-slate-800"
    >
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <polyline points="18 15 12 9 6 15" />
      </svg>
    </button>
  );
}
