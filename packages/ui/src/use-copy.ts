"use client";

import { useEffect, useRef, useState } from "react";

export interface UseCopyOptions {
  /** Read lazily, so a copy always takes the current value rather than the one at render time. */
  value: string | (() => string);
  /**
   * Override the clipboard write. The app passes `platform().copyToClipboard`; the default uses
   * `navigator.clipboard` directly, which works unchanged in a browser tab and in an Electron
   * renderer served over a real origin.
   */
  writeClipboard?: (text: string) => Promise<void>;
}

/**
 * Copy-to-clipboard with a "it worked" window, shared by the labelled and icon-only buttons.
 *
 * Extracted rather than duplicated because the timer handling below is the whole substance of both
 * buttons, and two copies of it is precisely the drift `ClearButton`'s own note describes: three
 * things that almost match. An icon-only button needs the same 1.5-second window to swap a glyph
 * that a labelled one needs to swap a word.
 */
export function useCopy({ value, writeClipboard }: UseCopyOptions): {
  copied: boolean;
  copy: () => Promise<void>;
} {
  const [copied, setCopied] = useState(false);
  /**
   * The revert timer, held so it can be replaced and cancelled.
   *
   * It was a bare `window.setTimeout` with nothing keeping it, which is wrong in two ways. Copy twice
   * inside the window and there are two timers: the first fires 1.5 seconds after the *first* click
   * and reverts while the second copy is still fresh, so the button reports failure for something
   * that worked. And a timer outliving its component sets state on a dead render -- harmless in React
   * 18, but it pins the closure until it fires, and these buttons are on panels that unmount on every
   * tool switch.
   */
  const revertRef = useRef<number | undefined>(undefined);

  const clearRevert = () => {
    if (revertRef.current !== undefined) window.clearTimeout(revertRef.current);
    revertRef.current = undefined;
  };

  useEffect(() => clearRevert, []);

  const copy = async () => {
    const text = typeof value === "function" ? value() : value;
    if (text === "") return;
    const write = writeClipboard ?? ((t: string) => navigator.clipboard.writeText(t));
    await write(text);
    setCopied(true);
    // Restart the window on every copy, so what is shown reflects the most recent one.
    clearRevert();
    revertRef.current = window.setTimeout(() => {
      revertRef.current = undefined;
      setCopied(false);
    }, 1500);
  };

  return { copied, copy };
}
