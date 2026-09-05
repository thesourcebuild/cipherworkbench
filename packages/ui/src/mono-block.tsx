"use client";

import type { HTMLAttributes } from "react";
import { cn } from "./cn";

export interface MonoBlockProps extends HTMLAttributes<HTMLDivElement> {
  value: string;
  /**
   * Insert a thin space every N characters.
   *
   * Worth having rather than a cosmetic nicety: comparing two 64-character hex
   * strings by eye is genuinely hard, and grouping into fours turns it into
   * comparing sixteen short chunks. Applied only when the value has no
   * whitespace of its own, so Base64 and the pre-grouped `binary` output
   * encoding are left alone.
   */
  groupSize?: number;
  /** Renders in the muted "nothing computed yet" state. */
  placeholder?: boolean;
  tone?: "default" | "match" | "mismatch";
}

const TONES: Record<NonNullable<MonoBlockProps["tone"]>, string> = {
  default: "border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-950",
  match:
    "border-(--color-verify-match) bg-emerald-50/60 dark:bg-emerald-950/20 dark:border-(--color-verify-match)",
  mismatch:
    "border-(--color-verify-mismatch) bg-red-50/60 dark:bg-red-950/20 dark:border-(--color-verify-mismatch)",
};

export function MonoBlock({
  value,
  groupSize,
  placeholder = false,
  tone = "default",
  className,
  ...props
}: MonoBlockProps) {
  const display =
    groupSize && groupSize > 0 && !/\s/.test(value) ? group(value, groupSize) : value;

  /**
   * Laid-out text or one long token, and the two want opposite treatment.
   *
   * A digest has no newlines and must **wrap**: a 128-character hex string scrolling sideways would be
   * unreadable and uncopyable by eye. A UART frame table or a formatted XML document has newlines and
   * must **not** wrap -- wrapping is exactly what destroys the column alignment those outputs exist to
   * show, and the panel is narrower than a wide table. So the mode is chosen from the value rather
   * than passed in: any caller who has to say which would eventually say the wrong one.
   */
  const multiline = display.includes("\n");

  return (
    <div
      className={cn(
        "rounded-md border px-3 py-2 font-mono text-xs leading-relaxed",
        /**
         * Bounded height, always, and this is the fix for a real report.
         *
         * The UART tool prints one row per input byte, so thirty bytes is thirty-one lines and the
         * Result panel grew until the page did -- pushing Verify, the Table panel and the Variants
         * table off the bottom of a screen. It is not a UART problem: a formatted JSON document, a
         * decoded Base64 file and an SLH-DSA signature (30 KB of hex, hundreds of wrapped lines) all
         * do the same, which is why the cap belongs here rather than in the one panel that noticed.
         * `tool-workbench.tsx` had already solved it locally for the share link with a tighter cap of
         * its own, which still wins -- `cn` is tailwind-merge, so a caller's `max-h-*` overrides this.
         *
         * `resize-y` only when there is something to open up. A block element resizes only with
         * `overflow` set, which is why the two go together, and a draggable single-line digest would be
         * a handle that does nothing.
         */
        "max-h-52 overflow-auto",
        multiline
          ? "whitespace-pre overflow-x-auto"
          : "break-words whitespace-pre-wrap [overflow-wrap:anywhere]",
        multiline && "resize-y",
        TONES[tone],
        placeholder && "text-slate-400 dark:text-slate-600",
        className,
      )}
      {...props}
    >
      {display === "" ? " " : display}
    </div>
  );
}

/**
 * Only the *display* string is grouped. Copy actions read the ungrouped `value`,
 * so what lands on the clipboard is always the real digest with no spaces in it.
 */
function group(value: string, size: number): string {
  const chunks: string[] = [];
  for (let i = 0; i < value.length; i += size) chunks.push(value.slice(i, i + size));
  return chunks.join(" ");
}
