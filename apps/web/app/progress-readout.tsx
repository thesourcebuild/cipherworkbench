"use client";

import { cn } from "@ocs/ui";
import { formatBytes, formatBytesShort } from "./input-state";
import { progressPresentation } from "./progress-presentation";
import type { ComputeState } from "./use-compute";

/**
 * How much of the input has been consumed: a bar, and the numbers behind its width.
 *
 * It lives at the bottom of the **Input** panel, not under the result, and that is the whole point of
 * it being its own file. What it measures is input -- bytes read of bytes available -- so putting it
 * beneath a digest stacked two byte counts in one panel that meant different things: "1 byte · 2
 * characters as shown" is the size of the answer, "9 bytes of 9 bytes" is the size of the question.
 * Readers kept having to work out which was which, and the answer was that one of them was in the
 * wrong panel.
 *
 * The pairing earns its place before you press Compute rather than after. With auto-update off the
 * Input header says `9 bytes` and this says `0 bytes of 9 bytes — 0%`, which are two different facts;
 * once it has run they agree, and a line that is redundant at rest and informative in flight is the
 * right way round.
 *
 * Nothing here mounts or unmounts on status. The bar is always drawn and only its fill width moves;
 * the line under it always holds the same three numbers. Both were conditional once, and the panel
 * jumped every time a computation started or finished.
 */
export function ProgressReadout({ state }: { state: ComputeState }) {
  const { total, consumed, percent, indeterminate } = progressPresentation(state);

  return (
    <div className="space-y-1.5">
      <div
        className="h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        // Omitted while indeterminate, which is what tells assistive technology the position is
        // unknown rather than zero.
        aria-valuenow={indeterminate ? undefined : percent}
      >
        <div
          className={cn(
            "h-full rounded-full bg-slate-900 dark:bg-slate-100",
            indeterminate && "w-1/3 animate-pulse",
          )}
          style={indeterminate ? undefined : { width: `${percent}%` }}
        />
      </div>
      {/*
        Short form on the left, full form on the right, so the exact byte count appears once.
        "1.4 MiB (1,507,484 bytes) of 1.4 MiB (1,507,484 bytes)" states one number four times.
      */}
      <p
        data-ocs-progress-stats=""
        className="min-h-4 text-[11px] text-slate-500 dark:text-slate-400"
      >
        {indeterminate
          ? `${formatBytesShort(consumed)} processed — Working…`
          : `${formatBytesShort(consumed)} of ${formatBytes(total)} — ${percent}%`}
      </p>
    </div>
  );
}
