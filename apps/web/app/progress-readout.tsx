"use client";

import { cn } from "@ocs/ui";
import { formatBytes, formatBytesShort } from "./input-state";
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
  const busy = state.status === "computing";
  /**
   * `state.result !== undefined` rather than `status === "done"`, and that is what stops the bar
   * flickering: with auto-update on, every keystroke passes through `pending` with the previous
   * digest still on screen, and a bar keyed on `done` would empty and refill on each one. A finished
   * value is a finished value; `stale` is one too -- superseded, not stopped halfway.
   */
  const finished = state.result !== undefined;

  /**
   * How much there is to read: a streaming file says so itself, and everything else is the decoded
   * input, which `useCompute` reports whether or not anything has computed.
   *
   * A typed input has no intermediate positions, so it goes 0 to 100% in one step. That is honest --
   * the work was one synchronous call. Only a streamed file reports bytes as it goes.
   */
  const total = state.progress?.totalBytes ?? state.inputByteLength ?? 0;
  const consumed = busy ? (state.progress?.bytesProcessed ?? 0) : finished ? total : 0;
  const fraction = total > 0 ? Math.min(consumed / total, 1) : finished ? 1 : 0;
  /**
   * Working, over an amount nobody can state -- a legacy encoding's tables still loading over text
   * that does not decode yet. A fixed-width pulse says "working" without claiming a position it does
   * not know. Nearly theoretical now that the total comes from the input rather than only from a
   * file handle, and cheap enough to keep for the case that remains.
   */
  const indeterminate = busy && total === 0;

  return (
    <div className="space-y-1.5">
      <div
        className="h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        // Omitted while indeterminate, which is what tells assistive technology the position is
        // unknown rather than zero.
        aria-valuenow={indeterminate ? undefined : Math.round(fraction * 100)}
      >
        <div
          className={cn(
            "h-full rounded-full bg-slate-900 transition-[width] duration-150 dark:bg-slate-100",
            indeterminate && "w-1/3 animate-pulse",
          )}
          style={indeterminate ? undefined : { width: `${fraction * 100}%` }}
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
        {`${formatBytesShort(consumed)} of ${formatBytes(total)} — ${Math.round(fraction * 100)}%`}
      </p>
    </div>
  );
}
