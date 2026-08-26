"use client";

import { Button, type ButtonProps } from "./button";
import { cn } from "./cn";
import { useCopy } from "./use-copy";

export interface CopyIconButtonProps extends Omit<
  ButtonProps,
  "onClick" | "children" | "value"
> {
  /** Read lazily, so the button always copies the current value rather than the one at render time. */
  value: string | (() => string);
  writeClipboard?: (text: string) => Promise<void>;
  /** Announced and shown on hover. Required, since there is no visible text to fall back on. */
  "aria-label": string;
}

/**
 * Copy as a 24px circle with a clipboard in it, sized and shaped to pair with `ClearButton`.
 *
 * A separate component from `CopyButton` rather than a prop on it, because the two differ in more
 * than width: a labelled button says "Copied" and an icon-only one has to *become* a tick, and an
 * icon-only button's `aria-label` is not optional where a labelled one's is redundant. They share
 * the substance -- the clipboard write and the 1.5-second window -- through `useCopy`, so there is
 * one implementation of the part that could drift.
 *
 * Three decisions, and the first two are inherited from `ClearButton` on purpose: these two sit next
 * to each other in the Input panel's controls row, and a pair of round pills that almost match is
 * worse than either shape used consistently.
 *
 * **Same circle, neutral colour.** `ClearButton` is tinted red because it throws something away;
 * copying takes nothing, so this stays on the `secondary` variant's slate. Colouring it would imply a
 * distinction between two adjacent controls that does not exist -- and green-for-copy would make the
 * resting state look like a success message.
 *
 * **Disabled, never hidden.** Same reason as Clear: a control that appears on the first keystroke
 * moves the textarea down a line as you start typing.
 *
 * **The tick replaces the glyph rather than joining it.** At 13px there is no room for both, and a
 * tick alone is unambiguous for the second and a half it is up. The button keeps its size either way,
 * because the two icons share a viewBox -- a copy control that resized on click would nudge the Clear
 * button beside it.
 */
export function CopyIconButton({
  value,
  writeClipboard,
  className,
  ...props
}: CopyIconButtonProps) {
  const { copied, copy } = useCopy({ value, writeClipboard });

  return (
    <Button
      // At most one per panel, so a probe can ask for "the copy button" and get the one in front of it.
      data-ocs-copy-icon=""
      size="sm"
      variant="secondary"
      onClick={() => void copy()}
      className={cn(
        // Square, so the rounding makes a circle. `p-0` beats the size variant's `px-3`, which would
        // otherwise stretch it into a lozenge around a 13px glyph.
        "h-6 w-6 rounded-full p-0",
        className,
      )}
      {...props}
    >
      {copied ? <TickIcon /> : <ClipboardIcon />}
    </Button>
  );
}

/** Two overlapping sheets, which is the clipboard-free way to say "copy" without a lid and clasp. */
function ClipboardIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.9"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1" />
    </svg>
  );
}

function TickIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}
