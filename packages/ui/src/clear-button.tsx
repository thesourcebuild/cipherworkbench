"use client";

import { Button, type ButtonProps } from "./button";
import { cn } from "./cn";

/**
 * The Clear control: a light-red pill with a bin in it, and no label.
 *
 * In `packages/ui` rather than beside its first caller because there are now three of them -- the
 * Input panel's text, the Input panel's file, and the Verify panel's expected value -- and three
 * things that almost match is precisely the defect `CopyButton` was extracted to prevent. The Verify
 * panel had a `variant="ghost"` "Clear" that was plain text until you hovered it, rendered only when
 * the field was non-empty, so the panel header changed height as you typed. Both of those were fixed
 * on the Input panel first; sharing the component is what stops them coming back one call site at a
 * time.
 *
 * Three decisions carried over from that work.
 *
 * **A bin, no word.** With a label the pill was as wide as the controls beside it and read as a third
 * setting, and a cross means "close" or "remove this chip" rather than "empty this". A bin says
 * discard on its own -- which is the one thing an icon can carry without a word next to it.
 *
 * **Light red.** It is the one control in these panels that throws something away, but the weight is
 * `red-400` on `red-50`, not the `red-700`-on-`red-300` the error blocks use: that is right for a
 * diagnostic that has found something and wrong for a control that is merely available. It darkens a
 * step on hover so it still responds to being pointed at. Tinted rather than `variant="danger"`,
 * whose solid `bg-red-600` on a 24px circle would shout louder than the Compute button below it.
 *
 * **Disabled, never hidden.** A control that appears when the field becomes non-empty moves whatever
 * is under it as you start typing.
 *
 * Because there is no visible text, `aria-label` is not optional -- an icon-only button with neither
 * is announced as "button" and nothing else. Every call site passes its own, since they clear
 * different things.
 */
export function ClearButton({ className, ...props }: ButtonProps) {
  return (
    <Button
      // There is at most one of these on screen per panel, so a probe can ask for "the Clear button"
      // and get the one in front of it.
      data-ocs-clear=""
      size="sm"
      variant="secondary"
      className={cn(
        // Square, so the rounding makes a circle. `p-0` beats the size variant's `px-3`, which would
        // otherwise stretch it into a lozenge around a 13px glyph.
        "h-6 w-6 rounded-full p-0",
        // `twMerge` resolves each of these against the `secondary` variant's slate equivalent, so the
        // border, background, text and hover all land on the red rather than doubling up.
        "border-red-200 bg-red-50/40 text-red-400 hover:bg-red-100/60 hover:text-red-500",
        "dark:border-red-900/60 dark:bg-red-950/20 dark:text-red-400/80",
        "dark:hover:bg-red-950/40 dark:hover:text-red-400",
        className,
      )}
      {...props}
    >
      <BinIcon />
    </Button>
  );
}

/**
 * A bin, at 13px inside a 24px button.
 *
 * The lid and body only -- the two vertical strokes a fuller bin icon has inside it close up into a
 * smudge at this size, which is worse than leaving them out.
 */
function BinIcon() {
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
      <path d="M3 6h18" />
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
      <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    </svg>
  );
}
