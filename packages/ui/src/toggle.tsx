"use client";

import { useId } from "react";
import { cn } from "./cn";

export interface ToggleProps {
  checked: boolean;
  onCheckedChange: (next: boolean) => void;
  /** Shown beside the switch, and it is also the accessible name. */
  label: string;
  /** Tooltip. Say what the setting does, not what the control is. */
  hint?: string;
  disabled?: boolean;
  /** Test hook, rendered as `data-ocs-toggle`. */
  id?: string;
  className?: string;
  /**
   * Overrides the label's typography. `cn` runs through tailwind-merge, so a size or weight passed
   * here wins over the default.
   *
   * Exists because this switch is used in two places with different type scales: the panel header,
   * where it is one of several small controls, and the options form, where its label has to look
   * like every other option label beside it.
   */
  labelClassName?: string;
}

/**
 * An on/off switch.
 *
 * A `<button role="switch">` rather than a styled `<input type="checkbox">`, and the distinction is
 * real: a checkbox is a *form field*, holding a value that something else will act on later, so
 * unchecking it before pressing Submit changes nothing yet. A switch takes effect the moment it
 * moves. `Auto update` is the second kind - turning it off stops the next recompute from happening
 * at all - and a control that looks like a pending choice while actually being immediate is the
 * wrong shape for it.
 *
 * This is now the only on/off control in the app; the boolean options in the form use it too. A
 * boolean option is arguably the first kind, since nothing recomputes until the debounce fires, but
 * one lone checkbox among switches reads as an oversight rather than as a distinction.
 *
 * `role="switch"` carries the same keyboard contract as a checkbox (Space toggles, Tab reaches it)
 * and a screen reader announces "on"/"off" rather than "checked", which is the honest reading.
 */
export function Toggle({
  checked,
  onCheckedChange,
  label,
  hint,
  disabled = false,
  id,
  className,
  labelClassName,
}: ToggleProps) {
  const labelId = useId();

  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-labelledby={labelId}
      disabled={disabled}
      title={hint}
      data-ocs-toggle={id}
      onClick={() => onCheckedChange(!checked)}
      className={cn(
        "group flex items-center gap-1.5 rounded text-[11px]",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600",
        disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer",
        className,
      )}
    >
      <span
        aria-hidden
        className={cn(
          "relative inline-flex h-3.5 w-6 shrink-0 items-center rounded-full transition-colors",
          checked
            ? "bg-(--color-nav-here)"
            : "bg-slate-300 group-hover:bg-slate-400 dark:bg-slate-700 dark:group-hover:bg-slate-600",
        )}
      >
        <span
          className={cn(
            "absolute h-2.5 w-2.5 rounded-full bg-white shadow-sm transition-transform",
            // Translated rather than swapped between two positioned elements, so the movement is
            // what tells you it changed even if the colour is hard to see.
            checked ? "translate-x-3" : "translate-x-0.5",
          )}
        />
      </span>
      <span
        id={labelId}
        className={cn(
          "whitespace-nowrap transition-colors",
          checked ? "text-slate-700 dark:text-slate-200" : "text-slate-500 dark:text-slate-400",
          labelClassName,
        )}
      >
        {label}
      </span>
    </button>
  );
}
