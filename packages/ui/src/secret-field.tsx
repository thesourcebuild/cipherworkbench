"use client";

import { useId, useState, type InputHTMLAttributes, type ReactNode } from "react";
import { cn } from "./cn";

export interface SecretFieldProps extends Omit<
  InputHTMLAttributes<HTMLInputElement>,
  "type" | "value" | "onChange"
> {
  value: string;
  onValueChange: (value: string) => void;
  label: string;
  hint?: string;
  /** Rendered under the input in the error colour — a bad length, an unparseable encoding. */
  problem?: string;
  /** Right-hand controls: a "Generate" button for a key or nonce, an encoding selector. */
  trailing?: ReactNode;
  /**
   * Render a textarea instead of an input. For PEM private keys, which are multi-line by
   * construction and unreadable squeezed onto one line.
   */
  multiline?: boolean;
  rows?: number;
}

/**
 * A masked input with a reveal toggle, for keys, passwords and passphrases.
 *
 * Masked by default rather than on request. The realistic setting for this app is
 * someone checking a key on a laptop in an office or on a call with their screen
 * shared, and a plaintext key in a form field is the thing that leaks. The toggle
 * is right there for when they need to confirm what they pasted.
 */
export function SecretField({
  value,
  onValueChange,
  label,
  hint,
  problem,
  trailing,
  multiline = false,
  rows = 6,
  className,
  ...props
}: SecretFieldProps) {
  const [revealed, setRevealed] = useState(false);
  const id = useId();

  const shared = cn(
    "min-w-0 flex-1 rounded-md border px-2 py-1.5 font-mono text-xs",
    "border-slate-300 bg-white text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100",
    "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-blue-600",
    problem && "border-(--color-severity-error)",
    className,
  );

  return (
    <div className="space-y-1">
      <div className="flex items-baseline justify-between gap-2">
        <label htmlFor={id} className="text-xs font-medium text-slate-700 dark:text-slate-300">
          {label}
        </label>
        <button
          type="button"
          onClick={() => setRevealed((r) => !r)}
          className="text-[11px] text-slate-500 underline decoration-dotted hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
          aria-pressed={revealed}
        >
          {revealed ? "Hide" : "Show"}
        </button>
      </div>
      <div className={cn("flex gap-2", multiline ? "items-start" : "items-center")}>
        {multiline ? (
          /**
           * A textarea cannot be masked with `type="password"`, so when hidden it shows a
           * fixed-height placeholder instead of the content. That is the honest option: a
           * blurred or dot-filled textarea invites people to believe the value is still
           * editable while hidden, and a PEM key pasted into it would be lost.
           */
          revealed ? (
            <textarea
              id={id}
              value={value}
              onChange={(event) => onValueChange(event.target.value)}
              rows={rows}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              className={cn(shared, "resize-y whitespace-pre")}
            />
          ) : (
            <button
              type="button"
              onClick={() => setRevealed(true)}
              className={cn(
                shared,
                "flex items-center justify-center text-slate-400 dark:text-slate-500",
              )}
              style={{ minHeight: `${rows * 1.4}rem` }}
            >
              {value === ""
                ? "Click to enter a key"
                : `${value.length} characters hidden — click to show`}
            </button>
          )
        ) : (
          <input
            id={id}
            type={revealed ? "text" : "password"}
            value={value}
            onChange={(event) => onValueChange(event.target.value)}
            // Browsers offering to save a hashing key as a login credential is
            // both useless and a way for it to end up in a password manager.
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            className={shared}
            {...props}
          />
        )}
        {trailing}
      </div>
      {problem ? (
        <p className="text-[11px] text-(--color-severity-error)">{problem}</p>
      ) : (
        hint && <p className="text-[11px] text-slate-500 dark:text-slate-400">{hint}</p>
      )}
    </div>
  );
}
