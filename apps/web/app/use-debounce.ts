"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ByteSourceMode } from "@ocs/contracts";

/**
 * How long a typed input waits after the last change before recomputing.
 *
 * **This is the only place to change it.** One constant, one hook, one rule about which sources it
 * applies to — all here rather than as a `setTimeout` inside whichever effect happened to need it.
 * The number is a product decision and it belongs somewhere it can be found and changed once.
 */
export const INPUT_DEBOUNCE_MS = 1000;

/**
 * The same interval as user-facing prose, for the `Auto update` tooltip.
 *
 * Derived rather than written out, because a tooltip claiming "two seconds" while the constant says
 * one is worse than no tooltip — and that is exactly what happens when the number lives in two
 * places. Whole and half seconds are all this interval ever needs to be, so the formatting stays
 * this simple.
 */
export const INPUT_DEBOUNCE_LABEL: string =
  INPUT_DEBOUNCE_MS === 1000
    ? "1 second"
    : `${Number((INPUT_DEBOUNCE_MS / 1000).toFixed(1))} seconds`;

/**
 * The debounce for one source mode: `INPUT_DEBOUNCE_MS` for anything typed, none for a file.
 *
 * The asymmetry is the point. Text, hex, loose hex and both Base64 modes arrive one keystroke at a
 * time, and every intermediate state is a different input that would otherwise be hashed — half a
 * pasted key, an odd number of hex digits, a Base64 string that does not decode yet. Waiting until
 * someone stops typing means the error messages describe what they meant rather than what they were
 * halfway through, and for the expensive tools — Argon2, scrypt, bcrypt — it is the difference
 * between one derivation and forty.
 *
 * A file has no intermediate states. It is chosen once, whole, and it should start reading the
 * moment it lands rather than sitting still for a second for no reason. `computeFile` streams and
 * reports progress, so there is nothing to protect against there either.
 */
export function debounceForMode(mode: ByteSourceMode): number {
  return mode === "file" ? 0 : INPUT_DEBOUNCE_MS;
}

export interface DebouncedTrigger {
  /**
   * Run `action` once `delayMs` has passed with no further call. A later call replaces an earlier
   * one, so only the last version of a rapidly-changing input is ever computed.
   *
   * `delayMs` of 0 runs it synchronously rather than on a zero timer, so a caller that has opted
   * out of debouncing entirely does not pay a frame for it.
   */
  schedule: (action: () => void, delayMs: number) => void;
  /** Drop a scheduled action. Also the effect-cleanup function. */
  cancel: () => void;
  /** True while an action is waiting, so the UI can say why nothing has happened yet. */
  pending: boolean;
}

/**
 * A single pending action with a cancellable delay.
 *
 * `schedule` and `cancel` are stable for the life of the component, which matters more than it
 * looks: the caller is an effect, and a `schedule` that changed identity on every render would make
 * that effect re-run and reschedule itself forever.
 */
export function useDebouncedTrigger(): DebouncedTrigger {
  const timerRef = useRef<number | undefined>(undefined);
  const [pending, setPending] = useState(false);

  const cancel = useCallback(() => {
    if (timerRef.current !== undefined) {
      window.clearTimeout(timerRef.current);
      timerRef.current = undefined;
    }
    setPending(false);
  }, []);

  const schedule = useCallback((action: () => void, delayMs: number) => {
    if (timerRef.current !== undefined) window.clearTimeout(timerRef.current);
    if (delayMs <= 0) {
      timerRef.current = undefined;
      setPending(false);
      action();
      return;
    }
    setPending(true);
    timerRef.current = window.setTimeout(() => {
      timerRef.current = undefined;
      setPending(false);
      action();
    }, delayMs);
  }, []);

  // A timer outliving its component would fire an action closing over a dead render.
  useEffect(() => cancel, [cancel]);

  return { schedule, cancel, pending };
}
