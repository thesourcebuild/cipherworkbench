"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { cn } from "./cn";

export type ToastTone = "success" | "error" | "warning" | "info";

export interface ToastOptions {
  title: ReactNode;
  description?: ReactNode;
  tone?: ToastTone;
  /** Milliseconds before dismissal. Set to 0 to keep the toast open. */
  durationMs?: number;
}

export interface ToastProviderProps {
  children?: ReactNode;
  defaultDurationMs?: number;
}

export interface ToastApi {
  showToast: (options: ToastOptions) => string;
  dismissToast: (id: string) => void;
}

interface ToastEntry extends ToastOptions {
  id: string;
  tone: ToastTone;
  durationMs: number;
}

const DEFAULT_DURATION_MS = 3000;
const MAX_VISIBLE_TOASTS = 4;
const EXIT_DURATION_MS = 160;
const ToastContext = createContext<ToastApi | undefined>(undefined);

const ACCENT_STYLES: Record<ToastTone, string> = {
  success: "bg-emerald-500",
  error: "bg-red-500",
  warning: "bg-amber-500",
  info: "bg-blue-500",
};

function ToastIcon({ tone }: { tone: ToastTone }) {
  if (tone === "success") {
    return (
      <svg viewBox="0 0 20 20" fill="none" className="h-3.5 w-3.5" aria-hidden="true">
        <path d="m5 10 3.1 3L15 6.5" stroke="currentColor" strokeWidth="2.4" />
      </svg>
    );
  }

  if (tone === "error") {
    return (
      <svg viewBox="0 0 20 20" fill="none" className="h-3.5 w-3.5" aria-hidden="true">
        <path d="m6 6 8 8m0-8-8 8" stroke="currentColor" strokeWidth="2.4" />
      </svg>
    );
  }

  if (tone === "warning") {
    return (
      <svg viewBox="0 0 20 20" fill="none" className="h-3.5 w-3.5" aria-hidden="true">
        <path d="M10 4.5v7" stroke="currentColor" strokeWidth="2.4" />
        <circle cx="10" cy="15" r="1.25" fill="currentColor" />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 20 20" fill="none" className="h-3.5 w-3.5" aria-hidden="true">
      <circle cx="10" cy="5" r="1.25" fill="currentColor" />
      <path d="M10 8.5v7" stroke="currentColor" strokeWidth="2.4" />
    </svg>
  );
}

function Toast({ entry, onDismiss }: { entry: ToastEntry; onDismiss: (id: string) => void }) {
  const [leaving, setLeaving] = useState(false);
  const timerRef = useRef<number | undefined>(undefined);
  const exitTimerRef = useRef<number | undefined>(undefined);
  const animationFrameRef = useRef<number | undefined>(undefined);
  const progressRef = useRef<HTMLDivElement | null>(null);
  const remainingRef = useRef(entry.durationMs);
  const startedAtRef = useRef(0);
  const hoveredRef = useRef(false);
  const focusedRef = useRef(false);
  const leavingRef = useRef(false);

  const clearTimer = useCallback(() => {
    if (timerRef.current !== undefined) window.clearTimeout(timerRef.current);
    if (animationFrameRef.current !== undefined) {
      window.cancelAnimationFrame(animationFrameRef.current);
    }
    timerRef.current = undefined;
    animationFrameRef.current = undefined;
  }, []);

  const updateProgress = useCallback(
    (remainingMs: number) => {
      if (!progressRef.current || entry.durationMs === 0) return;
      const fraction = Math.max(0, Math.min(1, remainingMs / entry.durationMs));
      progressRef.current.style.transform = `scaleX(${fraction})`;
    },
    [entry.durationMs],
  );

  const beginDismiss = useCallback(() => {
    if (leavingRef.current) return;
    leavingRef.current = true;
    clearTimer();
    updateProgress(0);
    setLeaving(true);
    exitTimerRef.current = window.setTimeout(() => onDismiss(entry.id), EXIT_DURATION_MS);
  }, [clearTimer, entry.id, onDismiss, updateProgress]);

  const startTimer = useCallback(() => {
    if (entry.durationMs === 0 || remainingRef.current <= 0) return;
    clearTimer();
    startedAtRef.current = Date.now();
    timerRef.current = window.setTimeout(beginDismiss, remainingRef.current);

    const startingRemaining = remainingRef.current;
    const updateFrame = () => {
      const remaining = startingRemaining - (Date.now() - startedAtRef.current);
      updateProgress(remaining);
      if (remaining > 0) {
        animationFrameRef.current = window.requestAnimationFrame(updateFrame);
      } else {
        animationFrameRef.current = undefined;
      }
    };
    updateProgress(startingRemaining);
    animationFrameRef.current = window.requestAnimationFrame(updateFrame);
  }, [beginDismiss, clearTimer, entry.durationMs, updateProgress]);

  const pauseTimer = useCallback(() => {
    if (timerRef.current === undefined) return;
    remainingRef.current = Math.max(
      0,
      remainingRef.current - (Date.now() - startedAtRef.current),
    );
    clearTimer();
    updateProgress(remainingRef.current);
  }, [clearTimer, updateProgress]);

  const pause = useCallback(() => {
    pauseTimer();
  }, [pauseTimer]);

  const resume = useCallback(() => {
    if (hoveredRef.current || focusedRef.current) return;
    startTimer();
  }, [startTimer]);

  useEffect(() => {
    startTimer();
    return () => {
      clearTimer();
      if (exitTimerRef.current !== undefined) window.clearTimeout(exitTimerRef.current);
    };
  }, [clearTimer, startTimer]);

  return (
    <div
      role={entry.tone === "error" ? "alert" : "status"}
      aria-atomic="true"
      onMouseEnter={() => {
        hoveredRef.current = true;
        pause();
      }}
      onMouseLeave={() => {
        hoveredRef.current = false;
        resume();
      }}
      onFocusCapture={() => {
        focusedRef.current = true;
        pause();
      }}
      onBlurCapture={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) {
          focusedRef.current = false;
          resume();
        }
      }}
      className={cn(
        "pointer-events-auto relative flex min-h-16 w-full items-center gap-3 overflow-hidden rounded-md border border-slate-200 bg-white px-3.5 py-3 pr-9 text-slate-900 shadow-[0_8px_24px_rgba(15,23,42,0.24)] sm:w-96 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100",
        leaving ? "ocs-toast-exit" : "ocs-toast-enter",
      )}
    >
      <span
        className={cn(
          "flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-white",
          ACCENT_STYLES[entry.tone],
        )}
      >
        <ToastIcon tone={entry.tone} />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-medium leading-5">{entry.title}</div>
        {entry.description ? (
          <div className="mt-0.5 text-xs leading-5 text-slate-500 dark:text-slate-400">
            {entry.description}
          </div>
        ) : null}
      </div>
      <button
        type="button"
        aria-label="Dismiss notification"
        onClick={beginDismiss}
        className="absolute right-1 top-1 flex h-6 w-6 items-center justify-center rounded text-slate-500 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-1 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white"
      >
        <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5" aria-hidden="true">
          <path d="M5.22 5.22a.75.75 0 0 1 1.06 0L10 8.94l3.72-3.72a.75.75 0 1 1 1.06 1.06L11.06 10l3.72 3.72a.75.75 0 0 1-1.06 1.06L10 11.06l-3.72 3.72a.75.75 0 0 1-1.06-1.06L8.94 10 5.22 6.28a.75.75 0 0 1 0-1.06Z" />
        </svg>
      </button>
      {entry.durationMs > 0 ? (
        <div className="absolute inset-x-0 bottom-0 h-1 bg-slate-100 dark:bg-slate-800">
          <div
            ref={progressRef}
            className={cn(
              "h-full w-full origin-left will-change-transform",
              ACCENT_STYLES[entry.tone],
            )}
          />
        </div>
      ) : null}
    </div>
  );
}

export function ToastProvider({
  children,
  defaultDurationMs = DEFAULT_DURATION_MS,
}: ToastProviderProps) {
  const [toasts, setToasts] = useState<ToastEntry[]>([]);
  const nextIdRef = useRef(0);

  const dismissToast = useCallback((id: string) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const showToast = useCallback(
    (options: ToastOptions) => {
      const id = `toast-${++nextIdRef.current}`;
      const entry: ToastEntry = {
        ...options,
        id,
        tone: options.tone ?? "info",
        durationMs: Math.max(0, options.durationMs ?? defaultDurationMs),
      };
      setToasts((current) => [...current, entry].slice(-MAX_VISIBLE_TOASTS));
      return id;
    },
    [defaultDurationMs],
  );
  const api = useMemo(() => ({ showToast, dismissToast }), [dismissToast, showToast]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        aria-label="Notifications"
        className="pointer-events-none fixed bottom-3 left-1/2 z-[70] flex w-[calc(100%-1.5rem)] -translate-x-1/2 flex-col items-center gap-2 sm:bottom-4 sm:w-auto"
      >
        {toasts.map((entry) => (
          <Toast key={entry.id} entry={entry} onDismiss={dismissToast} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast must be used within a ToastProvider");
  return value;
}
