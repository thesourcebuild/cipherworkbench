"use client";

import type { ReactNode } from "react";
import { cn } from "./cn";
import { Dialog } from "./dialog";

export interface GuideOverlayProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  footerNote?: string;
  children: ReactNode;
}

/**
 * A generic, full-screen documentation/guide overlay modal for interactive workbench tools.
 */
export function GuideOverlay({
  open,
  onClose,
  title,
  subtitle,
  icon,
  footerNote,
  children,
}: GuideOverlayProps) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      dismissible
      className="flex h-[92vh] w-[96vw] max-w-7xl flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white p-0 shadow-2xl dark:border-slate-800 dark:bg-slate-950"
    >
      {/* Modal Header */}
      <div className="flex shrink-0 items-center justify-between border-b border-slate-200 bg-slate-50/90 px-6 py-4 dark:border-slate-800 dark:bg-slate-900/90">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-indigo-700 text-white shadow-xs">
            {icon ?? (
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="h-5 w-5"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="m9 12 2 2 4-4" />
              </svg>
            )}
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white">
              {title}
            </h2>
            {subtitle && (
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        <button
          type="button"
          onClick={onClose}
          aria-label="Close guide"
          title="Close guide"
          className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-200 text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white transition-colors"
        >
          ✕
        </button>
      </div>

      {/* Modal Scrollable Body */}
      <div className="flex-1 overflow-y-auto px-6 py-6 sm:px-8 space-y-8 text-slate-800 dark:text-slate-200">
        {children}
      </div>

      {/* Modal Footer */}
      <div
        className={cn(
          "flex shrink-0 items-center border-t border-slate-200 bg-slate-50/90 px-6 py-3.5 dark:border-slate-800 dark:bg-slate-900/90",
          footerNote ? "justify-between" : "justify-end",
        )}
      >
        {footerNote && (
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {footerNote}
          </span>
        )}
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg bg-indigo-600 px-4 py-1.5 text-xs font-semibold text-white shadow-xs hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600 transition-colors"
        >
          Close Guide
        </button>
      </div>
    </Dialog>
  );
}
