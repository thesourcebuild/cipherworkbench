"use client";

import { useState, type ReactNode } from "react";

export function TutorialRevealClient({
  summary,
  children,
}: {
  summary: string;
  children?: ReactNode;
}) {
  const [open, setOpen] = useState(false);

  return (
    <section className="my-6 overflow-hidden rounded-xl border border-slate-200/90 bg-white shadow-2xs dark:border-slate-800 dark:bg-slate-900/70 transition-all">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
        className="flex w-full items-center justify-between gap-3 px-5 py-3.5 text-left text-sm font-semibold text-slate-900 hover:bg-slate-50/80 dark:text-slate-100 dark:hover:bg-slate-800/50 transition-colors"
      >
        <div className="flex items-center gap-2.5">
          <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-md bg-indigo-100 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-400">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 20 20"
              fill="currentColor"
              className="h-3.5 w-3.5"
            >
              <path
                fillRule="evenodd"
                d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Zm-8-5a.75.75 0 0 1 .75.75v4.5a.75.75 0 0 1-1.5 0v-4.5A.75.75 0 0 1 10 5Zm0 10a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z"
                clipRule="evenodd"
              />
            </svg>
          </div>
          <span>{summary}</span>
        </div>
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 20 20"
          fill="currentColor"
          className={`h-4 w-4 shrink-0 text-slate-400 transition-transform duration-200 ${
            open ? "rotate-180" : ""
          }`}
        >
          <path
            fillRule="evenodd"
            d="M5.22 8.22a.75.75 0 0 1 1.06 0L10 11.94l3.72-3.72a.75.75 0 1 1 1.06 1.06l-4.25 4.25a.75.75 0 0 1-1.06 0L5.22 9.28a.75.75 0 0 1 0-1.06Z"
            clipRule="evenodd"
          />
        </svg>
      </button>
      {open && (
        <div className="border-t border-slate-100 px-5 py-4 text-sm text-slate-700 dark:border-slate-800/80 dark:text-slate-300">
          {children}
        </div>
      )}
    </section>
  );
}
