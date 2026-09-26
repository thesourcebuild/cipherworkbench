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
    <section className="my-6 overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
        className="flex w-full items-center justify-between gap-4 bg-slate-100 px-4 py-3 text-left text-sm font-semibold text-slate-900 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700"
      >
        {summary}
        <span aria-hidden="true" className="text-lg leading-none">
          {open ? "-" : "+"}
        </span>
      </button>
      {open && <div className="px-4 py-1 text-sm">{children}</div>}
    </section>
  );
}
