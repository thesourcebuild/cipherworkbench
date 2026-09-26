import type { ReactNode } from "react";
import { TutorialRevealClient } from "./tutorial-reveal-client";

export function TutorialCallout({
  title,
  children,
  type = "info",
}: {
  title: string;
  children?: ReactNode;
  type?: "info" | "warning" | "security";
}) {
  return (
    <aside
      className={`my-6 rounded-r-xl rounded-l-md border border-l-4 p-5 shadow-2xs transition-all ${
        type === "security" || type === "info"
          ? "border-indigo-200/80 border-l-indigo-600 bg-gradient-to-r from-indigo-50/80 via-indigo-50/40 to-transparent dark:border-indigo-900/50 dark:border-l-indigo-400 dark:from-indigo-950/30 dark:via-indigo-950/10"
          : "border-amber-200/80 border-l-amber-500 bg-gradient-to-r from-amber-50/80 via-amber-50/40 to-transparent dark:border-amber-900/50 dark:border-l-amber-400 dark:from-amber-950/30 dark:via-amber-950/10"
      }`}
    >
      <div className="flex items-start gap-3">
        <div
          className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-md ${
            type === "security" || type === "info"
              ? "bg-indigo-600 text-white dark:bg-indigo-500"
              : "bg-amber-500 text-white"
          }`}
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 20 20"
            fill="currentColor"
            className="h-3.5 w-3.5"
          >
            <path
              fillRule="evenodd"
              d="M10 1a4.5 4.5 0 0 0-4.5 4.5V9H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2h-.5V5.5A4.5 4.5 0 0 0 10 1Zm3 8V5.5a3 3 0 1 0-6 0V9h6Z"
              clipRule="evenodd"
            />
          </svg>
        </div>
        <div className="min-w-0 flex-1">
          <p className="m-0 text-sm font-bold text-slate-900 dark:text-white">{title}</p>
          <div className="mt-2 text-sm leading-relaxed text-slate-700 dark:text-slate-300 [&>p]:my-2 [&>ul]:my-2 [&>ul]:space-y-1.5 [&>ul]:pl-5 [&>ul]:list-disc">
            {children}
          </div>
        </div>
      </div>
    </aside>
  );
}

export function TutorialReveal({
  summary = "Reveal explanation",
  children,
}: {
  summary?: string;
  children?: ReactNode;
}) {
  return <TutorialRevealClient summary={summary}>{children}</TutorialRevealClient>;
}

export function StatusBadge({
  status,
}: {
  status: "trusted" | "warning" | "airgapped" | "self-issued";
}) {
  switch (status) {
    case "trusted":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-300 bg-emerald-50 px-2.5 py-0.5 text-xs font-semibold text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
          Trusted
        </span>
      );
    case "warning":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-300 bg-amber-50 px-2.5 py-0.5 text-xs font-semibold text-amber-700 dark:border-amber-800 dark:bg-amber-950/60 dark:text-amber-300">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
          Warning
        </span>
      );
    case "airgapped":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-indigo-300 bg-indigo-50 px-2.5 py-0.5 text-xs font-semibold text-indigo-700 dark:border-indigo-800 dark:bg-indigo-950/60 dark:text-indigo-300">
          <span className="h-1.5 w-1.5 rounded-full bg-indigo-500" />
          Air-gapped
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-slate-300 bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
          {status}
        </span>
      );
  }
}
