"use client";

import type { SecurityPosture, ToolManifest } from "@ocs/engine";
import { cn } from "@ocs/ui";

const POSTURE_STYLE: Record<SecurityPosture, string> = {
  modern: "border-emerald-300 text-emerald-700 dark:border-emerald-800 dark:text-emerald-300",
  legacy: "border-amber-300 text-amber-700 dark:border-amber-800 dark:text-amber-300",
  broken:
    "border-red-300 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950/30 dark:text-red-300",
  "not-a-mac": "border-sky-300 text-sky-700 dark:border-sky-800 dark:text-sky-300",
  "not-encryption": "border-slate-300 text-slate-600 dark:border-slate-700 dark:text-slate-300",
};

const POSTURE_LABEL: Record<SecurityPosture, string> = {
  modern: "Modern",
  legacy: "Legacy",
  broken: "Broken",
  "not-a-mac": "Not a MAC",
  "not-encryption": "Not encryption",
};

/**
 * Name, one-line summary, and the badges that say what this tool is and is not.
 *
 * `describe` comes from the tool itself and reflects the *current settings*, not
 * just the algorithm — "Computes a double SHA-256 digest — 32 bytes" changes as
 * you change the options, which is the only way a user finds out that the
 * iteration count they typed is doing what they meant.
 */
export function ToolHeader({
  manifest,
  description,
}: {
  manifest: ToolManifest | undefined;
  description: string | undefined;
}) {
  if (!manifest) return null;

  return (
    <div className="mb-4">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-base font-semibold text-slate-900 dark:text-slate-100">{manifest.label}</h1>
        <div className="flex flex-wrap items-center gap-1.5">
          <span
            className={cn(
              "shrink-0 whitespace-nowrap rounded border px-1.5 py-px text-[10px] font-medium",
              POSTURE_STYLE[manifest.security],
            )}
          >
            {POSTURE_LABEL[manifest.security]}
          </span>
          {manifest.directions.length === 1 && manifest.directions[0] === "forward" && (
            <span
              title="A one-way function. There is no inverse to compute — nothing here, or anywhere, can turn a digest back into its input."
              className="shrink-0 whitespace-nowrap cursor-help rounded border border-slate-300 px-1.5 py-px text-[10px] font-medium text-slate-500 underline decoration-dotted dark:border-slate-700 dark:text-slate-400"
            >
              One-way
            </span>
          )}
          {manifest.streaming && (
            <span
              title="Can be fed a file in chunks, so file size is not limited by memory."
              className="shrink-0 whitespace-nowrap cursor-help rounded border border-slate-300 px-1.5 py-px text-[10px] font-medium text-slate-500 underline decoration-dotted dark:border-slate-700 dark:text-slate-400"
            >
              Streaming
            </span>
          )}
        </div>
      </div>
      <p className="mt-1 text-xs text-slate-600 break-words dark:text-slate-400">
        {description ?? manifest.summary}
      </p>
    </div>
  );
}
