"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import { MonoBlock } from "@ocs/ui";

export type WorkingViewMode = "rendered" | "raw";

const Markdown = dynamic(() => import("@ocs/ui/markdown"), {
  ssr: false,
});

export function WorkingView({ value }: { value: string }) {
  const [mode, setMode] = useState<WorkingViewMode>("rendered");

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          Working
        </p>
        <select
          data-ocs-working-view=""
          aria-label="Working view"
          value={mode}
          onChange={(event) => setMode(event.target.value as WorkingViewMode)}
          className="rounded-md border border-slate-300 bg-white px-1.5 py-1 text-[11px] dark:border-slate-700 dark:bg-slate-950"
        >
          <option value="rendered">Rendered Markdown</option>
          <option value="raw">Raw Markdown</option>
        </select>
      </div>

      {mode === "raw" ? (
        <MonoBlock data-ocs-working="" value={value} />
      ) : (
        <Markdown data-ocs-working="" data-ocs-working-rendered="" value={value} />
      )}
    </div>
  );
}

