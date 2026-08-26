"use client";

import type { Diagnostic, DiagnosticLevel } from "@ocs/contracts";
import type { LintResult } from "@ocs/engine";
import { Button, Panel, cn } from "@ocs/ui";

const LEVEL_STYLE: Record<DiagnosticLevel, string> = {
  error: "border-l-(--color-severity-error) bg-red-50/60 dark:bg-red-950/20",
  insecure: "border-l-(--color-severity-insecure) bg-orange-50/60 dark:bg-orange-950/20",
  warning: "border-l-(--color-severity-warning) bg-amber-50/60 dark:bg-amber-950/20",
  info: "border-l-(--color-severity-info) bg-blue-50/60 dark:bg-blue-950/20",
};

const LEVEL_LABEL: Record<DiagnosticLevel, string> = {
  error: "Error",
  insecure: "Insecure",
  warning: "Warning",
  info: "Note",
};

/**
 * Generic over the spec type so every tool reuses this panel with its own
 * `lint(spec)` result — the panel has no idea what a spec contains, it only
 * renders `Diagnostic`s and offers their fixes.
 */
export function DiagnosticsPanel<TSpec>({
  spec,
  result,
  onApplyFix,
}: {
  spec: TSpec;
  result: LintResult<TSpec>;
  onApplyFix: (next: TSpec) => void;
}) {
  return (
    <Panel
      title="Checks"
      description={
        result.diagnostics.length === 0
          ? "Nothing to flag."
          : `${result.counts.error} errors · ${result.counts.insecure} insecure · ${result.counts.warning} warnings · ${result.counts.info} notes`
      }
    >
      {result.diagnostics.length === 0 ? (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          These settings are internally consistent and nothing about them is known to be unsafe.
        </p>
      ) : (
        <ul className="space-y-2">
          {result.diagnostics.map((d: Diagnostic<TSpec>) => (
            <li
              key={`${d.code}-${d.message}`}
              className={cn("rounded-r border-l-4 px-3 py-2", LEVEL_STYLE[d.level])}
            >
              <p className="text-xs font-semibold">
                <span className="font-mono text-slate-500 dark:text-slate-400">{d.code}</span>{" "}
                {LEVEL_LABEL[d.level]} — {d.message}
              </p>
              {d.detail && (
                <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">{d.detail}</p>
              )}
              {d.fix && (
                // Its own row rather than inline with the text: this panel lives in
                // a narrow rail, and a flex row with a shrink-0 button squeezes the
                // message down to one word per line.
                <div className="mt-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => onApplyFix(d.fix!.apply(spec))}
                  >
                    {d.fix.label}
                  </Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
