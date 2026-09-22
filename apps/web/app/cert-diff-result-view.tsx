"use client";

import { useState } from "react";
import type { ToolResultField, ToolResultTableRow } from "@ocs/engine";
import { cn } from "@ocs/ui";

interface CertDiffResultViewProps {
  fields: readonly ToolResultField[];
  rows: readonly ToolResultTableRow[];
  stale: boolean;
  pending: boolean;
}

const STATUS_CONFIG = {
  ok: {
    badge: "OK",
    badgeCls:
      "bg-emerald-100 text-emerald-800 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800/40",
    rowCls: "",
  },
  diff: {
    badge: "DIFF",
    badgeCls:
      "bg-red-100 text-red-800 border-red-200 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800/40",
    rowCls: "bg-red-50/40 dark:bg-red-950/10",
  },
  warn: {
    badge: "WARN",
    badgeCls:
      "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800/40",
    rowCls: "bg-amber-50/40 dark:bg-amber-950/10",
  },
  added: {
    badge: "ADDED",
    badgeCls:
      "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-800/40",
    rowCls: "bg-blue-50/40 dark:bg-blue-950/10",
  },
  removed: {
    badge: "REMOVED",
    badgeCls:
      "bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
    rowCls: "bg-slate-50/40 dark:bg-slate-900/20",
  },
} satisfies Record<
  ToolResultTableRow["status"],
  { badge: string; badgeCls: string; rowCls: string }
>;

const FIELD_STATUS_MAP: Record<string, ToolResultTableRow["status"]> = {
  "Identical Certificates": "ok",
  "Differences Detected": "diff",
  "Clean Renewal (Same Subject & SANs, Extended Validity)": "ok",
  "Exact Duplicate": "ok",
  "Modified Parameters": "diff",
  "Reused Key (Same SPKI Public Key)": "ok",
  "Key Rolled Over (New Public Key Generated)": "warn",
};

export function CertDiffResultView({
  fields,
  rows,
  stale,
  pending,
}: CertDiffResultViewProps) {
  const [expandedCells, setExpandedCells] = useState<Set<string>>(new Set());

  const toggleCell = (key: string) => {
    setExpandedCells((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const diffCount = rows.filter((r) => r.status === "diff").length;
  const warnCount = rows.filter((r) => r.status === "warn").length;

  return (
    <div className={cn("space-y-4", (stale || pending) && "opacity-60")}>
      {/* Summary pills */}
      <div className="flex flex-wrap items-center gap-2">
        {fields.map((f) => {
          const status = FIELD_STATUS_MAP[f.value];
          const cfg = status ? STATUS_CONFIG[status] : undefined;
          return (
            <span
              key={f.label}
              title={f.hint}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11px] font-medium",
                cfg
                  ? cfg.badgeCls
                  : "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300",
              )}
            >
              <span className="text-slate-500 dark:text-slate-400">{f.label}:</span>
              <span className="font-semibold">{f.value}</span>
            </span>
          );
        })}
      </div>

      {/* Quick stats */}
      <div className="flex items-center gap-3 text-[11px] text-slate-500 dark:text-slate-400">
        <span>
          <span className="font-semibold text-red-600 dark:text-red-400">{diffCount}</span>{" "}
          {diffCount === 1 ? "difference" : "differences"}
        </span>
        {warnCount > 0 && (
          <span>
            <span className="font-semibold text-amber-600 dark:text-amber-400">{warnCount}</span>{" "}
            {warnCount === 1 ? "warning" : "warnings"}
          </span>
        )}
        <span>{rows.length} properties compared</span>
      </div>

      {/* Diff table */}
      <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
        <table className="w-full border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-900">
              <th className="px-3 py-2.5 text-left font-semibold text-slate-600 dark:text-slate-400 w-[18%]">
                Property
              </th>
              <th className="px-3 py-2.5 text-left font-semibold text-slate-600 dark:text-slate-400 w-[34%]">
                Certificate 1 (Base)
              </th>
              <th className="px-3 py-2.5 text-left font-semibold text-slate-600 dark:text-slate-400 w-[34%]">
                Certificate 2 (Target)
              </th>
              <th className="px-3 py-2.5 text-center font-semibold text-slate-600 dark:text-slate-400 w-[8%]">
                Status
              </th>
              <th className="px-3 py-2.5 text-left font-semibold text-slate-600 dark:text-slate-400 w-[6%]">
                Notes
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
            {rows.map((row, i) => {
              const cfg = STATUS_CONFIG[row.status];
              const leftKey = `${i}-left`;
              const rightKey = `${i}-right`;
              const leftExpanded = expandedCells.has(leftKey);
              const rightExpanded = expandedCells.has(rightKey);
              const isChanged = row.status !== "ok";

              return (
                <tr
                  key={row.property}
                  className={cn(
                    "transition-colors",
                    cfg.rowCls,
                    "hover:bg-slate-50/70 dark:hover:bg-slate-800/30",
                  )}
                >
                  {/* Property */}
                  <td className="px-3 py-2 align-top">
                    <span className="font-semibold text-slate-800 dark:text-slate-200">
                      {row.property}
                    </span>
                  </td>

                  {/* Cert 1 value */}
                  <td className="px-3 py-2 align-top">
                    <CellValue
                      value={row.left}
                      expanded={leftExpanded}
                      highlight={isChanged}
                      side="left"
                      onToggle={() => toggleCell(leftKey)}
                    />
                  </td>

                  {/* Cert 2 value */}
                  <td className="px-3 py-2 align-top">
                    <CellValue
                      value={row.right}
                      expanded={rightExpanded}
                      highlight={isChanged}
                      side="right"
                      onToggle={() => toggleCell(rightKey)}
                    />
                  </td>

                  {/* Status badge */}
                  <td className="px-3 py-2 text-center align-top">
                    <span
                      className={cn(
                        "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold tracking-wide",
                        cfg.badgeCls,
                      )}
                    >
                      {cfg.badge}
                    </span>
                  </td>

                  {/* Notes */}
                  <td className="px-3 py-2 align-top text-[11px] text-slate-500 dark:text-slate-400">
                    {row.note ?? "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="text-[11px] text-slate-400 dark:text-slate-500">
        Click any truncated cell value to expand it.
      </p>
    </div>
  );
}

function CellValue({
  value,
  expanded,
  highlight,
  side,
  onToggle,
}: {
  value: string;
  expanded: boolean;
  highlight: boolean;
  side: "left" | "right";
  onToggle: () => void;
}) {
  const isTruncatable = value.length > 60;
  const display = !isTruncatable || expanded ? value : `${value.slice(0, 58)}…`;

  return (
    <span
      onClick={isTruncatable ? onToggle : undefined}
      title={isTruncatable ? (expanded ? "Click to collapse" : "Click to expand") : undefined}
      className={cn(
        "block break-all font-mono text-[11px] leading-relaxed",
        highlight && side === "left"
          ? "text-red-700 dark:text-red-400"
          : highlight && side === "right"
            ? "text-emerald-700 dark:text-emerald-400"
            : "text-slate-800 dark:text-slate-200",
        isTruncatable && "cursor-pointer hover:opacity-80",
      )}
    >
      {display}
    </span>
  );
}
