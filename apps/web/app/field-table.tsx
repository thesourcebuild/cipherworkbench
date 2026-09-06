"use client";

import { useState } from "react";
import type { ToolResultField } from "@ocs/engine";
import { CopyIconButton } from "@ocs/ui";
import { platform } from "@ocs/platform";

export interface FieldTableProps {
  fields: readonly ToolResultField[];
  copyable?: boolean;
}

export function FieldTable({ fields, copyable = false }: FieldTableProps) {
  const [revealed, setRevealed] = useState<Set<string>>(new Set());

  const toggle = (label: string) =>
    setRevealed((prev) => {
      const next = new Set(prev);
      if (next.has(label)) next.delete(label);
      else next.add(label);
      return next;
    });

  return (
    <table className="w-full border-t border-slate-200 text-xs dark:border-slate-800">
      <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
        {fields.map((field) => {
          const shown = !field.secret || revealed.has(field.label);
          return (
            <tr key={field.label} className="align-baseline">
              <th
                scope="row"
                /**
                 * Narrow, and breaking only where a label asks it to.
                 *
                 * `whitespace-pre` rather than `nowrap`: the labels are short and fixed and the
                 * values are not, so the column that has to give is still the value's -- but a
                 * label that carries a newline gets it honoured. `nowrap` would flatten
                 * "Alias\n(Also known as)" onto one line, and `pre-line` would give the column back
                 * the soft wrapping this deliberately does not want. For every label without a
                 * newline the two render identically.
                 */
                className="w-px py-1.5 pr-3 text-left align-baseline font-semibold whitespace-pre text-[11px] uppercase tracking-wide text-slate-500"
              >
                {field.hint ? (
                  <span
                    title={field.hint}
                    className="cursor-help underline decoration-dotted decoration-slate-300 dark:decoration-slate-700"
                  >
                    {field.label}
                  </span>
                ) : (
                  field.label
                )}
              </th>
              <td className="py-1.5 font-mono break-all text-slate-900 dark:text-slate-100">
                <div className="flex items-center justify-between gap-2">
                  <span className="min-w-0 break-all">
                    {shown ? field.value : "\u2022".repeat(Math.min(field.value.length, 48))}
                  </span>
                  <div className="flex shrink-0 items-center gap-1.5">
                    {field.secret && (
                      <button
                        type="button"
                        onClick={() => toggle(field.label)}
                        className="font-sans text-[11px] text-slate-500 underline decoration-dotted hover:text-slate-700 dark:hover:text-slate-200"
                      >
                        {shown ? "Hide" : "Show"}
                      </button>
                    )}
                    {copyable && (
                      <CopyIconButton
                        value={() => field.value}
                        writeClipboard={(text) => platform().copyToClipboard(text)}
                        aria-label={`Copy ${field.label}`}
                        title={`Copy ${field.label}`}
                      />
                    )}
                  </div>
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
