"use client";

import { useState } from "react";
import type { ToolResultField } from "@ocs/engine";

/**
 * A label/value table. Two callers: the Result panel's output fields and the Settings rail's Info
 * section.
 *
 * One component because both are the same kind of data -- a short name and a short value, in rows to
 * be compared down a column. What differs is only where the data came from: a computation, or the
 * spec.
 *
 * A table, because that is what this data is. Each field used to render as its own stacked block --
 * label row, bordered value block, hint paragraph -- which is four lines each, so CRC-32's seven
 * parameters filled the panel with 28 rows of mostly whitespace to say seven short things. Nothing
 * about a polynomial needs a bordered block of its own.
 *
 * `<th scope="row">` rather than a `<dl>`: it pairs each label with its value for a screen reader,
 * which the previous div-per-field arrangement only implied visually.
 *
 * Hints move to the label's tooltip, matching how the options form treats an option's `detail` -- a
 * dotted underline and `cursor-help`. They are worth keeping (the check value's hint tells you how
 * to verify this tool against the RevEng catalogue) and they are not worth a paragraph each.
 */
export function FieldTable({ fields }: { fields: readonly ToolResultField[] }) {
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
                {shown ? field.value : "\u2022".repeat(Math.min(field.value.length, 48))}
                {/*
                  No Copy button per row. Seven of them down the side of seven short values was
                  furniture rather than function: these are two to twelve characters long and
                  selectable with a mouse, and the one value people do copy -- the result itself --
                  has a Copy in the panel header. Show/Hide stays and moves in here, because a
                  masked value cannot be selected at all, so it is the one control a row needs.
                */}
                {field.secret && (
                  <button
                    type="button"
                    onClick={() => toggle(field.label)}
                    className="ml-2 font-sans text-[11px] text-slate-500 underline decoration-dotted hover:text-slate-700 dark:hover:text-slate-200"
                  >
                    {shown ? "Hide" : "Show"}
                  </button>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
