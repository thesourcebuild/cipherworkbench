"use client";

import { useMemo, useState } from "react";
import {
  formatTable,
  isSourceFormat,
  TABLE_COPY_FORMATS,
  type TableCopyDelimiter,
  type TableCopyFormat,
  type ToolTable,
} from "@ocs/engine";
import { CopyButton, Panel } from "@ocs/ui";
import { platform } from "@ocs/platform";

export interface TablePanelProps {
  tables: readonly ToolTable[];
}

/**
 * The constant tables an algorithm is built from.
 *
 * One panel for every family, driven by `ToolDefinition.tables()` -- the same arrangement as
 * `OptionsForm` and `ResultPanel`, and for the same reason. A CRC's lookup table is the immediate
 * need, but nothing here knows what a CRC is: it renders a list of strings in a grid, and any tool
 * that wants to show its S-box, its round constants or its subkey schedule gets this for free.
 *
 * Collapsed by default. It is reference material rather than an answer, and 256 cells unfolding
 * under every result would push the Verify panel off the screen for the majority of visits that
 * never need it.
 *
 * The controls are display-only and deliberately local state rather than spec options: none of them
 * changes what the tool computes, so putting them in the spec would put them in a share link and in
 * saved state for no gain. `ResultPanel`'s output-encoding selector is local for the same reason.
 *
 * The copy formats live in `@ocs/engine`'s `formatTable`, not here. Emitting a C array that compiles
 * and a Rust one whose declared length matches its contents is pure logic and worth a test, and a
 * defect in either survives a glance at the screen.
 */
export function TablePanel({ tables }: TablePanelProps) {
  const [selectedId, setSelectedId] = useState<string>(tables[0]?.id ?? "");
  const [format, setFormat] = useState<TableCopyFormat>("hex");
  const [delimiter, setDelimiter] = useState<TableCopyDelimiter>("space");
  const [showPrefix, setShowPrefix] = useState(true);

  // A tool switch can leave a `selectedId` the new tool does not have, so fall back rather than
  // render an empty grid.
  const table = tables.find((t) => t.id === selectedId) ?? tables[0];

  const copyText = useMemo(
    () => (table ? formatTable(table, { format, delimiter, prefix: showPrefix }) : ""),
    [table, format, delimiter, showPrefix],
  );

  // Every hook above runs unconditionally; the early return comes after them.
  if (!table) return null;

  const cell = (value: string) => (showPrefix ? `0x${value}` : value);

  /**
   * Column width in `ch`, from the longest cell.
   *
   * Fixed rather than `auto`, so switching from CRC-8 to CRC-64 does not reflow the grid into a
   * different shape -- and so a table whose entries differ in rendered length still lines up.
   */
  const widest = table.values.reduce((max, v) => Math.max(max, cell(v).length), 1);

  return (
    <Panel
      // Hooks for the packaged smoke probe. The panel is collapsed by default, so a render fault in
      // here is invisible to everything except something that opens it.
      data-ocs-table={table.id}
      /**
       * The count is a badge on the heading, not a caption in the actions column.
       *
       * It is a fact about the table rather than a caption for the Copy button, and it reads that
       * way on the line that names the thing -- the same shape as the header's posture badge. It sat
       * under the button, which put a number in the top-right corner of the panel with nothing to
       * say whether it counted cells, columns or bytes.
       *
       * Inside the collapse toggle, because `title` is what that button wraps. Clicking the badge
       * therefore folds the panel, which is right: it is a label, and a wider target for the one
       * control the header has.
       */
      title={
        <span className="flex items-center gap-2">
          Table
          <span
            // Compared against the rendered cell count by the smoke probe. A count that disagreed
            // with the grid beside it would be the panel's most quietly wrong state.
            data-ocs-table-count=""
            className="rounded border border-slate-300 px-1.5 py-px text-[10px] font-medium text-slate-500 dark:border-slate-700 dark:text-slate-400"
          >
            {table.values.length} {table.values.length === 1 ? "entry" : "entries"}
          </span>
        </span>
      }
      description={table.summary}
      collapsible
      defaultOpen={false}
      actions={
        /*
          The Result panel's own button, not a look-alike: `CopyButton` carries the size, the
          variant, the "Copied" flip and its timeout, so the two cannot drift apart. This was a
          hand-rolled copy of all four, which is exactly how two buttons end up almost matching.

          In the header rather than down with the controls, so it is reachable without scrolling
          past 256 cells -- and without expanding the panel at all, which copies in the default hex
          form. The `actions` slot is a sibling of the collapse toggle, not inside it, so this does
          not fold the panel when clicked.
        */
        <CopyButton
          value={() => copyText}
          disabled={copyText === ""}
          writeClipboard={(text) => platform().copyToClipboard(text)}
        />
      }
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          {tables.length > 1 && (
            <label className="flex items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-300">
              Table
              <select
                data-ocs-table-select
                value={table.id}
                onChange={(event) => setSelectedId(event.target.value)}
                className="rounded border border-slate-300 bg-white px-1.5 py-0.5 text-[11px] dark:border-slate-700 dark:bg-slate-900"
              >
                {tables.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.label}
                  </option>
                ))}
              </select>
            </label>
          )}

          <label className="flex items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-300">
            Copy as
            <select
              value={format}
              onChange={(event) => setFormat(event.target.value as TableCopyFormat)}
              className="rounded border border-slate-300 bg-white px-1.5 py-0.5 text-[11px] dark:border-slate-700 dark:bg-slate-900"
            >
              {/* From the engine's list, so the labels cannot drift from the formats. */}
              {TABLE_COPY_FORMATS.map((entry) => (
                <option key={entry.value} value={entry.value}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>

          {/* Only the hex form has anything between the values to choose. */}
          {format === "hex" && (
            <label className="flex items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-300">
              Separator
              <select
                value={delimiter}
                onChange={(event) => setDelimiter(event.target.value as TableCopyDelimiter)}
                className="rounded border border-slate-300 bg-white px-1.5 py-0.5 text-[11px] dark:border-slate-700 dark:bg-slate-900"
              >
                <option value="space">Space</option>
                <option value="comma">Comma</option>
                <option value="newline">One per line</option>
              </select>
            </label>
          )}

          {/*
            Hidden for the source formats rather than disabled: they always prefix, because a C
            array of bare hex digits does not compile and `77073096` is a decimal literal in every
            language offered here. A control that had no effect would be worse than its absence.
          */}
          {!isSourceFormat(format) && (
            <label className="flex items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-300">
              <input
                type="checkbox"
                checked={showPrefix}
                onChange={(event) => setShowPrefix(event.target.checked)}
                className="h-3 w-3"
              />
              0x prefix
            </label>
          )}
        </div>

        {/* Scrolls in both directions inside its own box: a 64-bit table is wider than the column. */}
        <div className="max-h-96 overflow-auto rounded border border-slate-200 bg-slate-50 p-2 font-mono text-[11px] dark:border-slate-800 dark:bg-slate-900/60">
          <div
            className="grid gap-x-2 gap-y-0.5"
            style={{ gridTemplateColumns: `repeat(${table.columns}, ${widest}ch)` }}
          >
            {/*
              A flat map into a fixed column count: the rows fall out of the grid, so there is no
              per-row wrapper and no offset column. The index is on hover instead -- it is what you
              look a value up by, and a `title` costs nothing beside 256 cells already in the DOM.
            */}
            {table.values.map((value, index) => (
              <span
                key={index}
                data-ocs-table-cell={index}
                title={`[${index}]`}
                className="text-right text-slate-700 dark:text-slate-200"
              >
                {cell(value)}
              </span>
            ))}
          </div>
        </div>
      </div>
    </Panel>
  );
}
