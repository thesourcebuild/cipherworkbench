"use client";

import { useMemo, useState } from "react";
import { OUTPUT_ENCODING_LABEL, type OutputEncoding } from "@ocs/contracts";
import { encodeOutput, type IdentifyOutcome } from "@ocs/engine";
import { Button, CopyButton, Panel, cn } from "@ocs/ui";
import { platform } from "@ocs/platform";
import { formatBytes, formatBytesShort } from "./input-state";
import type { VariantsState } from "./use-variants";

export interface VariantsPanelProps {
  state: VariantsState;
  /**
   * The encodings this tool's output can be spelled in, not the one the Result panel is showing.
   *
   * This panel picks its own from the list -- see `initialEncoding` -- because the two are answering
   * different questions. The Result panel shows one value to read and copy; this table exists to be
   * compared, by eye, against something printed somewhere else, and the conventional spelling of a
   * check value in a datasheet or in the RevEng catalogue is upper-case hex.
   */
  outputEncodings: readonly OutputEncoding[];
  /**
   * Which rows produce the value pasted into Verify, or undefined when that question does not apply.
   *
   * Computed by the workbench rather than here, because the Verify panel needs the same answer to
   * point at a row it did not match -- and two panels deriving one verdict is the mirror this repo
   * keeps finding drifted. One `identifyAmong` call, two consumers.
   */
  identity: IdentifyOutcome | undefined;
  onRun: () => void;
  onStop: () => void;
  canRun: boolean;
}

/**
 * The same input under every sibling variant, with the parameters that produced each value.
 *
 * One panel for every family, driven by `ToolDefinition.variants` -- the same arrangement as
 * `OptionsForm`, `ResultPanel` and `TablePanel`, and for the same reason. CRC is the immediate need
 * and nothing in here knows what a CRC is: the family supplies its own column headings alongside its
 * rows, and this renders whatever it gets.
 *
 * It answers a question the rest of the app cannot. You have an eight-bit checksum off a device and
 * you do not know which of the twenty CRC-8 models produced it; reading the seven parameters in the
 * Info table will not tell you. Computing all twenty and finding the row that matches will -- and the
 * parameter columns beside it are what you then need to reproduce the value in your own code, without
 * going back to the dropdown to select the model and read them off somewhere else.
 *
 * **Its own Run, and nothing else drives it.** Not `Auto update`, not the Result panel's `Compute`.
 * Twenty engines over a large file is a decision to make deliberately rather than something that
 * happens because a keystroke landed, and the button is the place that decision is made. It becomes
 * Stop while a run is in flight, because the thing you most want after starting a hundred-gigabyte
 * job is to not have started it.
 *
 * The rows are on screen before any of that: names, aliases and parameters come off the spec, so the
 * table is populated the moment the tool loads and only the Result column waits for Run.
 *
 * **And it identifies.** Paste a value into Verify and the rows that produce it are marked, which is
 * the whole point of computing them all: reading twenty hex bytes to find one is the task the Verify
 * panel exists because people are bad at. See `identify` below for why more than one row can match.
 */
export function VariantsPanel({
  state,
  outputEncodings,
  identity,
  onRun,
  onStop,
  canRun,
}: VariantsPanelProps) {
  /**
   * Local state, and it is display rather than spec -- so it is not in the share link and not in
   * saved state, on the same reasoning as the Table panel's copy-format and separator controls: it
   * changes how the bytes are spelled, never what they are.
   *
   * The workbench remounts this on every tool change, so the choice resets per tool rather than
   * carrying a hex-upper preference onto a tool whose output is text.
   */
  const [encoding, setEncoding] = useState<OutputEncoding>(() =>
    initialEncoding(outputEncodings),
  );
  const { table, values, status, progress, stale } = state;
  // The family names its own rows -- "model", "checksum", "algorithm". See `ToolVariantTable.noun`.
  const noun = table?.noun ?? "variant";
  const columns = table?.columns ?? NO_COLUMNS;
  const rows = table?.rows ?? NO_ROWS;
  const running = status === "running";

  const shown = useMemo(() => {
    const out = new Map<string, string>();
    for (const [id, bytes] of values) out.set(id, encodeOutput(bytes, encoding));
    return out;
  }, [values, encoding]);

  /**
   * Tab-separated with a header line, which is what pastes into a spreadsheet as columns and into a
   * diff as fields. The Result column is in whatever encoding the panel is showing, so what lands on
   * the clipboard is what is on screen.
   */
  const copyText = useMemo(() => {
    const head = ["Model", "Result", ...columns].join("\t");
    const body = rows.map((row) =>
      [row.label, shown.get(row.id) ?? "", ...row.cells].join("\t"),
    );
    return [head, ...body].join("\n");
  }, [columns, rows, shown]);

  /** One figure for every row: `runStreams` reads once and feeds all of them. */
  const fraction =
    progress?.totalBytes && progress.totalBytes > 0
      ? Math.min(progress.bytesProcessed / progress.totalBytes, 1)
      : undefined;

  const matched = useMemo(() => new Set(identity?.ids ?? []), [identity]);
  const labelFor = (id: string) => rows.find((row) => row.id === id)?.label ?? id;

  return (
    <Panel
      data-ocs-variants=""
      title={
        <span className="flex items-center gap-2">
          All variants
          <span
            data-ocs-variants-count=""
            className="rounded border border-slate-300 px-1.5 py-px text-[10px] font-medium text-slate-500 dark:border-slate-700 dark:text-slate-400"
          >
            {rows.length} {rows.length === 1 ? noun : `${noun}s`}
          </span>
        </span>
      }
      description={describe(state, identity, labelFor, noun)}
      collapsible
      actions={
        <div className="flex items-center gap-2">
          {/*
            Run first, then Copy. It is the order the two are used in -- there is nothing to copy
            until a run has happened -- and it puts the primary action nearest the heading it belongs
            to. Copy ends up rightmost, which is where the Result and Table panels put theirs.

            One button for the whole table, not one per row: there is a single read head, so a
            per-row control would offer twenty ways to start the same pass.
          */}
          {outputEncodings.length > 1 && (
            /*
              Its own selector rather than following the Result panel's.

              Without one, "upper hex by default" could not be a default at all: the only way to
              change it would be to change what the Result panel shows, which is a different
              question. With one, matching the Result panel is a single click -- and the two being
              independent is what lets this table stay in the spelling somebody is comparing against
              while the value above it stays in the spelling they are copying.
            */
            <select
              data-ocs-variants-encoding=""
              aria-label="Variants output encoding"
              value={encoding}
              onChange={(event) => setEncoding(event.target.value as OutputEncoding)}
              className="rounded-md border border-slate-300 bg-white px-1.5 py-1 text-[11px] dark:border-slate-700 dark:bg-slate-950"
            >
              {outputEncodings.map((option) => (
                <option key={option} value={option}>
                  {OUTPUT_ENCODING_LABEL[option]}
                </option>
              ))}
            </select>
          )}
          <Button
            data-ocs-variants-run=""
            size="sm"
            variant={running ? "secondary" : "primary"}
            className="h-8"
            disabled={!running && !canRun}
            onClick={running ? onStop : onRun}
            title={
              running
                ? "Stop reading. Nothing already shown is discarded."
                : "Compute every variant over the current input. Independent of Auto update and of Compute."
            }
          >
            {running ? "Stop" : "Run"}
          </Button>
          <CopyButton
            value={() => copyText}
            disabled={values.size === 0}
            writeClipboard={(text) => platform().copyToClipboard(text)}
          />
        </div>
      }
    >
      {rows.length === 0 ? (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          This tool has no sibling variants to compare.
        </p>
      ) : (
        /*
          Scrolls both ways in its own box: eight columns of CRC-64 is wider than the column this
          sits in, and thirty rows of CRC-16 is taller than anything else on the page.
        */
        <div className="max-h-96 overflow-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              {/*
                Sticky, because scrolling thirty rows past the headings leaves six unlabelled hex
                columns that all look exactly alike.
              */}
              <tr className="sticky top-0 bg-white dark:bg-slate-900">
                <th className={HEAD}>Model</th>
                <th className={cn(HEAD, RESULT_TINT, "w-1/3")}>Result</th>
                {columns.map((column) => (
                  <th key={column} className={HEAD}>
                    {column}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  data-ocs-variant={row.id}
                  data-ocs-variant-match={matched.has(row.id) ? "" : undefined}
                  /**
                   * The selected row is marked rather than moved to the top. Catalogue order means a
                   * row stays where it was when you change the model, so the value you were
                   * comparing against does not jump somewhere else on the screen. A *matched* row
                   * stays put for the same reason, and wins over the selected tint: which model you
                   * happen to have in the dropdown is a setting, and which one produced the value in
                   * your hand is an answer.
                   */
                  className={cn(
                    "border-b border-slate-100 align-top last:border-0 dark:border-slate-800/60",
                    row.selected && "bg-slate-100/70 dark:bg-slate-800/50",
                    matched.has(row.id) &&
                      "bg-(--color-verify-match)/12 dark:bg-(--color-verify-match)/15",
                  )}
                >
                  <td className="py-1.5 pr-3 whitespace-nowrap">
                    <span
                      className={cn(
                        row.selected
                          ? "font-medium text-slate-900 dark:text-slate-100"
                          : "text-slate-600 dark:text-slate-300",
                      )}
                    >
                      {row.label}
                    </span>
                    {/*
                      Stacked under the name, one per line, in the muted weight. They are how a
                      reader finds the row rather than what it is called: nobody is looking for
                      "CRC-8/I-432-1", they are looking for "CRC-8/ITU".
                    */}
                    {row.aliases?.map((alias) => (
                      <span
                        key={alias}
                        className="block text-[11px] text-slate-400 dark:text-slate-500"
                      >
                        {alias}
                      </span>
                    ))}
                  </td>
                  <td
                    data-ocs-variant-value={row.id}
                    className={cn("py-1.5 pr-3", RESULT_TINT)}
                  >
                    {/*
                      A bar per row while the pass runs, and every one of them is at the same
                      position -- there is one read head feeding all the engines, so there is one
                      figure to report. It is per row rather than one bar above the table because
                      the thing you are watching is a row: the eye is already on the model you are
                      trying to match, and that is where "not yet" belongs.
                    */}
                    {running ? (
                      <RowBar fraction={fraction} />
                    ) : (
                      <span
                        className={cn(
                          "font-mono font-medium break-all text-slate-900 dark:text-slate-100",
                          stale && "opacity-50",
                        )}
                      >
                        {shown.get(row.id) ?? (
                          <span className="text-slate-300 dark:text-slate-600">—</span>
                        )}
                      </span>
                    )}
                  </td>
                  {row.cells.map((cell, index) => (
                    <td
                      key={columns[index] ?? index}
                      className="py-1.5 pr-3 font-mono whitespace-nowrap text-slate-500 dark:text-slate-400"
                    >
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

const HEAD =
  "border-b border-slate-200 py-1.5 pr-3 font-medium whitespace-nowrap text-slate-500 dark:border-slate-800 dark:text-slate-400";

/**
 * Upper-case hex where the tool offers it, and the tool's own first encoding otherwise.
 *
 * Upper rather than lower, which is the one place in this app where the two differ. A check value is
 * printed upper-case almost everywhere it is printed at all -- the RevEng catalogue, the CRC entries
 * in a peripheral datasheet, the tables in a protocol specification -- and this table's whole job is
 * to be read against one of those. The Result panel keeps lower-case hex, because a digest is
 * something you copy rather than something you compare by eye.
 *
 * Not hardcoded to `hex-upper`: a tool whose output is text offers only `utf-8`, and a tool that
 * opens on `binary` -- the parity family does -- has a reason to. Falling back to the tool's first
 * declared encoding keeps this from overriding a family that has already made that decision.
 */
function initialEncoding(offered: readonly OutputEncoding[]): OutputEncoding {
  if (offered.includes("hex-upper")) return "hex-upper";
  return offered[0] ?? "hex";
}

/**
 * The Result column's tint, on the heading and on every cell, so it reads as one column.
 *
 * It is the one column that is an *answer*; the six beside it are the parameters that produced it.
 * Weight alone stopped being enough once there were six of them -- the eye scans a table by
 * background before it scans by boldness, which is how the reference calculators separate it too.
 *
 * A translucent slate rather than a solid one, because it has to sit over two grounds: white, and the
 * shaded row of the currently selected variant. `bg-slate-100` would vanish on the latter; an alpha
 * tint darkens whatever is behind it, so the column stays a column and the selected row stays
 * selected.
 */
const RESULT_TINT = "bg-slate-500/10 pl-2 dark:bg-slate-400/10";

/**
 * Stable empty arrays, so `table?.columns ?? NO_COLUMNS` keeps its identity between renders.
 *
 * `?? []` allocates a fresh one every time, which changes a memo's dependencies on every render and
 * quietly turns it into a plain call. eslint catches exactly this.
 */
const NO_COLUMNS: readonly string[] = [];
const NO_ROWS: NonNullable<VariantsState["table"]>["rows"] = [];

/** Indeterminate when the source cannot say how long it is -- typed text, which finishes at once. */
function RowBar({ fraction }: { fraction: number | undefined }) {
  return (
    <span className="block h-1.5 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
      <span
        className={cn(
          "block h-full rounded-full bg-slate-900 transition-[width] duration-150 dark:bg-slate-100",
          fraction === undefined && "w-1/3 animate-pulse",
        )}
        style={fraction === undefined ? undefined : { width: `${fraction * 100}%` }}
      />
    </span>
  );
}

/**
 * The panel's one line, and the verdict takes precedence over everything else it could say.
 *
 * Once a value has been pasted and matched, "which one is it" is the only thing anyone is reading this
 * line for; the row count and the run state are things they can see. The wording is deliberately
 * different for one match and several -- a table that said "matches CRC-8/I-432-1" and quietly meant
 * "and also MAXIM-DOW" would be the most damaging output this panel could produce, because it is the
 * one somebody writes down.
 */
function describe(
  state: VariantsState,
  identity: { ids: readonly string[]; readAs?: string; anyParsed: boolean } | undefined,
  labelFor: (id: string) => string,
  noun: string,
): string {
  if (state.status === "running") {
    const done = state.progress?.bytesProcessed ?? 0;
    const total = state.progress?.totalBytes;
    // One pass over the input, shared by every row -- so this is the whole table's position.
    return total === undefined
      ? `Reading… ${formatBytes(done)} so far.`
      : `${formatBytesShort(done)} of ${formatBytes(total)} — ${Math.round((done / Math.max(total, 1)) * 100)}%`;
  }
  if (state.status === "error") return state.error ?? "Could not run.";
  if (state.stale)
    return "The input changed after these were computed. Run again to update them.";

  if (identity) {
    const read = identity.readAs === undefined ? "" : `, read as ${identity.readAs}`;
    if (identity.ids.length === 1) {
      return `The value you pasted is ${labelFor(identity.ids[0]!)}${read}.`;
    }
    if (identity.ids.length > 1) {
      /**
       * Every one of them, named, and the reason said out loud. These are not near-misses: the models
       * produce the identical value over this input, which at eight bits happens for whole pairs. The
       * honest advice is a longer message, because a wider input separates them.
       */
      const names = identity.ids.map(labelFor).join(", ");
      return `${identity.ids.length} ${noun}s produce that value${read}: ${names}. They agree on this input — try a longer one to tell them apart.`;
    }
    if (identity.anyParsed) {
      return `No ${noun} here produces the value you pasted. Check the Verify panel for the length it read.`;
    }
  }

  if (state.values.size > 0) return "Every variant of this family over the current input.";
  return "Press Run to compute every variant of this family. Independent of Auto update.";
}
