"use client";

import { useMemo, useState } from "react";
import type { OutputEncoding } from "@ocs/contracts";
import { OUTPUT_ENCODING_LABEL } from "@ocs/contracts";
import { encodeOutput, type ToolResult } from "@ocs/engine";
import { Button, CopyButton, MonoBlock, Panel, cn } from "@ocs/ui";
import { platform } from "@ocs/platform";
import { FieldTable } from "./field-table";
import type { ComputeState } from "./use-compute";

/**
 * What to put in front of a hex result. Empty is the default and what everything else expects.
 *
 * `0X` is here because the choice is between two spellings people's tooling actually emits, not
 * because either is better -- and note it is independent of the digits' case: `0X` in front of
 * lower-case hex is legal C and is what some assemblers print.
 */
export type HexPrefix = "" | "0x" | "0X";

const HEX_PREFIX_LABEL: Record<HexPrefix, string> = {
  "": "No prefix",
  "0x": "0x",
  "0X": "0X",
};

/** The encodings a prefix means anything for: one continuous number, not per-byte groups. */
function acceptsHexPrefix(encoding: OutputEncoding): boolean {
  return encoding === "hex" || encoding === "hex-upper";
}

export interface ResultPanelProps {
  state: ComputeState;
  outputEncodings: readonly OutputEncoding[];
  outputEncoding: OutputEncoding;
  onOutputEncodingChange: (next: OutputEncoding) => void;
  /** True when the checks panel found an `insecure`-level diagnostic. */
  isInsecure: boolean;
  /** Shown when a file's digest no longer reflects the current settings. */
  onRecompute: () => void;
  canRecompute: boolean;
}

/**
 * The result, in whatever spelling was asked for.
 *
 * This replaces the "Generated command" panel of the tool this app is modelled
 * on, and the difference in what it has to handle is the whole reason the
 * architecture diverged: a generated command is always one string, whereas a
 * result can be a digest, a digest plus an IV plus an auth tag, a block of text,
 * or a reported failure that is not an exception — a GCM tag that did not verify
 * is a real answer, and the panel has to render it as one.
 */
export function ResultPanel({
  state,
  outputEncodings,
  outputEncoding,
  onOutputEncodingChange,
  isInsecure,
  onRecompute,
  canRecompute,
}: ResultPanelProps) {
  /**
   * Local state, not part of the spec and not in the share link.
   *
   * It changes how the bytes are spelled and not what they are, which is the same test the Table
   * panel's controls pass. `outputEncoding` *is* shared, and the line between them is that the
   * encoding decides which of several genuinely different renderings you get, where this decorates
   * one of them.
   */
  const [hexPrefix, setHexPrefix] = useState<HexPrefix>("");

  const primary = useMemo(
    () => renderPrimary(state.result, outputEncoding, hexPrefix),
    [state.result, outputEncoding, hexPrefix],
  );

  /**
   * The size of what is on screen, as a caption under it.
   *
   * Two numbers because they answer different questions and routinely differ: the digest is 4 bytes
   * whatever spelling is chosen, and the string in front of you is 8 characters in hex, 10 with a
   * `0x`, and 15 in octal. Counting `primary` rather than deriving it from the encoding is what keeps
   * the second number true when a prefix is on.
   */
  const resultLen = state.result?.bytes?.length ?? 0;
  const sizeLine = `${resultLen} ${resultLen === 1 ? "byte" : "bytes"} · ${primary.length} ${
    primary.length === 1 ? "character" : "characters"
  } as shown`;

  // Dimmed, not replaced: during the debounce window the value on screen is still the right answer
  // for the input that produced it, and blanking it on every keystroke is what a spinner here would
  // do. Same treatment as a file whose settings have moved on, for the same reason.
  const pending = state.status === "pending";
  const stale = state.status === "stale";

  return (
    <Panel
      title="Result"
      /**
       * No description, ever, and that is what makes the header a constant height.
       *
       * It used to be `describeStatus(state)`, which returned a sentence for five statuses and
       * `undefined` for `done` -- so the line existed while you typed and vanished the moment a
       * digest arrived, resizing the header on every single computation. That is the layout shift
       * left over after the progress bar stopped being conditional.
       *
       * Nothing was lost by dropping it, because every sentence it held was the third place the
       * same thing was said. "Reading..." sat above a progress bar and a byte readout that both
       * said it; "Could not compute." above a red block quoting the actual message; "Out of date..."
       * above the amber banner that says which of the input and the settings moved; and the debounce
       * message above a value already dimmed to show exactly that.
       */
      actions={
        <div className="flex items-center gap-2">
          {outputEncodings.length > 1 && (
            <select
              /**
               * A stable hook for the desktop smoke test, matching `data-ocs-result` beside it.
               *
               * Whether this control exists at all is a real claim -- a tool whose output has one
               * spelling renders no selector -- and it is one a typecheck and the node suite cannot
               * see either way. The parity family's UART tool returns a frame diagram and must offer
               * no menu; its Parity tool must open on `binary` rather than hex.
               */
              data-ocs-output-encoding=""
              aria-label="Output encoding"
              value={outputEncoding}
              onChange={(event) => onOutputEncodingChange(event.target.value as OutputEncoding)}
              className="rounded-md border border-slate-300 bg-white px-1.5 py-1 text-[11px] dark:border-slate-700 dark:bg-slate-950"
            >
              {outputEncodings.map((encoding) => (
                <option key={encoding} value={encoding}>
                  {OUTPUT_ENCODING_LABEL[encoding]}
                </option>
              ))}
            </select>
          )}
          {/*
            Only for the hex encodings, and only when there is more than one encoding to be in --
            a tool with a single fixed encoding renders no selector at all and this follows it.
          */}
          {acceptsHexPrefix(outputEncoding) && (
            <select
              aria-label="Hex prefix"
              value={hexPrefix}
              onChange={(event) => setHexPrefix(event.target.value as HexPrefix)}
              className="rounded-md border border-slate-300 bg-white px-1.5 py-1 text-[11px] dark:border-slate-700 dark:bg-slate-950"
            >
              {(Object.keys(HEX_PREFIX_LABEL) as HexPrefix[]).map((prefix) => (
                <option key={prefix} value={prefix}>
                  {HEX_PREFIX_LABEL[prefix]}
                </option>
              ))}
            </select>
          )}
          <CopyButton
            value={() => primary}
            disabled={primary === ""}
            writeClipboard={(text) => platform().copyToClipboard(text)}
          />
        </div>
      }
    >
      <div className="space-y-3">
        {isInsecure && primary !== "" && (
          // Above the value, not below it. Someone who has already copied the
          // digest will not scroll down to find out it should not be trusted.
          <p className="rounded-r border-l-4 border-l-(--color-severity-insecure) bg-orange-50/60 px-3 py-2 text-xs dark:bg-orange-950/20">
            This result is correct for the settings chosen, and those settings are not secure.
            See <span className="font-semibold">Checks</span>.
          </p>
        )}

        {/*
          Two things, both always rendered: the value and its size. Nothing here mounts or unmounts
          on status -- `MonoBlock` renders a space when it has no value, so an empty one is exactly as
          tall as a one-line digest, and the size line has a floor under it. The panel header carries
          no status either, for the same reason; see the note on `title` above.

          The progress bar used to be swapped in *for* the value while a file was being read, so
          dropping a file replaced a text box with a 2px rule and the whole page below -- Verify, the
          field table, the Table panel -- jumped up and then back down. It is in the Input panel's
          footer now, which is where what it measures lives: see `ProgressReadout`.
        */}
        <MonoBlock
          // A stable hook for the desktop smoke test, which needs to read the
          // computed value out of a packaged build. Keyed on an attribute rather
          // than a class or element shape so restyling this panel cannot silently
          // turn the smoke test into a no-op.
          data-ocs-result=""
          /**
           * The status, beside the value, because the two have to be read together.
           *
           * During the debounce window the value on screen is the *previous* answer, and a
           * check that polls for "something that looks like a digest" will happily accept it —
           * which is exactly what the packaged-app smoke test did the moment the debounce grew
           * past a keystroke: it read CRC-32("abc") and reported it as CRC-32("123456789").
           * Publishing the status means a reader can wait for a settled value instead of a
           * plausible one.
           */
          data-ocs-status={state.status}
          value={primary}
          // Hex only: grouping Base64 into fours would break its own 4-character
          // quantum in a way that reads as corruption.
          groupSize={outputEncoding === "hex" || outputEncoding === "hex-upper" ? 8 : undefined}
          placeholder={primary === ""}
          className={cn((stale || pending) && "opacity-50")}
        />

        {/*
          The size of the result, directly under it, and **nothing else ever goes in this line**.

          It is the caption for the value above it, so it belongs to the value and not to whatever
          the panel is currently doing. It was briefly a shared slot that also carried the progress
          readout, the debounce message and the "press Compute" hint -- which meant the one line
          someone reads to check they have the right number of bytes was replaced by unrelated text
          on every keystroke. And it is never empty either: with nothing computed the result is
          genuinely zero bytes, so it says so rather than blanking and taking its line with it.
        */}
        <p className="min-h-4 text-[11px] text-slate-500 dark:text-slate-400">{sizeLine}</p>

        {stale && (
          <div className="flex flex-wrap items-center gap-2 rounded-r border-l-4 border-l-(--color-severity-warning) bg-amber-50/60 px-3 py-2 dark:bg-amber-950/20">
            <p className="flex-1 text-xs">
              {/*
                Two reasons, two sentences. This said "after this file was read" for both, which is
                a plainly wrong explanation when what moved was the text in the box above -- and
                that is now the common case, because auto-update being off leaves a value on screen
                that its own input has moved out from under.
              */}
              {state.staleReason === "input"
                ? "The input changed after this was computed. The value above is for the input you had then."
                : "The settings changed after this was computed. The value above is from the previous settings."}
            </p>
            <Button size="sm" disabled={!canRecompute} onClick={onRecompute}>
              Recompute
            </Button>
          </div>
        )}

        {state.result?.error && (
          <p className="rounded-r border-l-4 border-l-(--color-severity-error) bg-red-50/60 px-3 py-2 text-xs dark:bg-red-950/20">
            {state.result.error}
          </p>
        )}

        {state.error && (
          <p className="rounded-r border-l-4 border-l-(--color-severity-error) bg-red-50/60 px-3 py-2 text-xs dark:bg-red-950/20">
            {state.error}
          </p>
        )}

        {state.result?.fields && state.result.fields.length > 0 && (
          <FieldTable fields={state.result.fields} />
        )}

        {/*
          The tool's working, below the summary rather than above it.
          
          The fields answer "what is it" in two rows and this answers "why" in as many rows as there
          are input bytes, so this is the half you scroll to. `MonoBlock` gives it the bounded height
          and the no-wrap treatment its columns need -- see the note there on choosing the mode from
          the value, which is what keeps a table's alignment intact while a digest still wraps.

          Headed, because an unlabelled second monospace block under the first reads as a continuation
          of the result rather than as an explanation of it.
        */}
        {state.result?.working && (
          <div className="space-y-1">
            <p className="text-[11px] font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">
              Working
            </p>
            <MonoBlock data-ocs-working="" value={state.result.working} />
          </div>
        )}
      </div>
    </Panel>
  );
}

/**
 * A bare track, always drawn, whose fill is the only thing that moves.
 *
 * Two things it deliberately is not. It is not conditional: a bar that appears pushes everything
 * below it -- Verify, the field table, sometimes a 256-cell grid -- down the page, and then back up
 * when it goes. And it is not invisible-when-idle either, which was the first attempt at that: it
 * fixed the shift and left the bar reading as something that came and went.
 *
 * It also carries no caption of its own. The byte readout goes in the result panel's single caption
 * slot, so there is one grey line under the value rather than two, and this element's height is
 * fixed at eight pixels in every state.
 */
function renderPrimary(
  result: ToolResult | undefined,
  encoding: OutputEncoding,
  hexPrefix: HexPrefix,
): string {
  if (!result) return "";
  /**
   * `text` is returned verbatim, prefix included in the exemption.
   *
   * A tool whose output is natively text -- a decoded Base64 string, a formatted JSON document -- is
   * not a number, and putting `0x` in front of it would be nonsense. This is also why the prefix is
   * applied here rather than to `primary` afterwards: a wrapper around the finished string could not
   * tell the two apart.
   */
  if (result.text !== undefined) return result.text;
  if (result.bytes) {
    const spelled = encodeOutput(result.bytes, encoding);
    // Nothing to prefix when there is nothing there: `0x` alone would defeat the `primary === ""`
    // checks that disable Copy and Save.
    if (spelled === "" || !acceptsHexPrefix(encoding)) return spelled;
    return hexPrefix + spelled;
  }
  return "";
}
