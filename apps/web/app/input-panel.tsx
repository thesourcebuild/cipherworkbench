"use client";

import { useCallback, useRef, useState, type DragEvent, type ReactNode } from "react";
import type { ByteSourceMode, TextEncoding } from "@ocs/contracts";
import { BYTE_SOURCE_MODE_LABEL, ENCODING_GROUP_LABEL, encodingsByGroup } from "@ocs/contracts";
import { Button, ClearButton, CopyIconButton, Panel, Toggle, cn } from "@ocs/ui";
import { platform } from "@ocs/platform";
import { describeInputSize, formatBytes, isInputBlank, type InputState } from "./input-state";
import { INPUT_DEBOUNCE_LABEL } from "./use-debounce";

const MODES: readonly ByteSourceMode[] = [
  "text",
  "hex",
  "hex-lenient",
  "base64",
  "base64url",
  "file",
];

/** Grouped once at module scope — the list is static and 40 entries is enough to matter. */
const ENCODING_GROUPS = encodingsByGroup();

/**
 * Tooltips for the source dropdown.
 *
 * UI copy, so it lives here rather than beside `BYTE_SOURCE_MODE_LABEL` in `@ocs/contracts` — that
 * map is data a share link depends on, and a tooltip is not. Only "Hex (loose)" genuinely needs
 * explaining, but a control where one option has a tooltip and five do not reads as though the
 * five are undefined.
 */
const MODE_HINT: Record<ByteSourceMode, string> = {
  text: "Characters, turned into bytes by the encoding selected beside this.",
  hex: "Strict hex: two digits per byte, whitespace allowed, nothing else.",
  "hex-lenient":
    "Hex out of a debugger or a source file — 0x prefixes, commas, braces and \\x escapes are all stripped before parsing.",
  base64: "Standard Base64, with or without padding.",
  base64url: "Base64 with - and _ in place of + and /, as used in JWTs and URLs.",
  file: "Streamed from disk in chunks, so file size is not bounded by memory.",
};

export interface InputPanelProps {
  input: InputState;
  onChange: (next: InputState) => void;
  /**
   * False when nothing reads the box: a generator, a KDF whose password is an option, TupleHash.
   *
   * The whole byte-source half of this panel then does not render -- no source, no encoding, no
   * Clear, no textarea, no drop zone and no byte count -- because every one of those controls is a
   * statement that what you put in them will be used. What is left is the panel's other two jobs:
   * the tool's material fields, and the run controls in the footer. Both still have to be somewhere,
   * which is why this narrows the panel rather than removing it.
   */
  readsInput: boolean;
  /**
   * True for a tool whose whole interaction is the button: `uuid`, `password`.
   *
   * Passed rather than worked out here from `!readsInput && !material`, so there is one answer to "is
   * this a generator" and it is the same one the compute hook was given. It decides three things: the
   * panel's title, whether the auto-update switch is offered at all, and -- in the workbench -- whether
   * the Generate button is always on screen.
   */
  generates: boolean;
  /** False for a tool that only accepts typed input; the File tab is then hidden. */
  supportsFile: boolean;
  /** True when the tool must read the whole file into memory — worth saying before someone drops 8 GB on it. */
  buffersWholeFile: boolean;
  /** Decoded byte count, from the compute hook. Undefined while the input is unparseable. */
  byteLength: number | undefined;
  /** Decode error for the current mode, shown inline. */
  problem: string | undefined;
  autoUpdate: boolean;
  onAutoUpdateChange: (next: boolean) => void;
  /**
   * The tool's key, IV, nonce, salt or signature fields, rendered under the message.
   *
   * A node rather than the catalogue itself, so this panel stays unaware of the options form: the
   * workbench already composes every other part of the layout and is the one place that knows the
   * material has nowhere else to be. Omitted entirely for a tool that has none — a hash takes a
   * message and nothing else — rather than passed as an empty form, because the divider and heading
   * belong to whatever is actually there.
   */
  material?: ReactNode;
  /**
   * Rendered right-aligned at the bottom of the panel. The workbench puts `Compute` here.
   *
   * A slot rather than a `Compute` button, for the same reason `material` is a node: this panel does
   * not know that recomputing is a thing, and the workbench is the one place that owns the
   * auto-update state that decides whether the button exists at all.
   *
   * The bottom of the input, because that is where the eye already is once you have finished typing
   * and it is the ordinary form-then-submit reading order. It sat between the Input and Result
   * panels before -- a full-width band of its own, floating between two cards.
   *
   * Rendered bare rather than wrapped in an aligning row: whatever goes here decides its own width,
   * which is what lets `Compute` span the panel.
   */
  footer?: ReactNode;
}

/**
 * Where the bytes come from: typed text in a chosen character encoding, a hex or
 * Base64 literal, or a file.
 *
 * The `Auto update` switch mirrors the layout of the online tool this is modelled on, deliberately —
 * anyone arriving from there should not have to relearn where things are. That tool has a "Remember
 * input" beside it and this no longer does: it was removed along with the stored input itself, so
 * nothing here writes what you typed to disk under any setting.
 *
 * Three other things differ. The source is a dropdown rather than a row of tabs, which puts it
 * beside the character-encoding selector as a matching control and leaves the two settings that
 * decide how the bytes are read sitting next to each other; six tabs also grew wider than the panel
 * on a narrow window. `Compute` is at the bottom of this panel rather than floating between two
 * cards. And the byte count is always visible: "abc" is 3 bytes as UTF-8 and 6 as UTF-16LE, which
 * is exactly the kind of thing that makes two tools disagree about a digest.
 */
export function InputPanel({
  input,
  onChange,
  readsInput,
  generates,
  supportsFile,
  buffersWholeFile,
  byteLength,
  problem,
  autoUpdate,
  onAutoUpdateChange,
  material,
  footer,
}: InputPanelProps) {
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const modes = supportsFile ? MODES : MODES.filter((m) => m !== "file");

  const setMode = (mode: ByteSourceMode) => onChange({ ...input, mode });

  const takeFile = useCallback(
    (file: File | undefined) => {
      if (!file) return;
      onChange({ ...input, mode: "file", file });
    },
    [input, onChange],
  );

  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    takeFile(event.dataTransfer.files[0]);
  };

  return (
    <Panel
      title={generates ? "Generate" : "Input"}
      description={
        readsInput ? (
          <span data-ocs-input-size="">
            {describeInputSize(input, byteLength) || "Nothing entered yet."}
          </span>
        ) : generates ? (
          "This tool reads no input. Everything it needs is in Settings."
        ) : (
          "This tool takes its input from the fields below rather than from a text box."
        )
      }
      actions={
        /**
         * Absent for a generator, because the switch is about typing.
         *
         * Its hint reads "recompute after you stop typing" over a panel with no box in it, and the
         * behaviour it controls -- not recomputing over input you are mid-way through -- has no
         * meaning where there is no input. The workbench forces it on for those tools rather than
         * leaving a hidden switch governing whether a UUID appears, and puts the Generate button on
         * screen permanently instead.
         *
         * A switch rather than a checkbox where it does appear: it takes effect immediately rather
         * than holding a value for something else to act on later. See the note on `Toggle`.
         */
        generates ? undefined : (
          <Toggle
            id="auto-update"
            label="Auto update"
            hint={`Recompute ${INPUT_DEBOUNCE_LABEL} after you stop typing. Off means nothing recomputes until you press Compute.`}
            checked={autoUpdate}
            onCheckedChange={onAutoUpdateChange}
          />
        )
      }
    >
      <div className="space-y-3">
        {/*
          Everything the bytes come from, in one conditional.

          Gated as a block rather than control by control, because the parts are not independent:
          the encoding selector only means something in Text mode, Clear only means something when
          there is something to clear, and the byte count in the header only means something when a
          box is producing one. A tool that reads no input has no answer to any of them.
        */}
        {readsInput && (
          <>
            <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-400">
              Source
              <select
                /**
                 * Driven by the desktop smoke test, which switches to File to push a real file
                 * through the streaming worker and back to Text afterwards. It sets `value` and
                 * dispatches `change` rather than clicking, because an `<option>` is not clickable
                 * the way the segmented buttons this replaced were. `data-ocs-mode` stays on each
                 * option so a probe can still find one by mode without matching on label text.
                 */
                data-ocs-input-mode=""
                aria-label="Input source"
                value={input.mode}
                onChange={(event) => setMode(event.target.value as ByteSourceMode)}
                className="rounded-md border border-slate-300 bg-white px-1.5 py-1 text-[11px] max-w-full dark:border-slate-700 dark:bg-slate-950"
              >
                {modes.map((mode) => (
                  <option
                    key={mode}
                    value={mode}
                    data-ocs-mode={mode}
                    title={MODE_HINT[mode]}
                  >
                    {BYTE_SOURCE_MODE_LABEL[mode]}
                  </option>
                ))}
              </select>
            </label>

            {input.mode === "text" && (
              <label className="flex items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-400">
                Encoding
                <select
                  // Paired with `data-ocs-input`: the smoke test drives this to prove the lazy
                  // encoding-table chunk resolves over app:// in the packaged build.
                  data-ocs-input-encoding=""
                  value={input.textEncoding}
                  onChange={(event) =>
                    onChange({ ...input, textEncoding: event.target.value as TextEncoding })
                  }
                  className="rounded-md border border-slate-300 bg-white px-1.5 py-1 text-[11px] max-w-[200px] sm:max-w-xs truncate dark:border-slate-700 dark:bg-slate-950"
                >
                  {ENCODING_GROUPS.map(({ group, encodings }) => (
                    <optgroup key={group} label={ENCODING_GROUP_LABEL[group]}>
                      {encodings.map((encoding) => (
                        <option
                          key={encoding.id}
                          value={encoding.id}
                          title={encoding.summary}
                        >
                          {encoding.label}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
              </label>
            )}

            <div className="flex items-center gap-1.5 ml-auto shrink-0">
                <CopyIconButton
                  value={() => input.text}
                  writeClipboard={(text) => platform().copyToClipboard(text)}
                  disabled={input.mode === "file" || input.text === ""}
                  aria-label="Copy the input"
                  title={
                    input.mode === "file"
                      ? "Nothing to copy: a file is read from disk rather than into the box."
                      : "Copy the text in the box above."
                  }
                />
                <ClearButton
                  disabled={isInputBlank(input)}
                  onClick={() =>
                    onChange(
                      input.mode === "file"
                        ? { ...input, file: undefined }
                        : { ...input, text: "" },
                    )
                  }
                  aria-label={input.mode === "file" ? "Remove this file" : "Clear the input"}
                  title={
                    input.mode === "file"
                      ? "Forget this file. The source stays on File."
                      : "Empty the box above. The source and encoding stay as they are."
                  }
                />
              </div>
            </div>

            {input.mode === "file" ? (
              <div
                data-ocs-dropzone=""
                onDragOver={(event) => {
                  event.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                className={cn(
                  "flex flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed px-4 py-8 text-center transition-colors",
                  dragging
                    ? "border-blue-500 bg-blue-50/50 dark:bg-blue-950/20"
                    : "border-slate-300 dark:border-slate-700",
                )}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden"
                  onChange={(event) => takeFile(event.target.files?.[0])}
                />
                {input.file ? (
                  <>
                    <p className="font-mono text-xs break-all">{input.file.name}</p>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">
                      {formatBytes(input.file.size)}
                    </p>
                  </>
                ) : (
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Drop a file here, or choose one.
                  </p>
                )}
                {/* The only control left in here, now that Clear has moved up to the controls row. */}
                <Button size="sm" onClick={() => fileInputRef.current?.click()}>
                  {input.file ? "Choose another" : "Choose file"}
                </Button>
                <p className="max-w-md text-[11px] text-slate-500 dark:text-slate-400">
                  {buffersWholeFile
                    ? "This tool cannot process a file incrementally, so the whole thing is read into memory. Keep it modest."
                    : "Read in chunks as it hashes — the file never has to fit in memory, and it is never uploaded anywhere."}
                </p>
              </div>
            ) : (
              <textarea
                // Paired with `data-ocs-result` in the result panel: together they let the
                // desktop smoke test drive a real computation through a packaged build.
                data-ocs-input=""
                value={input.text}
                onChange={(event) => onChange({ ...input, text: event.target.value })}
                spellCheck={false}
                // Autocorrect and capitalisation on a hex field would silently alter
                // the bytes being hashed.
                autoCorrect="off"
                autoCapitalize="off"
                rows={10}
                placeholder={PLACEHOLDERS[input.mode]}
                className={cn(
                  "w-full resize-y rounded-md border px-3 py-2 font-mono text-xs",
                  "border-slate-300 bg-white text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100",
                  "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-blue-600",
                  problem && "border-(--color-severity-error)",
                )}
              />
            )}

            {problem && <p className="text-[11px] text-(--color-severity-error)">{problem}</p>}
          </>
        )}

        {material && (
          /**
           * Below the message, not above it. The message is what someone changes on every
           * computation and the key is what they set once, so the field they came here to type in
           * stays where it was rather than being pushed down the panel by a key they pasted an hour
           * ago. The rule reverses for the Settings rail, which is why the material moved out of it.
           */
          <div
            // Hook for the smoke test, which asserts the private-key field really is inside this
            // panel and not back in the right-hand rail. Layout is not usually worth a probe; this
            // is, because moving it back would break nothing that any other check can see.
            data-ocs-material=""
            className="border-t border-slate-200 pt-3 dark:border-slate-800"
          >
            {material}
          </div>
        )}

        {footer}
      </div>
    </Panel>
  );
}

const PLACEHOLDERS: Record<Exclude<ByteSourceMode, "file">, string> = {
  text: "Type or paste anything…",
  // Spelled out because the hex reader accepts all of these, and people do not
  // expect that.
  hex: "de ad be ef  ·  0xdeadbeef  ·  de:ad:be:ef",
  // The point of the loose mode is that the surrounding litter does not matter, so the
  // placeholder shows litter.
  "hex-lenient": "00000000: de ad be ef   ....  ·  { 0xde, 0xad, 0xbe, 0xef }",
  base64: "3q2+7w==",
  base64url: "3q2-7w",
};
