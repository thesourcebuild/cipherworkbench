"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  runStreams,
  type StreamProgress,
  type ToolDefinition,
  type ToolSpecBase,
  type ToolVariantTable,
  type ToolVariantValues,
} from "@ocs/engine";
import { decodeInput } from "@ocs/engine";
import { computeVariantsFile } from "./file-compute";
import type { InputState } from "./input-state";

export type VariantsStatus = "idle" | "running" | "done" | "error";

export interface VariantsState {
  status: VariantsStatus;
  /** The rows: names, aliases and parameters. Spec-derived, so present before any run. */
  table: ToolVariantTable | undefined;
  /** Empty until a run finishes. Keyed by `ToolVariant.id`. */
  values: ToolVariantValues;
  /** Shared across every row: one read head, one figure. See `runStreams`. */
  progress?: StreamProgress;
  error?: string;
  /** The values were produced from input the box no longer holds. */
  stale: boolean;
}

/**
 * Runs every sibling variant over the current input, on demand and on demand only.
 *
 * Its own hook rather than part of `useCompute`, and that separation is the point. The main digest
 * recomputes as you type, on a debounce, and that is right for one cheap function over what is
 * usually a short string. Twenty of them over a file is a different proposition: pointing this at a
 * hundred gigabytes is a decision to make deliberately, not something that should happen because a
 * keystroke landed. So it is not touched by `Auto update`, it is not touched by the Result panel's
 * `Compute`, and nothing here runs until Run is pressed.
 *
 * What it does share with the digest is honesty about age. Once values exist, changing the input
 * marks them `stale` rather than clearing or silently refreshing them -- the same treatment, for the
 * same reason, as a file whose settings have moved on.
 *
 * One pass over the input feeds every stream (`runStreams`), so a second variant costs CPU and no
 * extra I/O, and they all finish together. File streaming runs in a Web Worker so the main thread
 * is never blocked and progress updates remain fluid even over multi-gigabyte files.
 */
export function useVariants(
  tool: ToolDefinition<ToolSpecBase> | undefined,
  spec: ToolSpecBase | undefined,
  input: InputState,
): { state: VariantsState; run: () => void; stop: () => void; canRun: boolean } {
  /** The rows, straight off the spec. Cheap: no engines are built until a run starts. */
  const table = useMemo(
    () => (tool?.variants && spec ? tool.variants(spec) : undefined),
    [tool, spec],
  );

  const [status, setStatus] = useState<VariantsStatus>("idle");
  const [values, setValues] = useState<ToolVariantValues>(() => new Map());
  const [progress, setProgress] = useState<StreamProgress | undefined>();
  const [error, setError] = useState<string | undefined>();

  /**
   * What the values were computed from, so "stale" is a fact rather than a guess.
   *
   * The input only, and deliberately not the spec -- an earlier version of this comment claimed
   * otherwise and was simply wrong about its own code. No spec option can invalidate a value here,
   * because every family runs each row at *its own* defaults: changing CRC's model, or HAVAL's pass
   * count, moves which row is marked and leaves all the values untouched. The one spec change that
   * would alter the row set is a change of width or category, and that is a change of *tool*, which
   * remounts this hook.
   */
  const inputKey =
    input.mode === "file"
      ? input.file
        ? `file:${input.file.name}:${input.file.size}:${input.file.lastModified}`
        : "file:none"
      : `${input.mode}:${input.textEncoding}:${input.text}`;
  const [ranKey, setRanKey] = useState<string | undefined>(undefined);

  const abortRef = useRef<AbortController | undefined>(undefined);
  const jobRef = useRef(0);

  // Abandon an in-flight run when the tool changes or the view goes away. A hundred gigabytes does
  // not stop being read just because someone navigated.
  useEffect(() => () => abortRef.current?.abort(), []);

  const stop = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = undefined;
    jobRef.current++;
    setStatus("idle");
    setProgress(undefined);
  }, []);

  const run = useCallback(() => {
    if (!tool?.variants || !spec || !table || table.rows.length === 0) return;

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const job = ++jobRef.current;
    const live = () => jobRef.current === job;

    setStatus("running");
    setError(undefined);
    setProgress({ bytesProcessed: 0, ...(input.file ? { totalBytes: input.file.size } : {}) });

    void (async () => {
      try {
        if (input.mode === "file") {
          if (!input.file) {
            if (live()) {
              setStatus("error");
              setError("Choose a file first.");
            }
            return;
          }

          const next = await computeVariantsFile(tool, spec, input.file, {
            onProgress: (nextProgress) => {
              if (live()) setProgress(nextProgress);
            },
            signal: controller.signal,
          });

          if (!live()) return;
          setValues(next);
          setRanKey(inputKey);
          setStatus("done");
        } else {
          const decoded = decodeInput(input.text, input.mode, input.textEncoding);
          if (!decoded.ok) {
            if (live()) {
              setStatus("error");
              setError("The input cannot be read in the selected source mode.");
            }
            return;
          }

          /*
           * Load every row's implementation before building any stream. `stream()` is synchronous by
           * contract, and the hash family reaches its algorithms through a dynamic import so that one
           * tool does not download every table -- so a sibling row's module may not be here yet. Done
           * for all rows at once rather than per row because `runStreams` fans one read head out to
           * all of them, so they all have to exist before the first chunk is dispatched.
           */
          await Promise.all(table.rows.map((row) => row.prepare?.()));
          if (!live()) return;

          const results = await runStreams(
            table.rows.map((row) => row.stream()),
            once(decoded.bytes),
            {
              totalBytes: decoded.bytes.length,
              onProgress: (nextProgress) => {
                if (live()) setProgress(nextProgress);
              },
              signal: controller.signal,
            },
          );

          if (!live()) return;
          const next = new Map<string, Uint8Array>();
          results.forEach((result, index) => {
            const row = table.rows[index];
            if (row && result.bytes) next.set(row.id, result.bytes);
          });
          setValues(next);
          setRanKey(inputKey);
          setStatus("done");
        }
      } catch (thrown) {
        // A cancelled run is not a failure; `stop` has already put the status back.
        if (thrown instanceof DOMException && thrown.name === "AbortError") return;
        if (!live()) return;
        setStatus("error");
        setError(thrown instanceof Error ? thrown.message : String(thrown));
      }
    })();
  }, [tool, spec, table, input.mode, input.text, input.textEncoding, input.file, inputKey]);

  /**
   * A row set from another width is not a stale version of this one's, so the values go rather than
   * being marked. Same reasoning as the digest being cleared on a tool switch.
   *
   * It aborts first, which it did not before. `ToolWorkbench` is keyed by tool id, so today a tool
   * change remounts this hook and the unmount cleanup catches the run -- which made the omission
   * unreachable rather than harmless. Unreachable is a property of a call site somewhere else: drop
   * the key, or reuse the hook across tools, and a hundred-gigabyte read would carry on in the
   * background with nothing left holding a reference to stop it.
   */
  useEffect(() => {
    abortRef.current?.abort();
    abortRef.current = undefined;
    jobRef.current++;
    setValues(new Map());
    setStatus("idle");
    setProgress(undefined);
    setError(undefined);
    setRanKey(undefined);
  }, [tool]);

  return {
    state: {
      status,
      table,
      values,
      ...(progress ? { progress } : {}),
      ...(error === undefined ? {} : { error }),
      stale: ranKey !== undefined && ranKey !== inputKey,
    },
    run,
    stop,
    canRun:
      Boolean(tool?.variants && spec && table && table.rows.length > 0) &&
      (input.mode === "file" ? input.file !== undefined : input.text !== ""),
  };
}

/** One chunk, as an async iterable, so the typed path uses the same runner as a file. */
async function* once(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
  yield bytes;
}
