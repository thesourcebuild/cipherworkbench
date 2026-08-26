"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  decodeInput,
  type StreamProgress,
  type ToolDefinition,
  type ToolResult,
  type ToolSpecBase,
} from "@ocs/engine";
import { needsTables } from "@ocs/contracts";
import { ensureLegacyTables, legacyTablesReady } from "@ocs/encodings";
import { computeFile } from "./file-compute";
import { isInputBlank, type InputState } from "./input-state";
import { debounceForMode, useDebouncedTrigger } from "./use-debounce";

/**
 * `pending` is the debounce window: the input has changed and the recompute has not started yet.
 *
 * A separate status from `computing` because the panel has to treat them differently. `computing`
 * means work is under way and the old value is gone; `pending` means the old value is still on
 * screen and about to be replaced. Collapsing the two would make the result vanish on every
 * keystroke and reappear a second later, which is worse than either.
 */
export type ComputeStatus = "blank" | "pending" | "computing" | "done" | "error" | "stale";

/**
 * Why a result is out of date, which decides the sentence the panel shows.
 *
 * `settings` is the original case: a file was read, then an option moved. `input` arrived with the
 * text path, where auto-update being off means the value on screen can outlive the text that
 * produced it -- and "the settings changed" would have been a plainly wrong explanation for it.
 */
export type StaleReason = "input" | "settings";

export interface ComputeState {
  status: ComputeStatus;
  result?: ToolResult;
  /** Length of the decoded input, for the byte counter. Undefined in file mode until known. */
  inputByteLength?: number;
  /** Input could not be decoded, or the tool threw. Distinct from `result.error`, which is the tool reporting a real outcome. */
  error?: string;
  /** Set only when `status` is `stale`. */
  staleReason?: StaleReason;
  progress?: StreamProgress;
}

/**
 * Drives one tool's computation from the current spec and input.
 *
 * Two behaviours are deliberately different between text and file input:
 *
 *  - Text recomputes once typing stops, on the shared debounce in `./use-debounce`. Every
 *    intermediate keystroke is a different input, and hashing half a pasted key to report that it
 *    is not valid Base64 yet is noise rather than feedback.
 *  - A file recomputes when the *file* changes, but a spec change only marks the
 *    result `stale`. Re-hashing four gigabytes because someone toggled an option
 *    is not a helpful interpretation of "auto update", so the panel says the
 *    settings moved and offers a button instead.
 */
export function useCompute(
  tool: ToolDefinition<ToolSpecBase> | undefined,
  spec: ToolSpecBase | undefined,
  input: InputState,
  autoUpdate: boolean,
): {
  state: ComputeState;
  recompute: () => void;
  canRecompute: boolean;
  /**
   * The input cannot be read at all, as opposed to the tool having refused it.
   *
   * Separate from `ComputeState.error` because it is true whether or not anything has computed: bad
   * hex is bad hex before you press Compute. The panel shows it under the textarea, where the
   * problem is.
   */
  inputProblem: string | undefined;
} {
  const [state, setState] = useState<ComputeState>({ status: "blank" });

  /**
   * The WHATWG conversion tables for a legacy character encoding, loaded on demand.
   *
   * This lives in the compute hook rather than in the input panel, and the difference is the
   * whole fix: the panel owning it meant the load finished, the panel re-rendered, and nothing
   * recomputed — because the input had not changed and `run`'s dependencies had not moved. The
   * tables are a dependency of *computing*, so the epoch below is one, and incrementing it is
   * what makes the digest appear.
   *
   * 635 KB in two chunks that a session hashing UTF-8 never fetches. `needsTables` is false for
   * the four Unicode encodings, so the common path costs nothing.
   */
  const [tablesEpoch, setTablesEpoch] = useState(0);
  const awaitingTables = input.mode === "text" && needsTables(input.textEncoding);
  useEffect(() => {
    if (!awaitingTables || legacyTablesReady()) return;
    let live = true;
    void ensureLegacyTables().then(() => {
      if (live) setTablesEpoch((n) => n + 1);
    });
    return () => {
      live = false;
    };
  }, [awaitingTables, input.textEncoding]);

  // Monotonic job id: a reply from a superseded run is dropped rather than
  // painted over a newer one. Cheaper and more reliable than trying to cancel
  // synchronous digest work.
  const jobRef = useRef(0);
  const abortRef = useRef<AbortController | undefined>(undefined);
  /**
   * The spec the last committed result was computed under.
   *
   * Only used to tell an input change from a settings change when marking a result stale, which is
   * worth the ref because the two need different sentences and getting it backwards would put "the
   * settings changed" under a typo.
   */
  const lastRunSpecRef = useRef("");
  const debounce = useDebouncedTrigger();
  const [manualTrigger, setManualTrigger] = useState(0);

  const recompute = useCallback(() => setManualTrigger((n) => n + 1), []);

  // Serialised so the effect below re-runs on a value change rather than on every
  // parent render — the spec object is rebuilt on each keystroke.
  const specKey = spec ? JSON.stringify(spec) : "";
  const fileKey = input.file
    ? `${input.file.name}:${input.file.size}:${input.file.lastModified}`
    : "";

  /**
   * The decoded input, whether or not anything is going to compute.
   *
   * The byte count and a decode failure are properties of what you typed, not of the computation, so
   * they must not wait for one -- and they did: the count only existed on a finished `ComputeState`,
   * so with auto-update off the Input panel read "Nothing entered yet." over visible text until you
   * pressed Compute.
   *
   * Memoised on exactly the keys `run` reads, so this is one decode per input change rather than one
   * for the counter and a second for the tool.
   */
  const decoded = useMemo(
    () =>
      input.mode === "file"
        ? undefined
        : decodeInput(input.text, input.mode, input.textEncoding),
    // `tablesEpoch`: a legacy encoding cannot be decoded until its conversion tables have landed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [input.mode, input.text, input.textEncoding, tablesEpoch],
  );

  const run = useCallback(
    async (job: number) => {
      if (!tool || !spec) return;

      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      const commit = (next: ComputeState) => {
        if (jobRef.current !== job) return;
        if (next.status === "done") lastRunSpecRef.current = specKey;
        setState(next);
      };

      try {
        if (input.mode === "file") {
          if (!input.file) return commit({ status: "blank" });
          commit({
            status: "computing",
            progress: { bytesProcessed: 0, totalBytes: input.file.size },
          });
          const result = await computeFile(tool, spec, input.file, {
            signal: controller.signal,
            onProgress: (progress) => commit({ status: "computing", progress }),
          });
          return commit({ status: "done", result, inputByteLength: input.file.size });
        }

        if (!decoded) return;
        if (!decoded.ok) {
          // A pending table load is not a bad input. Reporting it as `computing` keeps the panel
          // from flashing an error message that resolves itself a moment later.
          return commit(
            decoded.loading
              ? { status: "computing" }
              : { status: "error", error: decoded.error },
          );
        }

        const result = await tool.compute(spec, decoded.bytes);
        // Note what is *not* here: the variants table. It has its own hook, its own Run button and
        // its own lifecycle -- see `useVariants`. Twenty engines over a large file is not something
        // to start because a keystroke landed.
        commit({ status: "done", result, inputByteLength: decoded.bytes.length });
      } catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") return;
        commit({
          status: "error",
          error: error instanceof Error ? error.message : String(error),
        });
      }
    },
    // `input` is read wholesale but only these parts can change it materially.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [tool, specKey, input.mode, decoded, fileKey, tablesEpoch],
  );

  /**
   * Two things skip the wait, and both would otherwise read as the app being broken.
   *
   * Pressing Compute is an explicit "now" — a button that appears to do nothing for a whole second
   * is indistinguishable from one that is not wired up. And the first computation for a newly loaded
   * tool has nothing on screen to keep warm, so a share link or a restored input would open on an
   * empty Result panel. Neither is a rapidly-changing input, which is the only thing the debounce
   * exists to absorb.
   */
  const lastManualRef = useRef(manualTrigger);
  const lastToolRef = useRef<typeof tool>(undefined);

  // Text path: debounced auto-update.
  useEffect(() => {
    if (!tool || !spec) return;
    if (input.mode === "file") return;
    /**
     * An empty box is "nothing to compute" only for a tool that reads the box.
     *
     * A generator's input is its settings, so an empty input is its *normal* state -- and this guard
     * returning early meant `uuid` and `password` could not compute at all once the text box stopped
     * being rendered. They worked before only because the box happened to hold the check string,
     * which they then ignored. Same for the KDFs, whose password is an option.
     */
    if (tool.readsInput && isInputBlank(input) && input.text === "") {
      debounce.cancel();
      setState({ status: "blank" });
      return;
    }

    const manual = manualTrigger !== lastManualRef.current;
    lastManualRef.current = manualTrigger;
    const firstForThisTool = lastToolRef.current !== tool;
    lastToolRef.current = tool;

    /**
     * Off means off, and this is where it stopped meaning that.
     *
     * The condition was `!autoUpdate && manualTrigger === 0`, which guards nothing once Compute has
     * been pressed: the trigger is monotonic, so from 1 onwards every keystroke fell straight
     * through into a debounced run and the tool behaved exactly as though the switch were on. What
     * it has to ask is whether the trigger moved *this* time, which is what `manual` already is.
     *
     * What stays on screen matters as much as what does not run. A digest of the previous text is
     * not wrong, it is out of date -- the same thing the file path has always said when settings
     * move -- so it is marked rather than silently updated or silently left looking current.
     *
     * **There are no exceptions.** Not a tool change, not a first paint, not a share link. This
     * went back and forth once and the round trip is worth recording, because the argument that
     * won looks weaker than it is.
     *
     * `firstForThisTool` was briefly allowed through, on the grounds that a fresh session otherwise
     * opened on an empty Result over an input sitting right there in the box. That was a real
     * complaint, but the wrong diagnosis: what actually looked broken was the Variants panel, which
     * did not exist until something had computed. Fixing *that* -- its rows are spec-derived now, so
     * the table is populated on load and only its Result column waits for its own Run -- removed the
     * reason, and the exception went with it.
     *
     * What is left is a rule with no shape to remember: nothing recomputes unless you ask. A page
     * that computes on arrival is indistinguishable from one where the switch does not work, and
     * "except when the tool changes" is not a thing anyone can hold in their head while wondering
     * why a value moved.
     *
     * `firstForThisTool` survives below, where it only decides whether to *skip the debounce* for a
     * run that was going to happen anyway.
     */
    if (!autoUpdate && !manual) {
      debounce.cancel();
      const reason: StaleReason = lastRunSpecRef.current === specKey ? "input" : "settings";
      setState((prev) =>
        prev.status === "done" ? { ...prev, status: "stale", staleReason: reason } : prev,
      );
      return;
    }

    const job = ++jobRef.current;
    debounce.schedule(
      () => void run(job),
      manual || firstForThisTool ? 0 : debounceForMode(input.mode),
    );
    return debounce.cancel;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run, autoUpdate, manualTrigger, input.mode, input.text, specKey, tablesEpoch]);

  /**
   * The wait, said out loud.
   *
   * Only ever *enters* `pending`. Leaving it is `run`'s job — it commits `computing`, then `done` or
   * `error` — and an effect that also cleared the status on the way out would race with that reply
   * and could paint `computing` over a digest that had already arrived.
   */
  useEffect(() => {
    if (!debounce.pending) return;
    setState((prev) => (prev.status === "pending" ? prev : { ...prev, status: "pending" }));
  }, [debounce.pending]);

  // File path: compute when the file itself changes, and on an explicit request.
  useEffect(() => {
    if (!tool || !spec) return;
    if (input.mode !== "file") return;
    if (!input.file) {
      setState({ status: "blank" });
      return;
    }

    /**
     * The same guard the text path has, which this had none of at all.
     *
     * Choosing a file started a read regardless of the switch -- and this is the worse half of the
     * two, because a file is where "do not compute until I ask" actually costs something: four
     * gigabytes go through the streaming worker before anyone can stop it. `autoUpdate` was simply
     * never read here.
     *
     * `lastManualRef` is shared with the text effect on purpose rather than duplicated. It means
     * "the trigger value some path has already acted on", so pressing Compute in text mode and then
     * switching to a file does not spend that press a second time. The text effect returns before
     * touching it whenever the mode is `file`, so only one of the two ever consumes a given value.
     */
    const manual = manualTrigger !== lastManualRef.current;
    lastManualRef.current = manualTrigger;

    if (!autoUpdate && !manual) {
      // A new file makes an existing digest out of date rather than wrong -- the same treatment a
      // settings change gets below, and the same reason: saying so beats silently recomputing.
      setState((prev) =>
        prev.status === "done" ? { ...prev, status: "stale", staleReason: "input" } : prev,
      );
      return;
    }

    const job = ++jobRef.current;
    void run(job);
    // Note the absence of `specKey`: a settings change must not re-read the file. `autoUpdate` is
    // absent for the same reason -- flipping the switch on with a file already hashed would re-read
    // it, and the effect closes over the current value whenever one of the deps below does fire.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileKey, input.mode, manualTrigger]);

  // A spec change with a file loaded leaves the shown digest describing the old
  // settings. Saying so is the honest option; recomputing silently is not.
  const staleRef = useRef(specKey);
  useEffect(() => {
    if (input.mode === "file" && staleRef.current !== specKey) {
      setState((prev) =>
        prev.status === "done" ? { ...prev, status: "stale", staleReason: "settings" } : prev,
      );
    }
    staleRef.current = specKey;
  }, [specKey, input.mode]);

  // Abandon any in-flight file read when the tool changes or the view unmounts.
  useEffect(() => () => abortRef.current?.abort(), []);

  /**
   * Both off `decoded`, not off the last run -- see the note on it.
   *
   * A file's size is known from the handle, so it needs no decode and no computation either; that
   * path used to report it only once the read finished.
   */
  const inputByteLength =
    input.mode === "file" ? input.file?.size : decoded?.ok ? decoded.bytes.length : undefined;
  // `loading` is a pending table fetch, which is not a bad input and must not be reported as one.
  const inputProblem = decoded && !decoded.ok && !decoded.loading ? decoded.error : undefined;

  return {
    state: state.inputByteLength === inputByteLength ? state : { ...state, inputByteLength },
    recompute,
    // "There is something to compute over" -- which for a generator is always true, since what it
    // computes over is the spec. Without this the Compute button is permanently disabled on `uuid`.
    canRecompute: Boolean(tool && spec && (!tool.readsInput || !isInputBlank(input))),
    inputProblem,
  };
}
