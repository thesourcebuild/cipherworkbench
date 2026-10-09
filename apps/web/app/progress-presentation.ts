import type { ComputeState } from "./use-compute";

export interface ProgressPresentation {
  total: number;
  consumed: number;
  percent: number;
  indeterminate: boolean;
}

/** One source of truth for the visual width, label, and accessible progress value. */
export function progressPresentation(state: ComputeState): ProgressPresentation {
  const busy = state.status === "computing";
  const finished = state.status === "done";
  const total = Math.max(0, state.progress?.totalBytes ?? state.inputByteLength ?? 0);
  const reported = busy
    ? Math.max(0, state.progress?.bytesProcessed ?? 0)
    : finished
      ? total
      : 0;
  const consumed = total > 0 ? Math.min(reported, total) : reported;
  const indeterminate = busy && total === 0;
  const percent =
    total > 0
      ? consumed >= total
        ? 100
        : Math.min(99, Math.round((consumed / total) * 100))
      : finished
        ? 100
        : 0;

  return { total, consumed, percent, indeterminate };
}
