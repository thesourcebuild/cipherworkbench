import { describe, expect, it } from "vitest";
import { progressPresentation } from "../apps/web/app/progress-presentation";
import type { ComputeState } from "../apps/web/app/use-compute";

describe("progress presentation", () => {
  it("does not treat a retained result as completion while the next run is pending", () => {
    const state: ComputeState = {
      status: "pending",
      result: { bytes: new Uint8Array([1]) },
      inputByteLength: 100,
      progress: { bytesProcessed: 100, totalBytes: 100 },
    };

    expect(progressPresentation(state)).toEqual({
      total: 100,
      consumed: 0,
      percent: 0,
      indeterminate: false,
    });
  });

  it("does not report a stale result as progress over the current input", () => {
    const state: ComputeState = {
      status: "stale",
      result: { bytes: new Uint8Array([1]) },
      inputByteLength: 200,
    };

    expect(progressPresentation(state).percent).toBe(0);
  });

  it("does not round active work up to completion", () => {
    const state: ComputeState = {
      status: "computing",
      progress: { bytesProcessed: 996, totalBytes: 1000 },
    };

    expect(progressPresentation(state)).toEqual({
      total: 1000,
      consumed: 996,
      percent: 99,
      indeterminate: false,
    });
  });

  it("clamps malformed progress to the known range", () => {
    expect(
      progressPresentation({
        status: "computing",
        progress: { bytesProcessed: 120, totalBytes: 100 },
      }),
    ).toEqual({ total: 100, consumed: 100, percent: 100, indeterminate: false });
  });

  it("reports completion only for the current done state", () => {
    expect(
      progressPresentation({
        status: "done",
        result: { bytes: new Uint8Array(0) },
        inputByteLength: 25,
      }),
    ).toEqual({ total: 25, consumed: 25, percent: 100, indeterminate: false });
  });

  it("labels unknown-length computation as indeterminate without inventing a percentage", () => {
    expect(
      progressPresentation({
        status: "computing",
        progress: { bytesProcessed: 4096 },
      }),
    ).toEqual({ total: 0, consumed: 4096, percent: 0, indeterminate: true });
  });
});
