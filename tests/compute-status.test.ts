import { describe, expect, it } from "vitest";
import {
  canRequestCompute,
  claimComputeRequest,
  isComputeBusy,
  type ComputeStatus,
} from "../apps/web/app/use-compute";

describe("compute request state", () => {
  it.each<ComputeStatus>(["pending", "computing"])(
    "treats %s as busy and rejects another request",
    (status) => {
      expect(isComputeBusy(status)).toBe(true);
      expect(canRequestCompute(status, true)).toBe(false);
    },
  );

  it.each<ComputeStatus>(["blank", "done", "error", "stale"])(
    "allows a ready request from %s",
    (status) => {
      expect(isComputeBusy(status)).toBe(false);
      expect(canRequestCompute(status, true)).toBe(true);
    },
  );

  it.each<ComputeStatus>(["blank", "pending", "computing", "done", "error", "stale"])(
    "rejects an unready request from %s",
    (status) => {
      expect(canRequestCompute(status, false)).toBe(false);
    },
  );

  it("claims an allowed request once until the caller releases the lock", () => {
    const lock = { current: false };

    expect(claimComputeRequest(lock, true)).toBe(true);
    expect(claimComputeRequest(lock, true)).toBe(false);

    lock.current = false;
    expect(claimComputeRequest(lock, true)).toBe(true);
  });

  it("does not claim a request that is not allowed", () => {
    const lock = { current: false };

    expect(claimComputeRequest(lock, false)).toBe(false);
    expect(lock.current).toBe(false);
  });
});
