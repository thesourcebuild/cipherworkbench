import { requireParityTool } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";
import type { ParitySpec } from "./spec";

/** The canonical default-spec factory. */
export function createSpec(options?: { variant?: string }): ParitySpec {
  const variant = options?.variant ?? "parity";
  const tool = requireParityTool(variant);
  /**
   * Defaults written out rather than left to fall through.
   *
   * A share link then says which settings it meant even if a default later changes -- and every `enum`
   * a tool renders must have a value in the spec, or the form shows "(not set)" while the resolver
   * quietly computes at its fallback. `tests/registry.test.ts` walks every tool checking exactly that.
   */
  return { specVersion: SPEC_VERSION, variant, options: { ...tool.defaults } };
}
