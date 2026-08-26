import { requireFormatTool } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";
import type { FormatSpec } from "./spec";

/** The canonical default-spec factory. */
export function createSpec(options?: { variant?: string }): FormatSpec {
  const variant = options?.variant ?? "json";
  const tool = requireFormatTool(variant);
  /**
   * Defaults written out rather than left to fall through.
   *
   * Two reasons, both learned here already. A share link then says which settings it meant even if a
   * default later changes; and an `enum` a tool renders must have a value in the spec or the form
   * shows "(not set)" while quietly computing at the resolver's fallback --
   * `tests/registry.test.ts` walks every tool checking exactly that.
   */
  return { specVersion: SPEC_VERSION, variant, options: { ...tool.defaults } };
}
