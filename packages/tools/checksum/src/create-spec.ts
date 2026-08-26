import { requireChecksumTool } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";
import type { ChecksumSpec } from "./spec";

/** The canonical default-spec factory. */
export function createSpec(options?: { variant?: string }): ChecksumSpec {
  const variant = options?.variant ?? "sum";
  const tool = requireChecksumTool(variant);
  return {
    specVersion: SPEC_VERSION,
    variant,
    // Defaults are written into the spec rather than left to fall through, so a saved spec or a
    // share link says which of the three widths it means even if the default ever changes.
    options: { ...tool.defaults },
  };
}
