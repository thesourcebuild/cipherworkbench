import { requireEncodingTool } from "./catalogue/tool-meta";
import { OPTION_DIRECTION, SPEC_VERSION } from "./pure";
import type { EncodingSpec } from "./spec";

/** The canonical default-spec factory. */
export function createSpec(options?: { variant?: string }): EncodingSpec {
  const variant = options?.variant ?? "base64";
  const tool = requireEncodingTool(variant);
  return {
    specVersion: SPEC_VERSION,
    variant,
    // Encoding by default, and the defaults written out rather than left to fall through, so a
    // share link says which alphabet it meant even if the default ever changes.
    options: { [OPTION_DIRECTION]: "encode", ...tool.defaults },
  };
}
