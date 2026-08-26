import { requireCrcTool } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";
import type { CrcSpec } from "./spec";

/** The canonical default-spec factory. */
export function createSpec(options?: { variant?: string }): CrcSpec {
  const variant = options?.variant ?? "crc32";
  const tool = requireCrcTool(variant);
  return {
    specVersion: SPEC_VERSION,
    variant,
    // The default model is set explicitly rather than left to fall through, so a
    // spec always says which of thirty-one CRC-16s it means.
    options: { model: tool.defaultModel },
  };
}
