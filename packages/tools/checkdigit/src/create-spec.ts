import { requireCheckDigitTool } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";
import type { CheckDigitSpec } from "./spec";

/** The canonical default-spec factory. */
export function createSpec(options?: { variant?: string }): CheckDigitSpec {
  const variant = options?.variant ?? "luhn";
  const tool = requireCheckDigitTool(variant);
  return {
    specVersion: SPEC_VERSION,
    variant,
    options: { ...tool.defaults },
  };
}
