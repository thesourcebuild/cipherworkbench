import type { ToolDefinition } from "@ocs/engine";
import { checkDigitCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { CHECK_DIGIT_TOOL_IDS, requireCheckDigitTool } from "./catalogue/tool-meta";
import {
  checkDigitInfo,
  checkDigitVariants,
  computeCheckDigit,
  createCheckDigitStream,
} from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { CHECKDIGIT_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { CheckDigitSpec } from "./spec";

/**
 * Builds the full contract for one check digit tool.
 *
 * Deliberately not re-exported from `./index` — this module reaches `@ocs/algos`.
 */
export function checkDigitToolDefinition(toolId: string): ToolDefinition<CheckDigitSpec> {
  const meta = requireCheckDigitTool(toolId);
  const manifest = CHECKDIGIT_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for check digit tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: checkDigitCatalogueFor(toolId, meta.exposes),
    lintRules: RULES,
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: CheckDigitSpec,
    describe: describeSpec,
    info: checkDigitInfo,
    compute: computeCheckDigit,
    createStream: createCheckDigitStream,
    variants: checkDigitVariants,
  };
}

export { CHECK_DIGIT_TOOL_IDS };

export {
  checkDigitInfo,
  checkDigitVariants,
  computeCheckDigit,
  createCheckDigitStream,
} from "./compute";
export {
  checkDigitCatalogueFor,
  checkDigitOptionsFor,
  ALL_CHECK_DIGIT_OPTIONS,
} from "./catalogue/options";
export { createSpec } from "./create-spec";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
