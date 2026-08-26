import type { ToolDefinition } from "@ocs/engine";
import { crcCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { CRC_TOOL_IDS, requireCrcTool } from "./catalogue/tool-meta";
import { computeCrc, crcInfo, crcTables, crcVariants, createCrcStream } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { CRC_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { isCustom, TAG_CUSTOM } from "./pure";
import { CrcSpec } from "./spec";

/**
 * Builds the full contract for one checksum tool.
 *
 * The catalogue is per width — that is the only thing that varies —
 * so this is a function over the tool list rather than five hand-written objects.
 *
 * Deliberately not re-exported from `./index`: this module reaches `@ocs/algos`,
 * and keeping it out of the barrel is what lets the sidebar list these without
 * loading the model catalogue.
 */
export function crcToolDefinition(toolId: string): ToolDefinition<CrcSpec> {
  const meta = requireCrcTool(toolId);
  const manifest = CRC_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for CRC tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: crcCatalogueFor(meta.width),
    lintRules: RULES,
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: CrcSpec,
    describe: describeSpec,
    // Seven parameters that follow from the model, so they belong beside the model dropdown rather
    // than beside a digest that may not exist yet.
    info: crcInfo,
    // The 256-entry table the model implies, in both bit orders. Same reasoning as `info` above:
    // it follows from the model, not from the input.
    tables: crcTables,
    // Every model of this width over the same input -- what crccalc.com is used for. Takes the
    // input, unlike `info` and `tables`, so it is a result and travels with one.
    variants: crcVariants,
    compute: computeCrc,
    createStream: createCrcStream,
    // The six parameter fields appear only in Custom mode. A named model's
    // parameters are reported with the result instead of being editable, so there is
    // no way to select MODBUS and then quietly change its polynomial.
    variantTag: (spec) => (isCustom(spec.options) ? TAG_CUSTOM : undefined),
  };
}

export { CRC_TOOL_IDS };

// Re-exported from this side of the split: every one of these reaches `@ocs/algos`,
// directly or through `./resolve`, so none of them may appear in `./index`.
export { computeCrc, crcInfo, crcVariants, createCrcStream } from "./compute";
export { resolveModel, matchingCatalogueEntry, type ResolvedModel } from "./resolve";
export { crcCatalogueFor, crcOptionsFor } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
