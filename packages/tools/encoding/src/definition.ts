import type { ToolDefinition } from "@ocs/engine";
import { encodingCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { ENCODING_TOOL_IDS, requireEncodingTool } from "./catalogue/tool-meta";
import { computeEncoding, encodingInfo } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { ENCODING_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { readDirection, readVariant, TAG_DECODE, TAG_ENCODE } from "./pure";
import { EncodingSpec } from "./spec";

/**
 * Builds the full contract for one encoding tool.
 *
 * Deliberately not re-exported from `./index`: this module reaches `@scure/base` and `@ocs/algos`,
 * and keeping it out of the barrel is what lets the sidebar list these for the price of the strings.
 */
export function encodingToolDefinition(toolId: string): ToolDefinition<EncodingSpec> {
  const meta = requireEncodingTool(toolId);
  const manifest = ENCODING_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for encoding tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: encodingCatalogueFor(meta),
    lintRules: RULES,
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: EncodingSpec,
    describe: describeSpec,
    // The alphabet and the size ratio: the two facts that decide whether a format fits a job, and
    // both true before anything is typed.
    info: encodingInfo,
    compute: computeEncoding,
    /**
     * Two tags, and the direction is one of them.
     *
     * Padding is meaningless for Crockford (its specification has none) and the JSON layout applies
     * only when decoding, so both are gated. `availableOn` takes a list, which is what lets one
     * option depend on the direction while another depends on the alphabet.
     */
    variantTag: (spec) => {
      const tags = [readDirection(spec.options) === "decode" ? TAG_DECODE : TAG_ENCODE];
      const variant = readVariant(spec.options, meta.variants[0] ?? "standard");
      if (variant !== "crockford") tags.push("padded-format");
      return tags;
    },
  };
}

export { ENCODING_TOOL_IDS };

// Re-exported from this side of the split: every one of these reaches a coder.
export { computeEncoding, encodingInfo } from "./compute";
export { encodeToText, decodeFromText } from "./codec";
export { encodingCatalogueFor, ALL_ENCODING_OPTIONS } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
