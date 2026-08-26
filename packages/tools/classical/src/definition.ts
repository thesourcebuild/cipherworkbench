import type { ToolDefinition } from "@ocs/engine";
import { classicalCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { CLASSICAL_TOOL_IDS, requireClassicalTool } from "./catalogue/tool-meta";
import { classicalInfo, computeClassical } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { CLASSICAL_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { samplesFor } from "./samples";
import { readDirection, TAG_DECRYPT, TAG_ENCRYPT } from "./pure";
import { ClassicalSpec } from "./spec";

/**
 * Builds the full contract for one classical cipher.
 *
 * Deliberately not re-exported from `./index`: this module reaches `@ocs/algos`, and keeping it out of
 * the barrel is what lets the sidebar list the family for the price of the strings.
 */
export function classicalToolDefinition(toolId: string): ToolDefinition<ClassicalSpec> {
  const meta = requireClassicalTool(toolId);
  const manifest = CLASSICAL_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for classical tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: classicalCatalogueFor(meta),
    lintRules: RULES,
    samples: samplesFor(toolId),
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: ClassicalSpec,
    describe: describeSpec,
    /**
     * The formula, the alphabet and the keyspace: all true before anything is typed, which is the test
     * this member applies. What stays in `ToolResult.fields` is the per-run detail -- how many letters
     * actually moved, and what the shift came to after reduction.
     */
    info: classicalInfo,
    compute: computeClassical,
    /**
     * The direction, and nothing here is gated on it *yet*.
     *
     * Returned anyway rather than left undefined, because `isAvailableOn` reads a missing tag as "not
     * available": the first option this family gates on direction would be silently unreachable, which
     * is the defect the MAC family shipped four controls of. A tag with no consumer costs nothing; a
     * consumer with no tag costs a control.
     */
    variantTag: (spec) => [readDirection(spec.options) === "decrypt" ? TAG_DECRYPT : TAG_ENCRYPT],
  };
}

export { CLASSICAL_TOOL_IDS };

// Re-exported from this side of the split: each of these reaches `@ocs/algos`, or would drag in a
// module that does, so none may appear in `./index`.
export { computeClassical, classicalInfo, __testing } from "./compute";
export { classicalCatalogueFor, ALL_CLASSICAL_OPTIONS } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { samplesFor } from "./samples";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
