import type { ToolDefinition } from "@ocs/engine";
import { parityCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { PARITY_TOOL_IDS, requireParityTool } from "./catalogue/tool-meta";
import { computeParity, parityInfo } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { PARITY_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { samplesFor } from "./samples";
import {
  readDirection,
  readFrameParity,
  readScope,
  TAG_APPLY,
  TAG_CHECK,
  TAG_FRAMED,
  TAG_PER_BYTE,
} from "./pure";
import { ParitySpec } from "./spec";

/**
 * Builds the full contract for one parity tool.
 *
 * Deliberately not re-exported from `./index`: this module reaches `@ocs/algos`, and keeping it out of
 * the barrel is what lets the sidebar list these three for the price of the strings.
 */
export function parityToolDefinition(toolId: string): ToolDefinition<ParitySpec> {
  const meta = requireParityTool(toolId);
  const manifest = PARITY_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for parity tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: parityCatalogueFor(meta),
    lintRules: RULES,
    samples: samplesFor(toolId),
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: ParitySpec,
    describe: describeSpec,
    /**
     * Nearly everything worth knowing here is spec-derived, which is what `info` is for.
     *
     * A frame format, a bit time, what a code guarantees -- all true before anything is typed, which
     * is the test this member applies. What stays in `ToolResult.fields` is the per-run detail: which
     * offsets failed their parity, how many codewords were repaired.
     */
    info: parityInfo,
    compute: computeParity,
    /**
     * Three axes, and each gates a control that would otherwise be meaningless.
     *
     * `apply`/`check` hides the result layout while checking, since checking produces the stripped
     * data rather than a layout choice. `per-byte` hides the data width and the layout for
     * whole-message parity, which has neither -- one bit over every bit there is. `framed` marks a
     * frame that actually carries a parity bit.
     *
     * A list rather than one value, because a tool can need more than one at once: the pattern
     * `@ocs/encoding` established and `@ocs/asymmetric` leans on hardest.
     */
    variantTag: (spec) => {
      const tags: string[] = [readDirection(spec.options) === "check" ? TAG_CHECK : TAG_APPLY];
      if (meta.kind === "parity" && readScope(spec.options) === "byte") tags.push(TAG_PER_BYTE);
      if (meta.kind === "uart" && readFrameParity(spec.options) !== "none") tags.push(TAG_FRAMED);
      return tags;
    },
  };
}

export { PARITY_TOOL_IDS };

// Re-exported from this side of the split: each of these reaches `@ocs/algos`, or would drag in a
// module that does, so none may appear in `./index`.
export { computeParity, parityInfo, __testing } from "./compute";
export { parityCatalogueFor, ALL_PARITY_OPTIONS } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { samplesFor, UART_CAPTURE_SAMPLE } from "./samples";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
