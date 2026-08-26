import type { ToolDefinition } from "@ocs/engine";
import { formatCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { FORMAT_TOOL_IDS, requireFormatTool } from "./catalogue/tool-meta";
import { computeFormat, formatInfo } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { FORMAT_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { samplesFor } from "./samples";
import {
  readAction,
  readDirection,
  randomShapeTag,
  readRandomShape,
  readUuidVersion,
  TAG_DECODE,
  TAG_ENCODE,
  TAG_UUID_NAMED,
} from "./pure";
import { FormatSpec } from "./spec";

/**
 * Builds the full contract for one format tool.
 *
 * Deliberately not re-exported from `./index`: this module reaches `uuid`, `entities`,
 * `jsonc-parser`, `@xmldom/xmldom` and `change-case`, and keeping it out of the barrel is what lets
 * the sidebar list these eight for the price of the strings.
 */
export function formatToolDefinition(toolId: string): ToolDefinition<FormatSpec> {
  const meta = requireFormatTool(toolId);
  const manifest = FORMAT_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for format tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: formatCatalogueFor(meta),
    lintRules: RULES,
    /**
     * The one family that needs these: `123456789` is not a document. The two generators have none,
     * which the picker never asks for anyway -- `readsInput` is false, so there is no box.
     */
    samples: samplesFor(toolId),
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: FormatSpec,
    describe: describeSpec,
    // Which library is doing the work, and whether this tool reads input at all. Both true before
    // anything is typed, which is the test for belonging here rather than in `ToolResult.fields`.
    info: formatInfo,
    compute: computeFormat,
    /**
     * The tags, and each gates a control that would otherwise be meaningless.
     *
     * `encode`/`decode` hides the entity-style controls when decoding, because decoding accepts every
     * reference form regardless. `format` hides the indent for Minify and Validate, which lay nothing
     * out. `uuid-named` reveals the namespace and name for v3 and v5, the only two versions that hash
     * anything.
     *
     * A list rather than one value, because a tool can need more than one axis at once -- the pattern
     * `@ocs/encoding` established and `@ocs/asymmetric` leans on hardest.
     */
    variantTag: (spec) => {
      const tags: string[] = [];
      if (meta.bidirectional) {
        tags.push(readDirection(spec.options) === "decode" ? TAG_DECODE : TAG_ENCODE);
      }
      if (meta.kind === "json" || meta.kind === "xml") {
        tags.push(readAction(spec.options, "format"));
      }
      if (meta.kind === "uuid") {
        const version = readUuidVersion(spec.options);
        if (version === "v3" || version === "v5") tags.push(TAG_UUID_NAMED);
      }
      /**
       * The random shape, and this line is what makes six controls exist.
       *
       * `isAvailableOn` reads a *missing* tag as "not available", so every option carrying
       * `availableOn: [TAG_RANDOM_INTEGER]` is unreachable unless this returns it -- which is exactly
       * how four MAC options came to render nowhere with a green suite. The gate for that is in
       * `tests/format-tool.test.ts`: no option in a tool's catalogue may be invisible under its own
       * default spec.
       */
      if (meta.kind === "random") tags.push(randomShapeTag(readRandomShape(spec.options)));
      return tags;
    },
  };
}

export { FORMAT_TOOL_IDS };

// Re-exported from this side of the split: every one of these reaches a library.
export { computeFormat, formatInfo, __testing } from "./compute";
export { formatCatalogueFor, ALL_FORMAT_OPTIONS } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { samplesFor, ALL_FORMAT_SAMPLES } from "./samples";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
