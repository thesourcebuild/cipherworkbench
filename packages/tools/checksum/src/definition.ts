import type { ToolDefinition } from "@ocs/engine";
import { checksumCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { CHECKSUM_TOOL_IDS, requireChecksumTool } from "./catalogue/tool-meta";
import {
  checksumInfo,
  checksumVariants,
  computeChecksum,
  createChecksumStream,
} from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { CHECKSUM_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { TAG_WORDS, usesWords } from "./pure";
import { ChecksumSpec } from "./spec";

/**
 * Builds the full contract for one checksum tool.
 *
 * A function over the tool list rather than nine hand-written objects: everything that varies is
 * in `CHECKSUM_TOOLS`, so the ninth tool cost one entry there and nothing here.
 *
 * Deliberately not re-exported from `./index` — this module reaches `@ocs/algos`.
 */
export function checksumToolDefinition(toolId: string): ToolDefinition<ChecksumSpec> {
  const meta = requireChecksumTool(toolId);
  const manifest = CHECKSUM_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for checksum tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: checksumCatalogueFor(toolId, meta.exposes),
    lintRules: RULES,
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: ChecksumSpec,
    describe: describeSpec,
    // Grouping, the BCC convention, the coincidence with another tool and the published check
    // value: all decided by the settings, so all shown beside them.
    info: checksumInfo,
    compute: computeChecksum,
    createStream: createChecksumStream,
    // All nine over the same input. Three of them coincide by construction, so seeing them
    // together is the only way to tell an identification from a collision of names.
    variants: checksumVariants,
    /**
     * Byte order is revealed once the words are wider than a byte.
     *
     * Fletcher-32 gets the tag unconditionally: its words are 16-bit by definition, so it has no
     * word-size option for `usesWords` to read, and without this the control it *does* expose
     * would be permanently hidden. Read out of `meta` rather than the spec because it is a
     * property of the tool, not of what the user typed.
     */
    variantTag: (spec) =>
      meta.kind === "fletcher32" || usesWords(spec.options) ? TAG_WORDS : undefined,
  };
}

export { CHECKSUM_TOOL_IDS };

// Re-exported from this side of the split: each of these reaches `@ocs/algos`, or would drag in a
// module that does, so none may appear in `./index`.
export {
  checksumInfo,
  checksumVariants,
  computeChecksum,
  createChecksumStream,
} from "./compute";
export {
  checksumCatalogueFor,
  checksumOptionsFor,
  ALL_CHECKSUM_OPTIONS,
} from "./catalogue/options";
export { createSpec } from "./create-spec";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
