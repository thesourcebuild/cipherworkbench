import type { ToolDefinition } from "@ocs/engine";
import { macCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { MAC_TOOL_IDS, requireMacTool } from "./catalogue/tool-meta";
import { computeMac, createMacStream } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { MAC_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { TAG_ASCON_PRF } from "./pure";
import { MacSpec } from "./spec";

/**
 * Builds the full contract for one MAC tool.
 *
 * Not re-exported from `./index`: this module reaches `@noble` and `@ocs/algos`, and
 * keeping it out of the barrel is what lets the sidebar list four tools without loading
 * any of it.
 */
export function macToolDefinition(toolId: string): ToolDefinition<MacSpec> {
  const meta = requireMacTool(toolId);
  const manifest = MAC_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for MAC tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: macCatalogueFor(toolId),
    lintRules: RULES,
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: MacSpec,
    describe: describeSpec,
    compute: computeMac,
    createStream: meta.streaming ? createMacStream : undefined,
    /**
     * The tool's own id, always -- never `undefined`.
     *
     * Each tool's catalogue already contains only its own options, so this looks redundant. It is
     * not: `isAvailableOn` reads a *missing* tag as "not available", so any option carrying an
     * `availableOn` at all is invisible unless the tag is produced. This returned `undefined` for
     * every tool but HMAC and KMAC, which left Skein-MAC's State size and Tag length selects and
     * Ascon-PRF's and Ascon-PRFShort's output-length field rendering nowhere -- four controls that
     * existed, typechecked, were covered by unit tests through `compute`, and could not be reached
     * from the app. Skein-MAC was stuck at a 512-bit state and a 64-byte tag as a result.
     *
     * Since every tag in this family *is* a tool id, returning the id opens each tool's own gates and
     * no others. Ascon-PRFShort additionally answers to `asconprf`, because its output-length control
     * is the one option two tools share.
     */
    variantTag: () => (toolId === "asconprfs" ? [toolId, TAG_ASCON_PRF] : toolId),
  };
}

export { MAC_TOOL_IDS };

// Re-exported from the lazy side: all of these reach an implementation.
export { computeMac, createMacStream } from "./compute";
export { resolveMac, type ResolvedMac, type ResolveResult } from "./resolve";
export { macCatalogueFor } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
export { computeHmac, computeKmac, computePoly1305, computeCmac } from "./bindings";
