import type { ToolDefinition } from "@ocs/engine";
import { kdfCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { KDF_TOOL_IDS, requireKdfTool } from "./catalogue/tool-meta";
import { computeKdf } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { KDF_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { readMode } from "./pure";
import { samplesFor } from "./samples";
import { KdfSpec } from "./spec";

/**
 * Builds the full contract for one KDF tool.
 *
 * `createStream` is deliberately absent: a KDF's input is its password, not the
 * tool's byte input, so there is nothing to stream. The manifest says `supportsFile: false`
 * and the input panel hides the File tab accordingly.
 */
export function kdfToolDefinition(toolId: string): ToolDefinition<KdfSpec> {
  requireKdfTool(toolId);
  const manifest = KDF_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for KDF tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: kdfCatalogueFor(toolId),
    lintRules: RULES,
    samples: samplesFor(toolId),
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: KdfSpec,
    describe: describeSpec,
    compute: computeKdf,
    // The tag switches the Stored hash field on. Each tool's catalogue already holds only
    // its own cost options, so this is the one axis that varies within a tool.
    variantTag: (spec) => (readMode(spec.options) === "verify" ? "verify" : undefined),
  };
}

export { KDF_TOOL_IDS, samplesFor };

// Re-exported from the lazy side: all of these reach an implementation.
export { computeKdf, generateKdfCliProviders } from "./compute";
// Exported so the OpenSSL differential test can reach it directly, the same way the hash family
// exposes its bindings for the declared-output-length cross-check.
export { deriveEvpKdf } from "./bindings";
export {
  hashBcrypt,
  hashBcryptPrehash,
  hashPasslibBcryptSha256,
  verifyBcrypt,
  verifyBcryptPrehash,
  verifyPasslibBcryptSha256,
} from "./bindings";
export { resolveKdf, type ResolvedKdf, type ResolveResult } from "./resolve";
export { kdfCatalogueFor } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
export { formatPhc, parsePhc, phcNumber, type PhcString } from "./phc";
