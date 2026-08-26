import type { ToolDefinition } from "@ocs/engine";
import { asymmetricCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { ASYMMETRIC_TOOL_IDS, requireAsymmetricTool } from "./catalogue/tool-meta";
import { computeAsymmetric } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { ASYMMETRIC_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { readOperation } from "./pure";
import { AsymmetricSpec } from "./spec";

/**
 * Builds the full contract for one public-key tool.
 *
 * `createStream` is absent for all four and the manifest agrees -- see the note there.
 */
export function asymmetricToolDefinition(toolId: string): ToolDefinition<AsymmetricSpec> {
  const meta = requireAsymmetricTool(toolId);
  const manifest = ASYMMETRIC_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for public-key tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: asymmetricCatalogueFor(toolId),
    lintRules: RULES,
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: AsymmetricSpec,
    describe: describeSpec,
    compute: computeAsymmetric,
    /**
     * The variant tag is the operation.
     *
     * Every other family tags by algorithm variant; here it is what you are doing, because that
     * is what decides which fields mean anything. A signature field while signing, or a key-size
     * field while verifying, would be worse than absent -- they would look like settings that
     * mattered.
     */
    variantTag: (spec) => readOperation(spec.options, meta.operations),
  };
}

export { ASYMMETRIC_TOOL_IDS };

// Re-exported from the lazy side: all of these reach an implementation.
export { computeAsymmetric } from "./compute";
export {
  acceptedPublicKeyLengths,
  resolveAsymmetric,
  type ResolvedAsymmetric,
  type ResolveResult,
} from "./resolve";
export { asymmetricCatalogueFor } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
export { decodePem, encodePem, formatJwk, keyInputKind, parseJwk } from "./pem";
