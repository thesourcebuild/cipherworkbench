import type { ToolDefinition } from "@ocs/engine";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { certificateCatalogueFor } from "./catalogue/options";
import { CERTIFICATE_TOOL_IDS, requireCertificateTool } from "./catalogue/tool-meta";
import { certificateInfo, computeCertificate } from "./compute";
import { createSpec } from "./create-spec";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { CERTIFICATES_MANIFESTS } from "./manifest";
import { OPTION_CREATOR_MODE } from "./pure";
import { samplesFor } from "./samples";
import { CertificateSpec } from "./spec";

export function certificatesToolDefinition(toolId: string): ToolDefinition<CertificateSpec> {
  const meta = requireCertificateTool(toolId);
  const manifest = CERTIFICATES_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for certificate tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: certificateCatalogueFor(meta),
    lintRules: RULES,
    samples: samplesFor(toolId),
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: CertificateSpec,
    describe: describeSpec,
    info: certificateInfo,
    compute: computeCertificate,
    variantTag: (spec) => {
      if (toolId === "cert-creator") {
        return [String(spec.options[OPTION_CREATOR_MODE] ?? "single-cert")];
      }
      return undefined;
    },
  };
}

export { CERTIFICATE_TOOL_IDS };
export { computeCertificate, certificateInfo } from "./compute";
export { certificateCatalogueFor, ALL_CERTIFICATE_OPTIONS } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { samplesFor } from "./samples";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
