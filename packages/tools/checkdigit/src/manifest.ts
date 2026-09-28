import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { CHECK_DIGIT_TOOLS, type CheckDigitToolMeta } from "./catalogue/tool-meta";

/**
 * Check digit algorithms default to decimal representation, reflecting human digit output
 * (e.g., credit card last digit, barcode check digit).
 */
const CHECK_DIGIT_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "decimal",
  "hex-upper",
  "hex",
  "binary",
];

function toManifest(meta: CheckDigitToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "checkdigit",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    directions: ["forward"],
    security: "not-a-mac",
    outputEncodings: CHECK_DIGIT_OUTPUT_ENCODINGS,
    readsInput: true,
    supportsVerify: true,
    supportsFile: true,
    streaming: true,
  };
}

export const CHECKDIGIT_MANIFESTS: readonly ToolManifest[] = CHECK_DIGIT_TOOLS.map(toManifest);
