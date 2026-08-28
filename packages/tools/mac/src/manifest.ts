import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { MAC_TOOLS, type MacToolMeta } from "./catalogue/tool-meta";

/**
 * No `decimal`. A MAC is compared, not read as a number, and offering a decimal rendering
 * would invite someone to compare two of them as integers.
 */
const MAC_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "hex-upper",
  "hex",
  "base64",
  "base64url",
  "base32",
];

function toManifest(meta: MacToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "mac",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    // A MAC is one-way, like a digest. Verifying one means recomputing it and comparing,
    // which is what the Verify panel does.
    directions: ["forward"],
    security: meta.security,
    outputEncodings: MAC_OUTPUT_ENCODINGS,
    readsInput: true,
    supportsVerify: true,
    supportsFile: true,
    streaming: meta.streaming,
  };
}

export const MAC_MANIFESTS: readonly ToolManifest[] = MAC_TOOLS.map(toManifest);
