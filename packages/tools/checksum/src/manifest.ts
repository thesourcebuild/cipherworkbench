import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { CHECKSUM_TOOLS, type ChecksumToolMeta } from "./catalogue/tool-meta";

/**
 * `decimal` is offered here and in the CRC family, and nowhere else.
 *
 * These values genuinely are small integers and people quote them as such — an NMEA sentence's
 * XOR is two hex digits, but an Adler-32 out of a zlib header is as likely to be shown as
 * 168229890. Rendering a 32-byte SHA-256 as a 78-digit decimal is possible and useless, which is
 * why the hash family leaves it out.
 */
const CHECKSUM_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "hex",
  "hex-upper",
  "decimal",
  "base64",
  "octal",
  "binary",
];

function toManifest(meta: ChecksumToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "checksum",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    directions: ["forward"],
    // Every entry, and not a judgement about implementation quality — these do exactly what they
    // were designed to do. It is a judgement about the gap between that and what they get used for.
    security: "not-a-mac",
    outputEncodings: CHECKSUM_OUTPUT_ENCODINGS,
    readsInput: true,
    supportsVerify: true,
    supportsFile: true,
    streaming: true,
  };
}

export const CHECKSUM_MANIFESTS: readonly ToolManifest[] = CHECKSUM_TOOLS.map(toManifest);
