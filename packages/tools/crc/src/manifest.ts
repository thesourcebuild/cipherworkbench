import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { CRC_TOOLS, type CrcToolMeta } from "./catalogue/tool-meta";

/**
 * `decimal` is offered here and nowhere else in the app.
 *
 * A CRC genuinely is a small integer, and people quote it as one — `3421780262` is
 * how a ZIP tool or a database column will show you a CRC-32. Rendering a 32-byte
 * SHA-256 as a 78-digit decimal is technically possible and useless, which is why
 * that family's manifest leaves it out.
 */
const CHECKSUM_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "hex",
  "hex-upper",
  "decimal",
  "base64",
  "octal",
  "binary",
];

function toManifest(meta: CrcToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "crc",
    /**
     * One "CRC" group rather than a group per width.
     *
     * `CRC-${width}` was the obvious choice and it was wrong twice over: it produced
     * five categories containing one tool each, and the category header ended up
     * rendering the same string as the tool inside it — so the sidebar showed "CRC-32"
     * nested under "CRC-32".
     */
    category: "CRC",
    tags: [...meta.tags],
    summary: meta.summary,
    directions: ["forward"],
    // Every entry in this family. Not a judgement about implementation quality —
    // these do exactly what they were designed to do — but about what they are for,
    // and the gap between that and what they get used for.
    security: "not-a-mac",
    outputEncodings: CHECKSUM_OUTPUT_ENCODINGS,
    readsInput: true,
    supportsVerify: true,
    supportsFile: true,
    streaming: true,
  };
}

export const CRC_MANIFESTS: readonly ToolManifest[] = CRC_TOOLS.map(toManifest);
