import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { ENCODING_TOOLS, type EncodingToolMeta } from "./catalogue/tool-meta";

/**
 * `utf-8` first, because it is the default and decoding to readable text is what people come here
 * for: paste a Base64 string, read the sentence inside it. The rest are for when the decoded bytes
 * are not text -- which is why `hex` is second rather than absent.
 *
 * The list applies to the *decoded* side only. Encoding produces text, and the result panel renders
 * `ToolResult.text` verbatim without consulting this.
 */
const DECODED_ENCODINGS: readonly OutputEncoding[] = [
  "utf-8",
  "hex",
  "hex-upper",
  "base64",
  "base64url",
  "latin1",
  "octal",
  "binary",
];

function toManifest(meta: EncodingToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "encoding",
    category: meta.category,
    tags: [...meta.tags],
    // Both ways, unlike every family before this one. `direction` is the option that picks.
    directions: ["forward", "inverse"],
    summary: meta.summary,
    // The one thing every tool here has to say about itself. See the posture's own doc comment for
    // why this is not `not-a-mac`.
    security: "not-encryption",
    outputEncodings: DECODED_ENCODINGS,
    readsInput: true,
    supportsVerify: true,
    supportsFile: true,
    /**
     * No streaming, and it is a property of the formats rather than a shortcut.
     *
     * Base64 and Base32 are groupwise and could stream; Base58 cannot, because it is arbitrary-
     * precision division over the whole input and the first character depends on the last byte. CBOR
     * decoding needs the whole item. Offering it for two of five and not the others would be a
     * distinction the UI cannot explain, so file input reads into memory and says so.
     */
    streaming: false,
  };
}

export const ENCODING_MANIFESTS: readonly ToolManifest[] = ENCODING_TOOLS.map(toManifest);
