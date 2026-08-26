import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { CIPHER_TOOLS, type CipherToolMeta } from "./catalogue/tool-meta";

/**
 * `latin1` is offered here and in no other family.
 *
 * Decrypted output is very often text, and rendering it as bytes when the user is trying to
 * read a message is unhelpful. It is still not the default — the first entry is hex, because
 * plenty of decrypted output is not text and mojibake would be worse than honest bytes.
 */
const CIPHER_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "hex",
  "hex-upper",
  "base64",
  "base64url",
  "latin1",
];

function toManifest(meta: CipherToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "cipher",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    // The first family where `inverse` is decryption rather than verification.
    directions: ["forward", "inverse"],
    security: meta.security,
    outputEncodings: CIPHER_OUTPUT_ENCODINGS,
    readsInput: true,
    supportsVerify: true,
    supportsFile: true,
    /**
     * No cipher here streams, and the reason is inherent rather than an implementation gap.
     * An AEAD cannot emit authenticated output until it has seen every byte, and CBC needs
     * the whole ciphertext to strip padding. The input panel says so for any tool with
     * `supportsFile && !streaming`, which is the honest position.
     */
    streaming: false,
  };
}

export const CIPHER_MANIFESTS: readonly ToolManifest[] = CIPHER_TOOLS.map(toManifest);
