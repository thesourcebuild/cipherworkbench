import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { KDF_TOOLS, type KdfToolMeta } from "./catalogue/tool-meta";

const KDF_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "hex-upper",
  "hex",
  "base64",
  "base64url",
  "base32",
];

function toManifest(meta: KdfToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "kdf",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    /**
     * The only family where `inverse` means something real. It is not decryption — a
     * password hash cannot be reversed — it is verification: re-derive with the stored
     * parameters and compare. The three tools with a self-describing output format can do
     * that; PBKDF2 and HKDF cannot, because their parameters are not in their output.
     */
    directions: meta.supportsVerify ? ["forward", "inverse"] : ["forward"],
    security: meta.security,
    outputEncodings: KDF_OUTPUT_ENCODINGS,
    /**
     * A KDF's inputs are its password and salt, both of which are options. There is nothing
     * for the input panel to supply, so file input is off and the whole streaming question
     * does not arise.
     */
    /**
     * A KDF reads no byte input: its password and salt are options, and `computeKdf` ignores the
     * argument entirely. `supportsFile: false` used to be the only thing said about that, which hid
     * the File tab and left a textarea above it that went nowhere.
     */
    readsInput: false,
    // A derived key is exactly the kind of value somebody has in advance -- a PHC string out of a
    // database, a test vector from an RFC -- so this stays true even though nothing is read from a box.
    supportsVerify: true,
    supportsFile: false,
    streaming: false,
  };
}

export const KDF_MANIFESTS: readonly ToolManifest[] = KDF_TOOLS.map(toManifest);
