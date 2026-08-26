import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { ASYMMETRIC_TOOLS, type AsymmetricToolMeta } from "./catalogue/tool-meta";

/**
 * `latin1` is offered because RSA decryption very often yields text.
 *
 * Hex stays the default: signatures, public keys and shared secrets are all bytes, and only one
 * of the six operations produces something a person would want to read as characters.
 */
const ASYMMETRIC_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "hex",
  "hex-upper",
  "base64",
  "base64url",
  "latin1",
];

function toManifest(meta: AsymmetricToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "asymmetric",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    /**
     * `inverse` marks the tools with a genuinely reversing pair of operations.
     *
     * RSA has two: verify undoes sign, decrypt undoes encrypt. ECDSA and Ed25519 have
     * sign/verify, which is a check rather than a reversal but is what `inverse` means for
     * every keyed family here. ECDH has neither -- derive has no opposite, and claiming one
     * would put a direction toggle in the header that does nothing.
     */
    directions: meta.operations.includes("verify") ? ["forward", "inverse"] : ["forward"],
    security: meta.security,
    outputEncodings: ASYMMETRIC_OUTPUT_ENCODINGS,
    /**
     * File input is offered because signing a file is a real thing to want, and it is the one
     * operation in this family where a large input makes sense.
     */
    readsInput: true,
    supportsVerify: true,
    supportsFile: true,
    /**
     * Nothing here streams. A signature covers a digest of the whole message, so the digest
     * could stream -- but the curve operation cannot begin until it is complete, and RSA's
     * WebCrypto interface takes the whole message in one call regardless. Claiming otherwise
     * would put a progress bar on something that still buffers the file.
     */
    streaming: false,
  };
}

export const ASYMMETRIC_MANIFESTS: readonly ToolManifest[] = ASYMMETRIC_TOOLS.map(toManifest);
