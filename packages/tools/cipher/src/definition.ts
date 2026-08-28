import type { ToolDefinition } from "@ocs/engine";
import { cipherCatalogueFor } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { CIPHER_TOOL_IDS, DEFAULT_AES_MODE, requireCipherTool } from "./catalogue/tool-meta";
import { computeCipher, createCipherStream } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { CIPHER_MANIFESTS } from "./manifest";
import { TAG_IV_MANUAL } from "./pure";
import { keySourceTag, readKdfDerives, readKeySource } from "@ocs/kdf/key-source";
import { createSpec } from "./create-spec";
import { cipherAcceptedByteLengths, cipherGenerateLength } from "./resolve";
import { readMode, TAG_CHACHA_COUNTER, TAG_RC4 } from "./pure";
import { CipherSpec } from "./spec";

/**
 * Every tag a cipher spec answers to, and **every tool returns one**.
 *
 * It used to return a bare mode string, and `undefined` for the 45 tools with no mode -- ChaCha20-
 * Poly1305, XChaCha, Ascon, Salsa, AEGIS and every shaped cipher. That was harmless while the only
 * gated options were mode-specific. It stopped being harmless the moment the Key field itself became
 * gated: `isAvailableOn` reads a missing tag as "not available", so those 45 tools would have lost
 * their key input entirely -- and it would have typechecked and passed the whole suite, because the
 * tests write option values straight into a spec rather than through the form. That is the MAC
 * family's four-inert-controls defect, which this repo has now shipped three times, and
 * `tests/cipher.test.ts` gained a walk over every tool's own default spec to catch the class.
 *
 * Three kinds of tag, and the third is the interesting one:
 *
 * - the **mode** (or the ChaCha counter / RC4 tag), exactly as before
 * - the **key source**, namespaced `key:` -- see `keySourceTag`
 * - `iv:<mode>`, emitted only while the IV is something the user supplies
 *
 * That last one encodes a *conjunction*, which `isAvailableOn` cannot express: it ORs its list, so
 * there is no way to say "this mode **and** the IV is not derived". The IV field is therefore gated on
 * `iv:cbc` rather than on `cbc`, and the tag is withheld when the KDF is deriving the IV -- so the
 * field disappears without any other mode-gated control being affected.
 */
export function cipherVariantTags(toolId: string, spec: CipherSpec): readonly string[] {
  const tags: string[] = [];

  const tool = requireCipherTool(toolId);
  const mode =
    toolId === "aes"
      ? readMode(spec.options, DEFAULT_AES_MODE)
      : tool.block
        ? readMode(spec.options, tool.block.modes[0]!)
        : undefined;
  if (mode) tags.push(mode);
  // Every raw ChaCha exposes the counter, which is what the tag gates.
  if (
    toolId === "chacha20" ||
    toolId === "chacha12" ||
    toolId === "chacha8" ||
    toolId === "chacha20orig"
  ) {
    tags.push(TAG_CHACHA_COUNTER);
  }
  if (toolId === "rc4") tags.push(TAG_RC4);

  const source = readKeySource(spec.options);
  tags.push(keySourceTag(source));

  /*
   * The IV is the user's unless a KDF is deriving it. `mode` is undefined for a shaped or stream
   * cipher, whose nonce field is gated on nothing at all, so there is nothing to withhold there.
   */
  const derivesIv = source !== "directinput" && readKdfDerives(spec.options) === "key-iv";
  if (!derivesIv) {
    tags.push(TAG_IV_MANUAL);
    if (mode) tags.push(`iv:${mode}`);
  }

  return tags;
}

/**
 * Builds the full contract for one cipher tool.
 */
export function cipherToolDefinition(toolId: string): ToolDefinition<CipherSpec> {
  requireCipherTool(toolId);
  const manifest = CIPHER_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) throw new Error(`No manifest for cipher tool: ${toolId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: cipherCatalogueFor(toolId),
    lintRules: RULES,
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: CipherSpec,
    describe: describeSpec,
    compute: computeCipher,
    ...(manifest.streaming ? { createStream: createCipherStream } : {}),
    /**
     * So Generate offers a length this tool will actually accept.
     *
     * The catalogue is resolved once per tool and cannot know the mode, so its static number was wrong
     * for eleven cipher/mode combinations -- five of them AES's own. See `cipherGenerateLength`.
     */
    generateLength: cipherGenerateLength,
    /**
     * And the field checks against a length this tool will actually accept.
     *
     * The other half of the same defect: the catalogue's union for AES's key is 16/24/32, so a
     * correctly generated 64-byte XTS key was reported as "needs 16, 24 or 32 bytes". See
     * `cipherAcceptedByteLengths`.
     */
    acceptedByteLengths: cipherAcceptedByteLengths,
    /**
     * For AES the tag is the *mode*, which is what hides the nonce field under ECB and the AAD
     * field under CBC and CTR. The other tools have one fixed mode, so their tag is a constant
     * that reveals the one control unique to them.
     */
    variantTag: (spec) => cipherVariantTags(toolId, spec),
  };
}

export { CIPHER_TOOL_IDS };

export {
  fernetOperation,
  fernetCrypto,
  cobblestoneOperation,
  cobblestoneCrypto,
  createCobblestoneStream,
} from "./bindings";
export { computeCipher, createCipherStream, constructionLabel } from "./compute";
export {
  acceptedNonceLengths,
  cipherAcceptedByteLengths,
  cipherBlockSize,
  cipherGenerateLength,
  modeForSpec,
  requiredNonceLength,
  requiresBlockAlignment,
  resolveCipher,
  type ResolvedCipher,
  type ResolveResult,
} from "./resolve";
export { cipherCatalogueFor } from "./catalogue/options";
export { createSpec } from "./create-spec";
export { describeSpec } from "./explain/describe";
export { RULES, RULE_CODES } from "./lint/rules";
export { lint, applyAllFixes } from "./lint/run";
