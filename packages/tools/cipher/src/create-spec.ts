import { DEFAULT_AES_KEY_SIZE, DEFAULT_PADDING, OPTION_KEY_SIZE, OPTION_PADDING } from "./pure";
import { DEFAULT_AES_MODE, requireCipherTool } from "./catalogue/tool-meta";
import {
  DEFAULT_TAG_LEN,
  OPTION_DIRECTION,
  OPTION_MODE,
  OPTION_PARAM_SET,
  OPTION_ANUBIS_VARIANT,
  OPTION_GOST_SBOX,
  OPTION_TAG_LEN,
  SPEC_VERSION,
} from "./pure";
import { cipherCatalogueFor } from "./catalogue/options";
import {
  DEFAULT_KDF_DERIVES,
  DEFAULT_KDF_ENVELOPE,
  DEFAULT_KEY_SOURCE,
  OPTION_ARGON2_VARIANT,
  OPTION_KDF_DERIVES,
  OPTION_KDF_ENVELOPE,
  OPTION_KDF_HASH,
  OPTION_KEY_SOURCE,
} from "@ocs/kdf/key-source";
import { DEFAULT_KDF_HASH } from "@ocs/kdf";

import type { CipherSpec } from "./spec";

/** The canonical default-spec factory. */
export function createSpec(options?: { variant?: string }): CipherSpec {
  const variant = options?.variant ?? "aes";
  requireCipherTool(variant);

  const tool = requireCipherTool(variant);
  const base: CipherSpec["options"] = { [OPTION_DIRECTION]: "encrypt" };
  // AES opens on GCM. Opening on ECB would teach the wrong thing by default.
  if (variant === "aes") {
    base[OPTION_MODE] = DEFAULT_AES_MODE;
    /*
     * Seeded, because an `enum` a tool renders and does not seed opens on "(not set)" while the
     * resolver quietly computes at its fallback -- which `tests/registry.test.ts` walks every tool
     * checking. 256 is what Generate produced before this control existed, so a fresh spec behaves
     * exactly as it did.
     */
    base[OPTION_KEY_SIZE] = String(DEFAULT_AES_KEY_SIZE);
  }
  /**
   * Seed the selects the block ciphers render, for the same reason the hash family does.
   *
   * Both values are the fallbacks `resolveCipher` already applies, so nothing computes differently.
   * What changes is that the Mode and Parameter set dropdowns open on the mode and set actually in
   * force instead of on "(not set)" -- which matters more here than anywhere else, because the
   * parameter set is what decides how many bytes the Generate buttons produce for the key and IV.
   */
  if (tool.block && variant !== "aes") base[OPTION_MODE] = tool.block.modes[0]!;
  /*
   * Padding, seeded wherever the tool actually renders the control.
   *
   * Asked of the *catalogue* rather than of `tool.block.modes`, which was the first version and was
   * wrong in the one case that matters most: AES declares no `block` at all -- its modes live in
   * `AES_MODES` -- so the guard never fired for it, and the Padding select would have opened on
   * "(not set)" under CBC while computing at the PKCS#7 fallback. That pairing is the worst available,
   * because it reads as broken and is not. The catalogue is the single place that already knows which
   * options a tool has, so there is no second list to keep in step.
   *
   * PKCS#7 is `readPadding`'s own fallback, so this changes what the select *shows* and never what a
   * fresh spec computes -- the invariant `tests/registry.test.ts` checks by stripping every enum out of
   * a default spec and requiring the same bytes back.
   */
  if (cipherCatalogueFor(variant).options.some((option) => option.id === OPTION_PADDING)) {
    base[OPTION_PADDING] = DEFAULT_PADDING;
  }

  /*
   * The key-derivation selects, on every tool -- they are spliced into every catalogue.
   *
   * All five are seeded even though only Key source is visible while the source is Custom, because a
   * select the user reveals later must already hold a value: an `enum` the form renders without one
   * opens on a disabled "(not set)" while the resolver quietly computes at its fallback, which is the
   * pairing `tests/registry.test.ts` walks every tool checking. Each value here *is* that fallback, so
   * seeding changes what the form shows and never what a spec computes -- the second registry gate,
   * which strips every enum out and requires the same bytes back.
   */
  base[OPTION_KEY_SOURCE] = DEFAULT_KEY_SOURCE;
  base[OPTION_KDF_DERIVES] = DEFAULT_KDF_DERIVES;
  base[OPTION_KDF_ENVELOPE] = DEFAULT_KDF_ENVELOPE;
  base[OPTION_KDF_HASH] = DEFAULT_KDF_HASH;
  base[OPTION_ARGON2_VARIANT] = "argon2id";
  if (tool.paramSets) {
    base[OPTION_PARAM_SET] = tool.defaultParamSet ?? tool.paramSets[0]!.id;
  }
  /**
   * A shaped tool's instance select shares `OPTION_PARAM_SET`, so it is seeded the same way.
   *
   * Exactly one of the two branches ever runs -- a tool has `block` or `shape` -- and this one matters
   * more than it looks: for Schwaemm and TinyJAMBU the instance decides how many bytes Generate
   * produces for the key, so an unseeded select would make the Generate button wrong rather than merely
   * blank.
   */
  if (tool.shape?.instances) {
    base[OPTION_PARAM_SET] = tool.shape.defaultInstance ?? tool.shape.instances[0]!.id;
  }
  /**
   * AEGIS's tag length, which is the only other select this family renders.
   *
   * `DEFAULT_TAG_LEN` is what `readTagLen` already falls back to, so this is the value the tool has
   * always used -- it just now says so in the control instead of showing "(not set)". A string,
   * because the option is an `enum`: writing 16 here would render as "(not set)" for the same reason
   * a missing value does, which is the shape of the bug that made the 256-bit choice inert once.
   */
  if (tool.aead && cipherCatalogueFor(variant).get(OPTION_TAG_LEN)) {
    base[OPTION_TAG_LEN] = String(DEFAULT_TAG_LEN);
  }
  /**
   * GOST 28147-89's S-box set, the third select this family renders.
   *
   * Seeded for the same reason and caught by the same gate: `tests/registry.test.ts` walks every tool
   * and requires each visible `enum` to have a value, because a form showing "(not set)" while the
   * resolver quietly computes at its fallback is the worst pairing available -- it reads as broken and
   * is not. `readGostSbox` already falls back to `test`, so this changes what the control *says* and
   * not what the tool computes, which is the invariant the second half of that gate asserts.
   */
  if (cipherCatalogueFor(variant).get(OPTION_GOST_SBOX)) base[OPTION_GOST_SBOX] = "test";
  if (cipherCatalogueFor(variant).get(OPTION_ANUBIS_VARIANT))
    base[OPTION_ANUBIS_VARIANT] = "tweaked";

  return { specVersion: SPEC_VERSION, variant, options: base };
}
