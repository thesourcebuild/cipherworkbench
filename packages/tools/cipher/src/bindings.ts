import {
  aeskw,
  aeskwp,
  aessiv,
  cbc,
  cfb,
  ctr,
  ecb,
  gcm,
  gcmsiv,
  unsafe,
} from "@noble/ciphers/aes.js";
import type {
  ChamVariant,
  MorusVariant,
  PresentVariant,
  RectangleVariant,
  SimeckVariant,
  SkinnyVariant,
} from "@ocs/algos";
import {
  chacha12,
  chacha20,
  chacha20orig,
  chacha20poly1305,
  chacha8,
  xchacha20poly1305,
} from "@noble/ciphers/chacha.js";
import { salsa20, xsalsa20, xsalsa20poly1305 } from "@noble/ciphers/salsa.js";
import {
  aegisDecrypt,
  aegisEncrypt,
  asconAead128Decrypt,
  asconAead128Encrypt,
  ccmDecrypt,
  ccmEncrypt,
  gcmDecrypt,
  gcmEncrypt,
  ocbDecrypt,
  ocbEncrypt,
  xtsDecrypt,
  xtsEncrypt,
  type AegisVariant,
  createAria,
  createBlowfish,
  createCamellia,
  createCast5,
  createDes,
  createIdea,
  createKuznyechik,
  createMagma,
  createPresent,
  createRc2,
  createSeed,
  createChaskeyLts,
  createCham,
  createLblock,
  createLilliput,
  createLsDesign,
  createLed,
  createPiccolo,
  createPride,
  createRoadRunneR,
  createPrince,
  createRectangle,
  createSparx,
  createTwine,
  createSerpent,
  createSimeck,
  createSkinny,
  createSimon,
  createSm4,
  createBelt,
  createCast6,
  createGost28147,
  createKalyna,
  createLea,
  createClefia,
  createKasumi,
  createAnubis,
  createKhazad,
  createSaferPlus,
  createHight,
  createMars,
  rabbitCrypt,
  snow3gCrypt,
  sosemanukCrypt,
  triviumCrypt,
  createMisty1,
  createNoekeon,
  createRc5,
  createRc6,
  createShacal2,
  createSkipjack,
  createSpeck,
  createTea,
  createThreefish,
  createXtea,
  createXxtea,
  ketjeJrOpen,
  morusOpen,
  morusSeal,
  MORUS_TAG_LEN,
  ketjeJrSeal,
  KETJE_JR_TAG_LEN,
  SIMON_SPECK_VARIANTS,
  createTwofish,
  createTripleDes,
  decryptBlockMode,
  encryptBlockMode,
  padBlocks,
  unpadBlocks,
  type PaddingScheme,
  elephantDecrypt,
  elephantEncrypt,
  giftCofbDecrypt,
  giftCofbEncrypt,
  grain128,
  grain128AeadDecrypt,
  grain128AeadEncrypt,
  grainV1,
  hc128,
  hc256,
  isapDecrypt,
  isapEncrypt,
  photonBeetleDecrypt,
  photonBeetleEncrypt,
  rc4,
  romulusDecrypt,
  romulusEncrypt,
  schwaemmDecrypt,
  schwaemmEncrypt,
  tinyJambuDecrypt,
  tinyJambuEncrypt,
  acornDecrypt,
  acornEncrypt,
  deoxysIIOpen,
  deoxysIISeal,
  norxDecrypt,
  norxEncrypt,
  xoodyakDecrypt,
  xoodyakEncrypt,
  zuc,
  type ElephantVariant,
  type IsapVariant,
  type PhotonBeetleRate,
  type RomulusMode,
  type SchwaemmVariant,
  type TinyJambuKeyBits,
  type BlockCipher,
  type BlockMode,
} from "@ocs/algos";
import { randomBytes } from "@ocs/engine";

/**
 * The only module in this package that reaches an implementation.
 *
 * `noble`'s AEAD constructions append the 16-byte tag to the ciphertext on encrypt and
 * expect it there on decrypt, and they throw when it does not verify. Both behaviours are
 * what this family wants: a tag transmitted separately from its ciphertext is a reliable
 * source of implementation bugs, and a decrypt that quietly returned garbage on a bad tag
 * would defeat the point of authenticating at all.
 */

export interface CipherOperation {
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
}

/** AES's block, named because the padding wrappers below would otherwise carry a bare 16. */
const AES_BLOCK = 16;

/**
 * A block-mode operation with its padding applied around it.
 *
 * For the AES ECB and CBC paths only, where the cipher comes from `@noble/ciphers` and does PKCS#7
 * itself. `disablePadding` turns that off and this puts the selected scheme in its place, so the four
 * schemes have one implementation shared with every other block cipher in the family.
 *
 * Note the asymmetry is real rather than tidiness: encryption pads before the cipher and decryption
 * unpads after it, and `unpadBlocks` validates -- so a wrong key under CBC still fails with a message
 * about the padding rather than returning a plausible short plaintext.
 */
function withPadding(
  inner: CipherOperation,
  blockSize: number,
  scheme: PaddingScheme,
): CipherOperation {
  return {
    // `randomBytes` is only reached by ISO 10126, whose filler is random by definition. It comes from
    // `@ocs/engine`, which wraps `crypto.getRandomValues` -- `@ocs/algos` has no platform globals, so
    // the generator is injected rather than drawn there.
    encrypt: (data) => inner.encrypt(padBlocks(data, blockSize, scheme, randomBytes)),
    decrypt: (data) => unpadBlocks(inner.decrypt(data), blockSize, scheme),
  };
}

/**
 * Wraps one of `@ocs/algos`'s AEADs, whose decrypt returns `null` rather than throwing.
 *
 * `null` is the right shape for a pure function and a throw is the right shape here, because
 * `computeCipher` turns a failed tag into a rendered result in exactly one place. This adapter is that
 * boundary, and it exists once so GCM, CCM and OCB cannot word the same failure three ways -- which is
 * what happened with Ascon and AEGIS before there was a helper.
 */
function sealed(
  label: string,
  seal: (data: Uint8Array) => Uint8Array,
  open: (data: Uint8Array) => Uint8Array | null,
): CipherOperation {
  return {
    encrypt: seal,
    decrypt: (data) => {
      const opened = open(data);
      if (!opened) throw new Error(`${label}: authentication tag did not verify`);
      return opened;
    },
  };
}

export function aesOperation(
  mode: string,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  tagLen: number,
  padding: PaddingScheme = "pkcs7",
): CipherOperation {
  const withAad = aad.length > 0 ? aad : undefined;

  switch (mode) {
    case "gcm":
      return gcm(key, nonce, withAad);
    case "gcm-siv":
      return gcmsiv(key, nonce, withAad);
    case "ctr":
      return ctr(key, nonce);
    case "cbc":
      /*
       * noble applies PKCS#7 itself, which is what every other implementation does -- so the default
       * path is left exactly as it was, on the audited implementation. The other three schemes turn
       * noble's padding off and go through `padBlocks`, so there is one implementation of each scheme
       * for AES and for the eleven other block ciphers rather than two that could drift.
       */
      return padding === "pkcs7" || padding === "pkcs5"
        ? cbc(key, nonce)
        : withPadding(cbc(key, nonce, { disablePadding: true }), AES_BLOCK, padding);
    case "cfb":
      return cfb(key, nonce);
    case "ofb":
      return aesOfbOperation(key, nonce);
    case "ecb":
      return padding === "pkcs7" || padding === "pkcs5"
        ? ecb(key)
        : withPadding(ecb(key, { disablePadding: true }), AES_BLOCK, padding);
    case "aessiv":
      /**
       * RFC 5297, and note it is `aessiv` rather than `siv`.
       *
       * `siv()` still exists in noble v2 as a removed-alias stub that throws when called -- it meant
       * GCM-SIV in v1. Wiring the obvious-looking name would have produced a mode that failed at
       * runtime and passed every typecheck.
       *
       * AAD is variadic here because RFC 5297 takes a *vector* of associated data strings rather than
       * one. This family's UI offers a single field, which is the common case; passing it as the sole
       * element is the faithful reading of that.
       */
      // Variadic, not an array argument: RFC 5297's associated data is a vector, and noble models it
      // as a rest parameter. Passing one array would make the whole vector a single AD string.
      return withAad ? aessiv(key, withAad) : aessiv(key);
    case "kw":
      return aeskw(key);
    case "kwp":
      return aeskwp(key);
    case "ccm":
      /**
       * CCM, OCB and XTS all come from `@ocs/algos` over `aesBlockCipher`, because noble has none of
       * the three. That is also what makes them available on Camellia, ARIA and SM4 for free -- the
       * mode layer only ever needed a 128-bit block permutation.
       */
      return sealed(
        "AES-CCM",
        (data) => ccmEncrypt(aesBlockCipher(key), nonce, data, aad, tagLen),
        (data) => ccmDecrypt(aesBlockCipher(key), nonce, data, aad, tagLen),
      );
    case "ocb":
      return sealed(
        "AES-OCB",
        (data) => ocbEncrypt(aesBlockCipher(key), nonce, data, aad, tagLen),
        (data) => ocbDecrypt(aesBlockCipher(key), nonce, data, aad, tagLen),
      );
    case "xts":
      return aesXtsOperation(key, nonce);
    default:
      throw new Error(`No AES binding for mode: ${mode}`);
  }
}

export function xsalsaPolyOperation(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): CipherOperation {
  // libsodium's secretbox takes no associated data at all, so the AAD field is not offered for this
  // tool and this argument is here only to keep one call shape across the family.
  void aad;
  return xsalsa20poly1305(key, nonce);
}

/** Salsa20 and XSalsa20 differ only in nonce length, so one binding serves both. */
export function salsaOperation(
  key: Uint8Array,
  nonce: Uint8Array,
  extended: boolean,
): CipherOperation {
  const run = (data: Uint8Array) =>
    extended ? xsalsa20(key, nonce, data) : salsa20(key, nonce, data);
  return { encrypt: run, decrypt: run };
}

/**
 * Ascon-AEAD128.
 *
 * The one AEAD here whose decryption reports failure by returning `null` rather than throwing, since
 * `@ocs/algos` owns it and that is the better shape for a pure function. The throw is reintroduced at
 * this boundary with a message the family's `catch` recognises, because `computeCipher` turns a failed
 * tag into a rendered result and it does that for every AEAD in one place -- a second path would be a
 * second chance to word the same explanation differently.
 */
export function asconOperation(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): CipherOperation {
  return {
    encrypt: (data) => asconAead128Encrypt(key, nonce, data, aad),
    decrypt: (data) => {
      const opened = asconAead128Decrypt(key, nonce, data, aad);
      if (!opened) throw new Error("Ascon-AEAD128: authentication tag did not verify");
      return opened;
    },
  };
}

/**
 * AEGIS-128L and AEGIS-256.
 *
 * The tag length is a parameter rather than a constant here, which is the whole reason the resolved
 * spec carries one: encryption appends whatever was chosen and decryption must split at the same
 * place, and a mismatch would look like a tag failure rather than a configuration error.
 */
export function aegisOperation(
  variant: AegisVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  tagLen: number,
): CipherOperation {
  return {
    encrypt: (data) => aegisEncrypt(variant, key, nonce, data, aad, tagLen),
    decrypt: (data) => {
      const opened = aegisDecrypt(variant, key, nonce, data, aad, tagLen);
      if (!opened) throw new Error("AEGIS: authentication tag did not verify");
      return opened;
    },
  };
}

/**
 * DES, 3DES and SM4 through the shared mode layer.
 *
 * One function for three ciphers and five modes, which is the whole return on putting the modes in
 * `@ocs/algos` rather than beside each cipher. AES does not come through here -- noble's own AEAD and
 * key-wrap constructions do more than a mode layer can -- except for OFB, which noble does not offer
 * and which this layer supplies over noble's ECB used as a bare block permutation.
 */
/**
 * Word size in bits, from a `<blockBits>-<keyBits>` parameter-set id.
 *
 * Throws on anything unrecognised rather than defaulting. `SIMON_SPECK_VARIANTS` is the same list
 * the metadata is generated from, so a set that reaches here and is not in it means the two halves
 * have drifted -- which is exactly the failure that should stop rather than produce output.
 */
function simonSpeckWordBits(paramSetId: string | undefined): 16 | 24 | 32 | 48 | 64 {
  const match = /^(\d+)-(\d+)$/.exec(paramSetId ?? "");
  const blockBits = match ? Number(match[1]) : NaN;
  const known = SIMON_SPECK_VARIANTS.some(
    (v) => v.blockBits === blockBits && v.keyBits === Number(match![2]),
  );
  if (!known) {
    throw new Error(`Unknown Simon/Speck parameter set: ${String(paramSetId)}`);
  }
  return (blockBits / 2) as 16 | 24 | 32 | 48 | 64;
}

/**
 * Block size in bits, from a Kalyna `<blockBits>-<keyBits>` parameter-set id.
 *
 * Throws rather than defaulting, for the same reason `simonSpeckWordBits` does: the id and the metadata
 * are two halves of one list, and a set that reaches here unrecognised means they have drifted.
 */
function kalynaBlockBits(paramSetId: string | undefined): 128 | 256 | 512 {
  const blockBits = Number(/^(\d+)-(\d+)$/.exec(paramSetId ?? "")?.[1] ?? NaN);
  if (blockBits !== 128 && blockBits !== 256 && blockBits !== 512) {
    throw new Error(`Unknown Kalyna parameter set: ${String(paramSetId)}`);
  }
  return blockBits;
}

export function blockCipherOperation(
  toolId: string,
  mode: string,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  tagLen: number,
  effectiveKeyBits?: number,
  /**
   * The selected parameter set's id, for the two tools that have them.
   *
   * Required in practice for Simon and Speck -- the lookup below throws without it rather than
   * quietly building the default set, because a Speck48/96 request answered with Speck128/128 would
   * encrypt successfully and match nothing.
   */
  paramSetId?: string,
  /** RC5's round count and Threefish's tweak: two more parameters that belong to one tool each. */
  rc5Rounds?: number,
  tweak?: Uint8Array,
  /** GOST 28147-89's S-box set: the fourth parameter here that belongs to a single cipher. */
  gostSbox?: string,
  anubisVariant?: string,
  /**
   * Which padding ECB and CBC use. Ignored by every other mode, which never pads.
   *
   * Defaulted rather than required, because `padBlocks` defaults the same way -- so a caller that has
   * not been updated behaves exactly as it did instead of throwing, and there is one place that says
   * what "unspecified" means.
   */
  padding: PaddingScheme = "pkcs7",
): CipherOperation {
  /**
   * The cipher itself, by id. A `Record` rather than a chain ending in a default, for the reason
   * given in `catalogue/options.ts`: a tool added to the metadata without an entry here should fail
   * by name rather than silently become SM4.
   */
  const factories: Record<string, (k: Uint8Array) => BlockCipher> = {
    des: createDes,
    "3des": createTripleDes,
    sm4: createSm4,
    belt: createBelt,
    camellia: createCamellia,
    aria: createAria,
    magma: createMagma,
    blowfish: createBlowfish,
    /**
     * Read from the resolved parameter set, never inferred from the key length.
     *
     * 10 and 16 bytes happen to identify the two sets uniquely here, so inference would work -- and it
     * is still the wrong shape: this repo records Kalyna, where two sets share a key length and the
     * inference produces a plausible wrong answer. One rule for every parameter-set tool.
     */
    present: (k: Uint8Array) =>
      createPresent(k, (paramSetId as PresentVariant | undefined) ?? "80"),
    /**
     * Simon and Speck are one tool each over ten parameter sets.
     *
     * The word size is half the block and comes out of the set's id; `createSpeck`/`createSimon`
     * then validate the (word size, key length) pair against the paper's own table, which is what
     * stops a malformed id inventing a variant that does not exist. Note that the *key length* is
     * not passed -- it is implied by the key handed in, and the resolver has already refused a key
     * the selected set does not take.
     */
    speck: (k: Uint8Array) => createSpeck(k, simonSpeckWordBits(paramSetId)),
    simon: (k: Uint8Array) => createSimon(k, simonSpeckWordBits(paramSetId)),
    /**
     * Three more tools whose parameter set decides the block size, so the same rule applies: read the
     * set from the spec, never the tool's own `block.size`.
     */
    cham: (k: Uint8Array) =>
      createCham(k, (paramSetId as ChamVariant | undefined) ?? "128-128"),
    simeck: (k: Uint8Array) =>
      createSimeck(k, (paramSetId as SimeckVariant | undefined) ?? "64-128"),
    skinny: (k: Uint8Array) =>
      createSkinny(k, (paramSetId as SkinnyVariant | undefined) ?? "128-256"),
    twofish: createTwofish,
    serpent: createSerpent,
    kuznyechik: createKuznyechik,
    seed: createSeed,
    cast5: createCast5,
    idea: createIdea,
    /**
     * RC2 alone takes a second argument, because its effective key length is a genuine parameter of
     * the cipher rather than a property of the key -- and the resolver reads it from its own option.
     * The factory signature is `(key) => BlockCipher`, so this closes over the resolved value.
     */
    rc2: (k: Uint8Array) => createRc2(k, effectiveKeyBits ?? k.length * 8),
    cast6: createCast6,
    rc6: createRc6,
    /**
     * RC5 and Threefish close over their own extra parameter, as RC2 does.
     *
     * The factory signature is `(key) => BlockCipher`, so anything that is neither the key nor derived
     * from it arrives this way. RC5's round count defaults to 12 rather than throwing, because the
     * resolver has already read it from the option and clamped it; Threefish's tweak defaults to the
     * all-zero one, which is the case its published vectors use.
     */
    rc5: (k: Uint8Array) => createRc5(k, rc5Rounds ?? 12),
    threefish: (k: Uint8Array) =>
      createThreefish(k, tweak && tweak.length === 16 ? tweak : undefined),
    tea: createTea,
    xtea: createXtea,
    xxtea: createXxtea,
    skipjack: createSkipjack,
    lea: createLea,
    misty1: createMisty1,
    kasumi: createKasumi,
    khazad: createKhazad,
    anubis: (k: Uint8Array) =>
      createAnubis(k, anubisVariant === "original" ? "original" : "tweaked"),
    saferp: createSaferPlus,
    sparx: createSparx,
    chaskeylts: createChaskeyLts,
    twine: createTwine,
    led: createLed,
    prince: createPrince,
    lblock: createLblock,
    robin: (k: Uint8Array) => createLsDesign(k, "robin"),
    robinstar: (k: Uint8Array) => createLsDesign(k, "robinstar"),
    fantomas: (k: Uint8Array) => createLsDesign(k, "fantomas"),
    roadrunner80: (k: Uint8Array) => createRoadRunneR(k, "64-80"),
    roadrunner128: (k: Uint8Array) => createRoadRunneR(k, "64-128"),
    lilliput: createLilliput,
    pride: createPride,
    piccolo: createPiccolo,
    rectangle: (k: Uint8Array) =>
      createRectangle(k, (paramSetId as RectangleVariant | undefined) ?? "64-128"),
    clefia: createClefia,
    mars: createMars,
    hight: createHight,
    noekeon: createNoekeon,
    shacal2: createShacal2,
    /**
     * GOST 28147-89 closes over its S-box choice, as RC2 and RC5 close over theirs.
     *
     * The 1989 standard leaves the tables to the deployer, so the set is a genuine parameter of the
     * cipher rather than a preference -- two implementations disagreeing about it agree about nothing.
     */
    gost28147: (k: Uint8Array) => createGost28147(k, gostSbox === "crypto" ? "crypto" : "test"),
    /**
     * Kalyna's block size comes from the selected parameter set, not from the key.
     *
     * It is the only cipher here where the *block* is a parameter and the key does not determine it: a
     * 32-byte key is legal for both Kalyna-128/256 and Kalyna-256/256. So the set id has to reach the
     * factory, and `kalynaBlockBits` throws on anything it does not recognise rather than defaulting --
     * a Kalyna-512 request answered with a 128-bit block would encrypt successfully and match nothing.
     */
    kalyna: (k: Uint8Array) => createKalyna(k, kalynaBlockBits(paramSetId)),
  };
  const factory = factories[toolId];
  if (!factory) throw new Error(`No block cipher implementation for "${toolId}".`);
  const cipher: BlockCipher = factory(key);

  /**
   * GCM and CCM are not `BlockMode`s and cannot be: they authenticate, so they own the tag and the
   * failure path, where `encryptBlockMode` returns bytes and nothing else. They are handled before the
   * mode layer for that reason rather than being smuggled into the mode string.
   *
   * SM4-GCM and SM4-CCM are the reason this exists at all -- RFC 8998 specifies exactly those two for
   * TLS 1.3 with SM3, so they are the *standardised* use of the cipher rather than a curiosity. That
   * Camellia and ARIA get them too is the mode layer paying for itself again.
   */
  const label = `${toolId.toUpperCase()}-${mode.toUpperCase()}`;
  if (mode === "gcm") {
    return sealed(
      label,
      (data) => gcmEncrypt(cipher, iv, data, aad, tagLen),
      (data) => gcmDecrypt(cipher, iv, data, aad, tagLen),
    );
  }
  if (mode === "ccm") {
    return sealed(
      label,
      (data) => ccmEncrypt(cipher, iv, data, aad, tagLen),
      (data) => ccmDecrypt(cipher, iv, data, aad, tagLen),
    );
  }

  const options =
    mode === "ecb" ? { padding, random: randomBytes } : { iv, padding, random: randomBytes };
  return {
    encrypt: (data) => encryptBlockMode(cipher, mode as BlockMode, data, options),
    decrypt: (data) => decryptBlockMode(cipher, mode as BlockMode, data, options),
  };
}

/**
 * AES as a bare block permutation, for the modes noble does not implement.
 *
 * Through `unsafe.expandKeyLE` / `unsafe.encryptBlock` rather than `ecb(key, { disablePadding: true })`,
 * and that distinction was a shipped bug worth recording. noble v2 guards its AEAD-shaped APIs against
 * misuse: calling `encrypt()` twice on one instance throws `cannot encrypt() twice with same key +
 * nonce`. ECB has no nonce, but the guard applies anyway -- so AES-OFB, which called `raw.encrypt` once
 * per block, worked for a single block and threw on the second. The only OFB test was NIST SP 800-38A's
 * F.4.1 vector, which is exactly one block, so nothing caught it.
 *
 * `unsafe` is the right door: it is noble's own name for the primitives beneath the modes, it has no
 * per-instance state, and the key schedule is expanded once rather than per block. The two callers here
 * -- OFB, and the CCM/GCM/XTS/OCB wiring below -- both need a plain permutation, and
 * `tests/cipher.test.ts` now compares every AES mode against OpenSSL at several lengths rather than at
 * one block.
 */
export function aesBlockCipher(key: Uint8Array): BlockCipher {
  const encKey = unsafe.expandKeyLE(key);
  const decKey = unsafe.expandKeyDecLE(key);
  /**
   * The scratch copy is not an optimisation, it is the correctness fix.
   *
   * `unsafe.encryptBlock(xk, block)` encrypts **in place** and returns its own argument, so handing it
   * a live buffer destroys the caller's data. GCM found this immediately: the counter block was
   * overwritten with its own encryption, so block one was right and every block after it was wrong. The
   * `BlockCipher` contract in `blockmodes.ts` says a cipher reads `src` and writes `dst`, and
   * `tests/cipher.test.ts` now asserts that of every adapter -- this one included.
   */
  const scratch = new Uint8Array(16);
  return {
    blockSize: 16,
    encryptBlock: (src, dst) => {
      scratch.set(src);
      dst.set(unsafe.encryptBlock(encKey, scratch));
    },
    decryptBlock: (src, dst) => {
      scratch.set(src);
      dst.set(unsafe.decryptBlock(decKey, scratch));
    },
  };
}

/**
 * AES-OFB, built on that permutation.
 *
 * noble offers ECB, CBC, CFB, CTR and the AEADs but not OFB, and OFB is what a good deal of older
 * OpenSSL output uses. The keystream comes from encrypting the state in both directions, so decryption
 * never calls `decryptBlock` at all.
 */
export function aesOfbOperation(key: Uint8Array, iv: Uint8Array): CipherOperation {
  const cipher = aesBlockCipher(key);
  return {
    encrypt: (data) => encryptBlockMode(cipher, "ofb", data, { iv }),
    decrypt: (data) => decryptBlockMode(cipher, "ofb", data, { iv }),
  };
}

/**
 * AES-XTS, whose key is two keys.
 *
 * The 32- or 64-byte key string splits down the middle: the first half enciphers the data, the second
 * enciphers the tweak. Two `aesBlockCipher` instances rather than one, and note there is no 192-bit
 * XTS -- SP 800-38E defines only XTS-AES-128 and XTS-AES-256, which is why `AES_MODES`'s entry carries
 * its own `keyLengths` of `[32, 64]` instead of inheriting AES's three.
 */
export function aesXtsOperation(key: Uint8Array, dataUnit: Uint8Array): CipherOperation {
  const half = key.length / 2;
  const dataCipher = aesBlockCipher(key.subarray(0, half));
  const tweakCipher = aesBlockCipher(key.subarray(half));
  return {
    encrypt: (data) => xtsEncrypt(dataCipher, tweakCipher, dataUnit, data),
    decrypt: (data) => xtsDecrypt(dataCipher, tweakCipher, dataUnit, data),
  };
}

export function chachaPolyOperation(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): CipherOperation {
  return chacha20poly1305(key, nonce, aad.length > 0 ? aad : undefined);
}

export function xchachaPolyOperation(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): CipherOperation {
  return xchacha20poly1305(key, nonce, aad.length > 0 ? aad : undefined);
}

/**
 * Raw ChaCha20 and RC4 are stream ciphers, so encrypt and decrypt are the same XOR.
 *
 * Written as one object with two identical methods rather than collapsed into a single call,
 * so the compute path treats every cipher uniformly instead of branching on whether
 * direction happens to matter.
 */
export function chacha20Operation(
  toolId: string,
  key: Uint8Array,
  nonce: Uint8Array,
  counter: number,
): CipherOperation {
  /**
   * One `Record`, no fall-through, for the same reason as everywhere else in this file: a raw ChaCha
   * tool added to the metadata without an entry here should fail by name rather than silently become
   * twenty-round ChaCha with the RFC layout, which would be right for one of the four and wrong for
   * the other three in a way no round-trip test can see.
   */
  const variants: Record<
    string,
    (k: Uint8Array, n: Uint8Array, d: Uint8Array, o?: Uint8Array, c?: number) => Uint8Array
  > = {
    chacha20,
    chacha12,
    chacha8,
    chacha20orig,
  };
  const cipher = variants[toolId];
  if (!cipher) throw new Error(`No raw ChaCha binding for "${toolId}".`);

  const run = (data: Uint8Array) => cipher(key, nonce, data, undefined, counter);
  return { encrypt: run, decrypt: run };
}

/**
 * The six eSTREAM-era stream ciphers, by id.
 *
 * One `Record`, no fall-through, for the sixth time in this file -- and here the consequence would have
 * been quiet rather than loud: every one of these is a keystream XOR with a key and a nonce, so a tool
 * that fell through to the wrong arm would encrypt and decrypt perfectly and produce a value nothing
 * else in the world agrees with.
 */
export function streamCipherOperation(
  toolId: string,
  key: Uint8Array,
  nonce: Uint8Array,
): CipherOperation {
  const ciphers: Record<string, (data: Uint8Array) => Uint8Array> = {
    zuc128: (data) => zuc("zuc128", key, nonce, data),
    zuc256: (data) => zuc("zuc256", key, nonce, data),
    hc128: (data) => hc128(key, nonce, data),
    hc256: (data) => hc256(key, nonce, data),
    grainv1: (data) => grainV1(key, nonce, data),
    grain128: (data) => grain128(key, nonce, data),
    // Rabbit's nonce is legitimately empty or eight bytes, and the two are different
    // keystreams rather than one being a special case of the other -- see `createRabbit`.
    rabbit: (data) => rabbitCrypt(key, nonce, data),
    trivium: (data) => triviumCrypt(key, nonce, data),
    sosemanuk: (data) => sosemanukCrypt(key, nonce, data),
    snow3g: (data) => snow3gCrypt(key, nonce, data),
  };
  const run = ciphers[toolId];
  if (!run) throw new Error(`No stream cipher implementation for "${toolId}".`);
  // A fresh engine per call, as RC4 does: these all advance state with the keystream, so one instance
  // shared across both directions would produce a different keystream the second time.
  return { encrypt: run, decrypt: run };
}

/**
 * The nine NIST lightweight finalists, by id, with the instance carried as an argument.
 *
 * One `Record`, no fall-through, for the seventh time in this file -- and the consequence here would be
 * the quietest yet: every one of these is `(key, nonce, plaintext, aad) -> ciphertext || tag`, so a tool
 * wired to the wrong arm would encrypt, decrypt, verify its own tag and produce a value that no other
 * implementation in the world agrees with.
 *
 * The instance id is validated by the implementations themselves -- `schwaemmEncrypt` indexes a `Record`
 * of parameter sets, `tinyJambuEncrypt` a `Record` of key sizes -- so a stale id from a share link
 * fails by name rather than silently running the default.
 */
export function lwcOperation(
  toolId: string,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  instanceId: string | undefined,
): CipherOperation {
  const withInstance = <T extends string>(fallback: T): T =>
    (instanceId as T | undefined) ?? fallback;
  const constructions: Record<string, CipherOperation> = {
    acorn: sealed(
      "ACORN-128",
      (data) => acornEncrypt(key, nonce, data, aad),
      (data) => acornDecrypt(key, nonce, data, aad),
    ),
    deoxysii: sealed(
      "Deoxys-II-256-128",
      (data) => deoxysIISeal(key, nonce, data, aad),
      (data) => deoxysIIOpen(key, nonce, data, aad),
    ),
    norx: sealed(
      "NORX32-4-1",
      (data) => norxEncrypt(key, nonce, data, aad),
      (data) => norxDecrypt(key, nonce, data, aad),
    ),
    xoodyak: sealed(
      "Xoodyak",
      (data) => xoodyakEncrypt(key, nonce, data, aad),
      (data) => xoodyakDecrypt(key, nonce, data, aad),
    ),
    /**
     * MORUS reads the resolved instance, never the key length: 640-128 and 1280-128 share every length
     * and are different ciphers.
     */
    morus: (() => {
      const v = withInstance<MorusVariant>("1280-256");
      return sealed(
        `MORUS-${v}`,
        (data) => {
          const { ciphertext, tag } = morusSeal(v, key, nonce, aad, data);
          const out = new Uint8Array(ciphertext.length + tag.length);
          out.set(ciphertext);
          out.set(tag, ciphertext.length);
          return out;
        },
        (data) => {
          if (data.length < MORUS_TAG_LEN) return null;
          const split = data.length - MORUS_TAG_LEN;
          return morusOpen(v, key, nonce, aad, data.subarray(0, split), data.subarray(split));
        },
      );
    })(),

    /**
     * Ketje Jr returns its tag separately rather than appended, so the two halves are joined here.
     * `sealed` expects seal to produce ciphertext-plus-tag and open to take the same.
     */
    ketjejr: sealed(
      "Ketje Jr",
      (data) => {
        const { ciphertext, tag } = ketjeJrSeal(key, nonce, aad, data);
        const out = new Uint8Array(ciphertext.length + tag.length);
        out.set(ciphertext);
        out.set(tag, ciphertext.length);
        return out;
      },
      (data) => {
        if (data.length < KETJE_JR_TAG_LEN) return null;
        const split = data.length - KETJE_JR_TAG_LEN;
        return ketjeJrOpen(key, nonce, aad, data.subarray(0, split), data.subarray(split));
      },
    ),
    schwaemm: (() => {
      const v = withInstance<SchwaemmVariant>("256-128");
      return sealed(
        `Schwaemm${v}`,
        (data) => schwaemmEncrypt(v, key, nonce, data, aad),
        (data) => schwaemmDecrypt(v, key, nonce, data, aad),
      );
    })(),
    giftcofb: sealed(
      "GIFT-COFB",
      (data) => giftCofbEncrypt(key, nonce, data, aad),
      (data) => giftCofbDecrypt(key, nonce, data, aad),
    ),
    photonbeetle: (() => {
      // The instance ids are the rate in bits; the implementation takes it in bytes.
      const rate: PhotonBeetleRate = instanceId === "32" ? 4 : 16;
      return sealed(
        `PHOTON-Beetle-AEAD[${rate * 8}]`,
        (data) => photonBeetleEncrypt(rate, key, nonce, data, aad),
        (data) => photonBeetleDecrypt(rate, key, nonce, data, aad),
      );
    })(),
    romulus: (() => {
      const mode = withInstance<RomulusMode>("n");
      return sealed(
        `Romulus-${mode.toUpperCase()}`,
        (data) => romulusEncrypt(mode, key, nonce, data, aad),
        (data) => romulusDecrypt(mode, key, nonce, data, aad),
      );
    })(),
    elephant: (() => {
      const v = withInstance<ElephantVariant>("dumbo");
      return sealed(
        v,
        (data) => elephantEncrypt(v, key, nonce, data, aad),
        (data) => elephantDecrypt(v, key, nonce, data, aad),
      );
    })(),
    isap: (() => {
      const v = withInstance<IsapVariant>("a-128a");
      return sealed(
        `ISAP-${v}`,
        (data) => isapEncrypt(v, key, nonce, data, aad),
        (data) => isapDecrypt(v, key, nonce, data, aad),
      );
    })(),
    grain128aead: sealed(
      "Grain-128AEAD",
      (data) => grain128AeadEncrypt(key, nonce, data, aad),
      (data) => grain128AeadDecrypt(key, nonce, data, aad),
    ),
    tinyjambu: (() => {
      const bits = (
        instanceId === "192" ? 192 : instanceId === "256" ? 256 : 128
      ) as TinyJambuKeyBits;
      return sealed(
        `TinyJAMBU-${bits}`,
        (data) => tinyJambuEncrypt(bits, key, nonce, data, aad),
        (data) => tinyJambuDecrypt(bits, key, nonce, data, aad),
      );
    })(),
  };
  const operation = constructions[toolId];
  if (!operation) throw new Error(`No lightweight AEAD implementation for "${toolId}".`);
  return operation;
}

export function rc4Operation(key: Uint8Array, drop: number): CipherOperation {
  // A fresh engine per call: RC4's state advances with the keystream, so reusing one across
  // both directions would produce a different keystream the second time.
  const run = (data: Uint8Array) => rc4(key, data, drop);
  return { encrypt: run, decrypt: run };
}
