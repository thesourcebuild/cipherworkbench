/**
 * Zod-free constants and accessors for the cipher family.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { optEnumOr, optNumber, optString, setOption } from "@ocs/contracts/pure";
import type { PaddingScheme } from "@ocs/algos";

export const SPEC_VERSION = 1;

export const OPTION_DIRECTION = "direction";
export const OPTION_MODE = "mode";
/**
 * Which parameter set a parameterised cipher is using. Simon and Speck only.
 *
 * Named `paramSet` to match the post-quantum family, and deliberately *not* `variant`: that word is
 * already taken by `CipherSpec.variant`, which holds the tool id.
 */
export const OPTION_PARAM_SET = "paramSet";
export const OPTION_KEY = "key";
export const OPTION_NONCE = "nonce";
export const OPTION_AAD = "aad";
export const OPTION_COUNTER = "counter";
export const OPTION_DROP = "drop";
export const OPTION_EFFECTIVE_KEY_BITS = "effectiveKeyBits";
/** RC5 only: the round count, which is part of the algorithm's name rather than a preference. */
export const OPTION_RC5_ROUNDS = "rc5Rounds";
/** Threefish only: its third input, which is neither a key nor an IV. */
export const OPTION_TWEAK = "tweak";
/** GOST 28147-89 only: which published S-box set, which is a parameter of the cipher. */
export const OPTION_GOST_SBOX = "gostSbox";
export const OPTION_ANUBIS_VARIANT = "anubisVariant";
export const OPTION_TAG_LEN = "tagLen";

/** `availableOn` tags. */
export const TAG_AEAD = "aead";
export const TAG_NONCE = "nonce";
/**
 * Emitted while the IV is the user's to supply -- that is, unless a KDF is deriving it alongside the
 * key. The nonce field of a tool with no modes is gated on it; a tool with modes uses `iv:<mode>`,
 * which carries the same condition *and* the mode. See `nonceOption`.
 */
export const TAG_IV_MANUAL = "iv:manual";

export const TAG_RC4 = "rc4";
export const TAG_CHACHA_COUNTER = "counter";

/**
 * Encrypt or decrypt, held as an option rather than as a first-class UI control.
 *
 * The KDF family already models its derive/verify switch this way, and doing the same here
 * keeps the workbench entirely generic — one options form and one result panel still serve
 * every family, which is the property the whole architecture rests on.
 */
export type CipherDirection = "encrypt" | "decrypt";

export function readDirection(options: OptionValues): CipherDirection {
  return optString(options, OPTION_DIRECTION) === "decrypt" ? "decrypt" : "encrypt";
}

export function withDirection(options: OptionValues, direction: CipherDirection): OptionValues {
  return setOption(options, OPTION_DIRECTION, direction);
}

export function readParamSet(options: OptionValues): string | undefined {
  return optString(options, OPTION_PARAM_SET);
}

export function withParamSet(options: OptionValues, id: string): OptionValues {
  return setOption(options, OPTION_PARAM_SET, id);
}

export function readMode(options: OptionValues, fallback: string): string {
  return optString(options, OPTION_MODE) ?? fallback;
}

export function withMode(options: OptionValues, mode: string): OptionValues {
  return setOption(options, OPTION_MODE, mode);
}

/** ChaCha20's initial block counter. RFC 8439's vectors use 0 and 1. */
export function readCounter(options: OptionValues): number {
  const raw = optNumber(options, OPTION_COUNTER);
  if (raw === undefined || !Number.isInteger(raw) || raw < 0) return 0;
  return raw;
}

/** RC4-drop: bytes of keystream to discard before use. */
export function readDrop(options: OptionValues): number {
  const raw = optNumber(options, OPTION_DROP);
  if (raw === undefined || !Number.isInteger(raw) || raw < 0) return 0;
  return Math.min(raw, 65536);
}

/**
 * AEGIS's tag length in bytes. 16 or 32, and 16 unless the spec's other option was chosen.
 *
 * A number rather than a boolean because the draft may yet gain a third length, and because "16" and
 * "32" are what the reader will compare against a wire format. Anything unrecognised falls back to 16,
 * which is the interoperable choice -- a share link naming 24 should not produce a tag nothing accepts.
 */
/**
 * The tag length a construction uses when nothing has chosen one: 128 bits.
 *
 * Named rather than left as a literal because `createSpec` seeds the control with it, and the two
 * must not be able to disagree -- a form showing 16 while compute used something else is precisely
 * the class of bug this option has already had once.
 */
export const DEFAULT_TAG_LEN = 16;

export function readTagLen(options: OptionValues): number {
  const raw = tagLenValue(options);
  return raw === 32 ? 32 : DEFAULT_TAG_LEN;
}

/**
 * The stored tag length, whichever shape it arrives in.
 *
 * `OPTION_TAG_LEN` is an `enum` control, so the form stores `"32"` and not `32` -- and `optNumber`
 * returns `undefined` for a string. That made AEGIS's 256-bit tag choice a no-op in the app while
 * every test passed, because the tests wrote the option as a number, which is a shape the form never
 * produces. Both are accepted here, and a test now drives it the way the UI does.
 */
function tagLenValue(options: OptionValues): number | undefined {
  const numeric = optNumber(options, OPTION_TAG_LEN);
  if (numeric !== undefined) return numeric;
  const text = optString(options, OPTION_TAG_LEN);
  if (text === undefined) return undefined;
  const parsed = Number(text);
  return Number.isInteger(parsed) ? parsed : undefined;
}

/**
 * Tag length constrained to a mode's own list.
 *
 * Separate from `readTagLen` because AEGIS offers 16 or 32 while CCM and OCB offer the even values from
 * 4 to 16 -- and a share link naming a length the mode does not allow should fall back to the default
 * rather than producing a tag nothing can verify.
 */
export function readTagLenFrom(
  options: OptionValues,
  allowed: readonly number[],
  fallback: number,
): number {
  const raw = tagLenValue(options);
  return raw !== undefined && allowed.includes(raw) ? raw : fallback;
}

/** AES accepts exactly these three key sizes; everything else here wants 32 bytes. */
export const AES_KEY_SIZES = [16, 24, 32] as const;

export const OPTION_KEY_SIZE = "keySize";

export const OPTION_PADDING = "padding";

/** PKCS#7, which is what every implementation interoperates on and what noble applies by default. */
export const DEFAULT_PADDING = "pkcs7";

/**
 * The selected padding scheme, or PKCS#7.
 *
 * Read as a *string*, because an `enum` option's value is one -- reading it with `optNumber` is how
 * AEGIS's tag length came to be inert in the app with a green suite. The fallback matters as much as
 * the parse: it is the same value `createSpec` seeds, so a spec arriving without the option (an older
 * share link, a saved state from before the control existed) computes exactly as it did.
 */
export function readPadding(options: OptionValues): PaddingScheme {
  const raw = options[OPTION_PADDING];
  return typeof raw === "string" && PADDING_SCHEMES.includes(raw as PaddingScheme)
    ? (raw as PaddingScheme)
    : DEFAULT_PADDING;
}

/**
 * The schemes offered, in the order the control lists them.
 *
 * Duplicated from `PaddingScheme` in `@ocs/algos` because a `type` has no runtime form to validate
 * against, and `tests/cipher.test.ts` asserts the two agree -- the same arrangement the hash family's
 * `outputLen` has. The order matches the one CryptoJS and the tools modelled on it use, so a
 * reader comparing two screens is comparing the same list in the same sequence.
 */
export const PADDING_SCHEMES: readonly PaddingScheme[] = [
  "pkcs7",
  "pkcs5",
  "iso7816",
  "x923",
  "iso10126",
  "zero",
  "none",
];

/**
 * AES's key size as a declared choice rather than something inferred from what was typed.
 *
 * The default is 256, which is what Generate produced before this control existed -- so the tool opens
 * on the same behaviour it had, and the control changes what is *offered* rather than what a fresh
 * spec computes.
 */
export const DEFAULT_AES_KEY_SIZE = 256;

/**
 * The selected key size in *bytes*, or the default.
 *
 * Stored in bits because that is how the sizes are named -- nobody asks for "AES-32" -- and read in
 * bytes because that is what every length check downstream is in. Doing the conversion in one place is
 * the point: an `enum` value is a string, so a caller reading this with `optNumber` would get
 * `undefined` and fall silently back to a default, which is the exact shape of the bug that left
 * AEGIS's tag-length control inert with a green suite.
 */
export function readAesKeySizeBytes(options: OptionValues): number {
  const raw = options[OPTION_KEY_SIZE];
  const bits =
    typeof raw === "string" ? Number(raw) : typeof raw === "number" ? raw : Number.NaN;
  const bytes = Number.isFinite(bits) ? bits / 8 : Number.NaN;
  return AES_KEY_STRING_SIZES.includes(bytes) ? bytes : DEFAULT_AES_KEY_SIZE / 8;
}

/**
 * Every key-string length any AES mode accepts, in bytes: AES's own three plus the ones the splitting
 * modes add -- 48 from AES-SIV and 64 from both XTS and SIV.
 *
 * Duplicated from `AES_MODES` deliberately, because `pure.ts` sits below the catalogue and importing
 * `tool-meta` here would be a cycle. `tests/cipher.test.ts` asserts the two agree, which is the
 * arrangement the hash family's `outputLen` already uses: a stale number here means a legal key size
 * silently falls back to the default rather than being read, and nothing else would say so.
 */
export const AES_KEY_STRING_SIZES: readonly number[] = [16, 24, 32, 48, 64];
export const CHACHA_KEY_SIZE = 32;

/** AES's block size, which is what makes CBC and ECB need padding. */
export const AES_BLOCK_SIZE = 16;

/** Re-exported under a distinct name so `resolve.ts` does not import from the catalogue for one string. */
export const DEFAULT_AES_MODE_FALLBACK = "gcm";

/**
 * RC2's effective key length in bits, which is a parameter of the cipher and not of the key.
 *
 * Defaults to the key length in bits, which is what OpenSSL does -- so someone comparing output with
 * `openssl rc2-cbc` gets a match without touching this. A share link naming something outside 1..1024
 * falls back to that default rather than reaching the implementation, which would refuse it.
 */
/**
 * RC5's round count. Clamped rather than refused, and defaulted to 12.
 *
 * Twelve is the number in "RC5-32/12/16" and what the deployments used, so it is what someone
 * comparing a value against an old file needs first. Sixteen is what the designers recommended after
 * the differential attack, and the control says so.
 */
export function readRc5Rounds(options: OptionValues): number {
  const raw = optNumber(options, OPTION_RC5_ROUNDS);
  if (raw !== undefined && Number.isInteger(raw) && raw >= 0 && raw <= 255) return raw;
  return 12;
}

/** The S-box set. `test` is the default because it is the one every published vector uses. */
export function readGostSbox(options: OptionValues): "test" | "crypto" {
  return optEnumOr(options, OPTION_GOST_SBOX, ["test", "crypto"] as const, "test");
}

/**
 * Which Anubis the tool runs.
 *
 * `tweaked` is the default because it is NESSIE's final version -- and because it is the one whose
 * S-box is Khazad's, so it is the half already pinned by that cipher's published vectors.
 */
export function readAnubisVariant(options: OptionValues): "original" | "tweaked" {
  return optEnumOr(options, OPTION_ANUBIS_VARIANT, ["original", "tweaked"] as const, "tweaked");
}

export function readEffectiveKeyBits(options: OptionValues, keyBytes: number): number {
  const raw = optNumber(options, OPTION_EFFECTIVE_KEY_BITS);
  if (raw !== undefined && Number.isInteger(raw) && raw >= 1 && raw <= 1024) return raw;
  return Math.max(1, keyBytes * 8);
}
