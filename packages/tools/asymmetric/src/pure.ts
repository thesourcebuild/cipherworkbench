/**
 * Zod-free constants and accessors for the public-key family.
 *
 * On the cheap side of the manifest/definition split: nothing here imports `@noble`,
 * `@scure` or the engine's compute path, so `./manifests` stays free of them too.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { optString, setOption } from "@ocs/contracts/pure";
import {
  DEFAULT_ECDH_CURVE,
  DEFAULT_ECDSA_CURVE,
  DEFAULT_PARAM_SETS,
  DEFAULT_RSA_HASH,
  DEFAULT_RSA_MODULUS,
  type AsymmetricOperation,
} from "./catalogue/tool-meta";

export const SPEC_VERSION = 1;

export const OPTION_OPERATION = "operation";
export const OPTION_CURVE = "curve";
export const OPTION_HASH = "hash";
export const OPTION_SCHEME = "scheme";
export const OPTION_MODULUS_LENGTH = "modulusLength";
export const OPTION_PRIVATE_KEY = "privateKey";
export const OPTION_PUBLIC_KEY = "publicKey";
export const OPTION_SIGNATURE = "signature";
export const OPTION_SIGNATURE_FORMAT = "signatureFormat";
export const OPTION_OAEP_LABEL = "oaepLabel";
export const OPTION_PARAM_SET = "paramSet";

/**
 * `availableOn` tags are the operations themselves.
 *
 * Every other family tags options by algorithm variant — AES's mode, ChaCha's counter. Here
 * the axis that decides which fields exist is *what you are doing*: a signature field is
 * meaningless while signing and required while verifying. So `variantTag` returns the
 * operation and these constants are the tags.
 */
export const OPERATIONS: readonly AsymmetricOperation[] = [
  "generate",
  "sign",
  "verify",
  "encrypt",
  "decrypt",
  "derive",
  "encapsulate",
  "decapsulate",
];

export function readOperation(
  options: OptionValues,
  available: readonly AsymmetricOperation[],
): AsymmetricOperation {
  const raw = optString(options, OPTION_OPERATION);
  // A share link or stale saved state can name an operation this tool does not have.
  if (raw && (available as readonly string[]).includes(raw)) return raw as AsymmetricOperation;
  return available[0] ?? "generate";
}

export function withOperation(
  options: OptionValues,
  operation: AsymmetricOperation,
): OptionValues {
  return setOption(options, OPTION_OPERATION, operation);
}

export function readCurve(options: OptionValues, toolId: string): string {
  return (
    optString(options, OPTION_CURVE) ??
    (toolId === "ecdh" ? DEFAULT_ECDH_CURVE : DEFAULT_ECDSA_CURVE)
  );
}

export function withCurve(options: OptionValues, curve: string): OptionValues {
  return setOption(options, OPTION_CURVE, curve);
}

/**
 * The hash the signature scheme is parameterised with.
 *
 * Spelled the way WebCrypto spells it ("SHA-256", not "sha256") because RSA passes it
 * straight through to `SubtleCrypto`, and one spelling used everywhere beats two mapped
 * back and forth.
 */
export function readHash(options: OptionValues): string {
  return optString(options, OPTION_HASH) ?? DEFAULT_RSA_HASH;
}

export function withHash(options: OptionValues, hash: string): OptionValues {
  return setOption(options, OPTION_HASH, hash);
}

/** RSA signature padding: `pss` or `pkcs1v15`. */
export type RsaScheme = "pss" | "pkcs1v15";

export const DEFAULT_RSA_SCHEME: RsaScheme = "pss";

export function readScheme(options: OptionValues): RsaScheme {
  return optString(options, OPTION_SCHEME) === "pkcs1v15" ? "pkcs1v15" : "pss";
}

export function withScheme(options: OptionValues, scheme: RsaScheme): OptionValues {
  return setOption(options, OPTION_SCHEME, scheme);
}

/**
 * Read as a string and parsed, because it is an `enum` option rather than a `number` one.
 *
 * Only three sizes are offered and the choice between them is not a free numeric input --
 * a select is the honest control, and enum values are strings. Storing "2048" and parsing it
 * here is the cost of that; reading it with `optNumber` would silently always fall back to the
 * default, which is exactly the bug this note exists to have prevented.
 */
export function readModulusLength(options: OptionValues): number {
  const raw = optString(options, OPTION_MODULUS_LENGTH);
  if (raw === undefined) return DEFAULT_RSA_MODULUS;
  const parsed = Number.parseInt(raw, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : DEFAULT_RSA_MODULUS;
}

/** ECDSA signature spelling: 64-byte `r || s`, or the ASN.1 sequence OpenSSL emits. */
export type SignatureFormat = "compact" | "der";

export const DEFAULT_SIGNATURE_FORMAT: SignatureFormat = "compact";

export function readSignatureFormat(options: OptionValues): SignatureFormat {
  return optString(options, OPTION_SIGNATURE_FORMAT) === "der" ? "der" : "compact";
}

export function withSignatureFormat(
  options: OptionValues,
  format: SignatureFormat,
): OptionValues {
  return setOption(options, OPTION_SIGNATURE_FORMAT, format);
}

/**
 * Largest plaintext RSA-OAEP can carry: k − 2·hLen − 2, where k is the modulus in bytes.
 *
 * Exported because the error message for exceeding it is the one thing that makes RSA
 * encryption comprehensible — that the limit exists at all is the reason nobody encrypts
 * messages with RSA directly.
 */
export function maxOaepPlaintext(modulusBytes: number, hashOutputLen: number): number {
  return modulusBytes - 2 * hashOutputLen - 2;
}

/**
 * The post-quantum parameter set, by id.
 *
 * A string rather than a number, unlike `readModulusLength`, because SLH-DSA's sets are named
 * `sha2-128s` and not sized -- two independent choices (hash family, and small-signature versus
 * fast-signing) rather than one dimension. The default per tool lives with the metadata.
 */
export function readParamSet(options: OptionValues, toolId: string): string {
  return optString(options, OPTION_PARAM_SET) ?? DEFAULT_PARAM_SETS[toolId] ?? "";
}

export function withParamSet(options: OptionValues, id: string): OptionValues {
  return setOption(options, OPTION_PARAM_SET, id);
}
