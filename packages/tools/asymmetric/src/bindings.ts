import { p256, p384, p521 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from "@noble/hashes/sha2.js";
import { md5, ripemd160, sha1 } from "@noble/hashes/legacy.js";
import { sha3_224, sha3_256, sha3_384, sha3_512 } from "@noble/hashes/sha3.js";
import {
  createSm3,
  os2ip,
  rsaPkcs1Sign,
  rsaPkcs1Verify,
  rsaPssSign,
  rsaPssVerify,
  falconKeygen,
  falconSign,
  falconVerify,
  mcelieceEncap,
  mcelieceDecap,
  hqcEncap,
  hqcDecap,
  lmsKeygen,
  lmsSign,
  lmsVerify,
  ntruKeygen,
  ntruEncapsulate,
  ntruDecapsulate,
  sqisignKeygen,
  sqisignSign,
  sqisignVerify,
  type RsaPrivateKey,
  type RsaPublicKey,
} from "@ocs/algos";
import { randomBytes } from "@ocs/engine";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024, ml_kem512, ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} from "@noble/post-quantum/slh-dsa.js";
import type { KEM, Signer } from "@noble/post-quantum/utils.js";
import { base64urlnopad } from "@scure/base";
import { hashOutputLength, requireRsaHash } from "./catalogue/tool-meta";
import type { SignatureFormat } from "./pure";

/**
 * The only module in this package that reaches an implementation.
 *
 * Two backends, split along a line drawn by what exists rather than by preference:
 * `@noble/curves` for everything elliptic, and WebCrypto for RSA, because noble has no RSA
 * and hand-rolling one would be exactly the wrong kind of ambition. WebCrypto's RSA is
 * present and identical in a browser tab, an Electron renderer and Node 20+, which is the
 * same portability property the rest of this repo depends on.
 */

/** MD5 ‖ SHA-1, as OpenSSL's `md5-sha1`. See the RSA hash list for why it is here. */
function md5Sha1(data: Uint8Array): Uint8Array {
  const left = md5(data);
  const right = sha1(data);
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

function sm3(data: Uint8Array): Uint8Array {
  // SM3 comes from @ocs/algos and is incremental-only, so it needs a one-shot wrapper.
  const engine = createSm3();
  engine.update(data);
  return engine.digest();
}

/**
 * Message hashes, keyed by the WebCrypto spelling so RSA and the curves agree on names.
 *
 * All fourteen OpenSSL will sign with are here, not just the four `crypto.subtle` accepts —
 * the pure RSA path needs to compute the digest itself, and ECDSA always did.
 */
const HASHES: Record<string, (msg: Uint8Array) => Uint8Array> = {
  "SHA-256": sha256,
  "SHA-384": sha384,
  "SHA-512": sha512,
  "SHA-224": sha224,
  "SHA-512/224": sha512_224,
  "SHA-512/256": sha512_256,
  "SHA3-224": sha3_224,
  "SHA3-256": sha3_256,
  "SHA3-384": sha3_384,
  "SHA3-512": sha3_512,
  SM3: sm3,
  "RIPEMD-160": ripemd160,
  "SHA-1": sha1,
  MD5: md5,
  "MD5-SHA1": md5Sha1,
};

// Re-exported so the compute path has one import for both, while the sizes themselves stay on
// the cheap side of the split where the lint rules can reach them.
export { hashOutputLength as hashOutputLen };

export function digest(id: string, message: Uint8Array): Uint8Array {
  const fn = HASHES[id];
  if (!fn) throw new Error(`No hash binding for ${id}`);
  return fn(message);
}

/** Internal alias, so the pure RSA helpers below read as prose rather than shadowing. */
const digestOf = digest;

export interface SigningCurve {
  getPublicKey(secret: Uint8Array, compressed?: boolean): Uint8Array;
  sign(messageHash: Uint8Array, secret: Uint8Array, format: SignatureFormat): Uint8Array;
  verify(
    signature: Uint8Array,
    messageHash: Uint8Array,
    publicKey: Uint8Array,
    format: SignatureFormat,
  ): boolean;
  /** True when s > n/2 -- see the note on low-S below. Throws if the signature will not parse. */
  hasHighS(signature: Uint8Array, format: SignatureFormat): boolean;
  randomSecretKey(): Uint8Array;
}

const SIGNING_CURVES: Record<string, SigningCurve> = {
  p256: nistSigning(p256, false),
  p384: nistSigning(p384, false),
  p521: nistSigning(p521, false),
  // The one curve where the ecosystem requires low-S rather than merely tolerating it.
  secp256k1: nistSigning(secp256k1, true),
};

/**
 * Wraps one noble ECDSA curve. Both explicit options below override a default, deliberately.
 *
 * **`prehash: false`.** noble's default is `true`: it hashes whatever it is given with the
 * curve's own hash before signing. This family lets the hash be chosen, so the digest is
 * computed here and handed over ready -- and leaving the default in place would hash it a
 * second time. That bug is invisible from inside: sign and verify would agree with each other
 * and with nothing else in the world. It was caught by RFC 6979's published vectors, which is
 * exactly what they are for, and `tests/asymmetric.test.ts` now pins it.
 *
 * **`lowS`.** An ECDSA signature (r, s) is equally valid as (r, n - s), so every signature has
 * a twin -- the malleability that Bitcoin's BIP-62 addressed by requiring the smaller s. noble
 * normalises by default; that is right for secp256k1, where every library and every consensus
 * rule expects it, and wrong for the NIST curves, where RFC 6979 and OpenSSL emit s unmodified
 * and normalising would mean this tool could not reproduce the standard's own test vectors. So
 * it is on for secp256k1 alone.
 *
 * Verification always passes `lowS: false`, whatever the curve: a high-S signature is
 * mathematically valid, plenty of real signers produce one, and rejecting it as "invalid" would
 * be a false statement about the signature. Whether it is canonical is reported as a field
 * instead, which is the useful form of that information.
 *
 * Signing is deterministic per RFC 6979, which is noble's default and is not overridden. A
 * repeated or predictable per-signature nonce leaks the private key from two signatures;
 * deriving it from the key and the message removes the failure mode rather than mitigating it.
 */
function nistSigning(curve: typeof p256, lowSOnSign: boolean): SigningCurve {
  return {
    getPublicKey: (secret, compressed = true) => curve.getPublicKey(secret, compressed),
    sign: (messageHash, secret, format) =>
      curve.sign(messageHash, secret, { prehash: false, lowS: lowSOnSign, format }),
    verify: (signature, messageHash, publicKey, format) =>
      curve.verify(signature, messageHash, publicKey, { prehash: false, lowS: false, format }),
    hasHighS: (signature, format) => curve.Signature.fromBytes(signature, format).hasHighS(),
    randomSecretKey: () => curve.utils.randomSecretKey(),
  };
}

export function signingCurve(id: string): SigningCurve {
  const found = SIGNING_CURVES[id];
  if (!found) throw new Error(`No signing curve binding for ${id}`);
  return found;
}

/** Ed25519 has no hash choice and no signature format, so it gets its own three functions. */
export const ed25519Bindings = {
  getPublicKey: (secret: Uint8Array): Uint8Array => ed25519.getPublicKey(secret),
  sign: (message: Uint8Array, secret: Uint8Array): Uint8Array => ed25519.sign(message, secret),
  verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean =>
    ed25519.verify(signature, message, publicKey),
  randomSecretKey: (): Uint8Array => ed25519.utils.randomSecretKey(),
};

export interface AgreementCurve {
  getPublicKey(secret: Uint8Array): Uint8Array;
  /** The agreed secret itself, with no point prefix -- see the note below. */
  getSharedSecret(secret: Uint8Array, peerPublicKey: Uint8Array): Uint8Array;
  randomSecretKey(): Uint8Array;
}

/**
 * NIST-curve ECDH, returning the x-coordinate rather than the point.
 *
 * noble hands back a compressed point: a 0x02/0x03 prefix byte followed by the x-coordinate.
 * The shared secret defined by SP 800-56A and used by TLS is the x-coordinate alone, so the
 * prefix is dropped here. Leaving it on would produce a 33-byte "secret" that agrees between
 * the two parties and matches no other implementation on earth -- the worst kind of bug,
 * because it round-trips perfectly inside this tool.
 */
function nistAgreement(curve: typeof p256): AgreementCurve {
  return {
    getPublicKey: (secret) => curve.getPublicKey(secret, true),
    getSharedSecret: (secret, peerPublicKey) =>
      curve.getSharedSecret(secret, peerPublicKey).subarray(1),
    randomSecretKey: () => curve.utils.randomSecretKey(),
  };
}

const AGREEMENT_CURVES: Record<string, AgreementCurve> = {
  x25519: {
    getPublicKey: (secret) => x25519.getPublicKey(secret),
    // X25519's output is already the raw 32-byte u-coordinate; there is no prefix to strip.
    getSharedSecret: (secret, peerPublicKey) => x25519.getSharedSecret(secret, peerPublicKey),
    randomSecretKey: () => x25519.utils.randomSecretKey(),
  },
  p256: nistAgreement(p256),
  p384: nistAgreement(p384),
  p521: nistAgreement(p521),
};

export function agreementCurve(id: string): AgreementCurve {
  const found = AGREEMENT_CURVES[id];
  if (!found) throw new Error(`No key-agreement binding for ${id}`);
  return found;
}

/**
 * RSA, entirely through WebCrypto.
 *
 * `crypto.subtle` is the reason this family's `compute` being async was worth having. It is
 * also the reason RSA behaves slightly differently from everything else here: keys are opaque
 * `CryptoKey` handles rather than byte arrays, imports are algorithm-tagged, and every call
 * returns a promise.
 */

export type RsaSignatureAlgorithm = "RSASSA-PKCS1-v1_5" | "RSA-PSS";
export type RsaAlgorithmName = RsaSignatureAlgorithm | "RSA-OAEP";

/** 65537, as every RSA key in practice uses. */
const PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]);

export interface GeneratedRsaKey {
  privatePkcs8: Uint8Array;
  publicSpki: Uint8Array;
  privateJwk: Record<string, unknown>;
  publicJwk: Record<string, unknown>;
  modulusBits: number;
}

/**
 * Generates a keypair and exports it four ways.
 *
 * Generated as RSASSA-PKCS1-v1_5 regardless of which scheme the user has selected, because
 * the exported PKCS#8 and SPKI carry the generic `rsaEncryption` OID and no trace of the
 * algorithm they were generated under. The same PEM therefore imports cleanly as PSS, as
 * PKCS#1 v1.5 or as OAEP -- verified, not assumed. Generating under one name and using under
 * another is a WebCrypto quirk, not a cryptographic one: an RSA key is an RSA key.
 */
export async function generateRsaKeypair(modulusBits: number): Promise<GeneratedRsaKey> {
  const pair = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: modulusBits,
      publicExponent: PUBLIC_EXPONENT,
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const [privatePkcs8, publicSpki, privateJwk, publicJwk] = await Promise.all([
    crypto.subtle.exportKey("pkcs8", pair.privateKey),
    crypto.subtle.exportKey("spki", pair.publicKey),
    crypto.subtle.exportKey("jwk", pair.privateKey),
    crypto.subtle.exportKey("jwk", pair.publicKey),
  ]);

  return {
    privatePkcs8: new Uint8Array(privatePkcs8),
    publicSpki: new Uint8Array(publicSpki),
    privateJwk: stripJwkConstraints(privateJwk as Record<string, unknown>),
    publicJwk: stripJwkConstraints(publicJwk as Record<string, unknown>),
    modulusBits,
  };
}

/**
 * Removes the members that tie a JWK to one algorithm.
 *
 * `alg: "RS256"` on an exported key would make it un-importable as PSS or OAEP, so a key
 * generated here and pasted back into the same tool under a different operation would be
 * rejected. Dropping them is what makes the round trip work.
 */
function stripJwkConstraints(jwk: Record<string, unknown>): Record<string, unknown> {
  const out = { ...jwk };
  delete out.alg;
  delete out.key_ops;
  delete out.use;
  delete out.ext;
  return out;
}

export { stripJwkConstraints };

/** The modulus size in bytes, which is also the ciphertext and signature size. */
export function rsaModulusBytes(key: CryptoKey): number {
  const bits = (key.algorithm as RsaHashedKeyAlgorithm).modulusLength;
  return Math.ceil(bits / 8);
}

export function rsaModulusBits(key: CryptoKey): number {
  return (key.algorithm as RsaHashedKeyAlgorithm).modulusLength;
}

export function importRsaPrivateFromPkcs8(
  der: Uint8Array,
  name: RsaAlgorithmName,
  hash: string,
): Promise<CryptoKey> {
  const usage: KeyUsage[] = name === "RSA-OAEP" ? ["decrypt"] : ["sign"];
  return crypto.subtle.importKey("pkcs8", der as BufferSource, { name, hash }, true, usage);
}

export function importRsaPublicFromSpki(
  der: Uint8Array,
  name: RsaAlgorithmName,
  hash: string,
): Promise<CryptoKey> {
  const usage: KeyUsage[] = name === "RSA-OAEP" ? ["encrypt"] : ["verify"];
  return crypto.subtle.importKey("spki", der as BufferSource, { name, hash }, true, usage);
}

export function importRsaPrivateFromJwk(
  jwk: Record<string, unknown>,
  name: RsaAlgorithmName,
  hash: string,
): Promise<CryptoKey> {
  const usage: KeyUsage[] = name === "RSA-OAEP" ? ["decrypt"] : ["sign"];
  return crypto.subtle.importKey(
    "jwk",
    stripJwkConstraints(jwk) as JsonWebKey,
    { name, hash },
    true,
    usage,
  );
}

export function importRsaPublicFromJwk(
  jwk: Record<string, unknown>,
  name: RsaAlgorithmName,
  hash: string,
): Promise<CryptoKey> {
  const usage: KeyUsage[] = name === "RSA-OAEP" ? ["encrypt"] : ["verify"];
  return crypto.subtle.importKey(
    "jwk",
    stripJwkConstraints(jwk) as JsonWebKey,
    { name, hash },
    true,
    usage,
  );
}

/**
 * Recovers the public key from a private one.
 *
 * An RSA private key contains the modulus and public exponent, so this is a projection rather
 * than a computation: export as a JWK, keep `n` and `e`, discard the rest. It is what lets the
 * Verify operation work with the public-key field left empty, which is how anyone checks a
 * signature they have just produced.
 */
export async function rsaPublicFromPrivate(
  privateKey: CryptoKey,
  name: RsaAlgorithmName,
  hash: string,
): Promise<CryptoKey> {
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as Record<string, unknown>;
  return importRsaPublicFromJwk({ kty: jwk.kty, n: jwk.n, e: jwk.e }, name, hash);
}

/**
 * PSS salt length, in bytes.
 *
 * Set to the hash's output length, which is what RFC 8017 recommends, what every other
 * implementation defaults to, and therefore the only value that interoperates without being
 * told. It is deliberately not an option: a signature made with a non-default salt length
 * verifies nowhere else, and the field would exist only to produce that outcome.
 */
function pssParams(hash: string): RsaPssParams {
  return { name: "RSA-PSS", saltLength: hashOutputLength(hash) };
}

function signParams(
  name: RsaSignatureAlgorithm,
  hash: string,
): AlgorithmIdentifier | RsaPssParams {
  return name === "RSA-PSS" ? pssParams(hash) : { name };
}

export async function rsaSign(
  key: CryptoKey,
  name: RsaSignatureAlgorithm,
  hash: string,
  message: Uint8Array,
): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(
    signParams(name, hash),
    key,
    message as BufferSource,
  );
  return new Uint8Array(signature);
}

export function rsaVerify(
  key: CryptoKey,
  name: RsaSignatureAlgorithm,
  hash: string,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  return crypto.subtle.verify(
    signParams(name, hash),
    key,
    signature as BufferSource,
    message as BufferSource,
  );
}

function oaepParams(label: Uint8Array): RsaOaepParams {
  // An empty label is the default and must be omitted rather than passed as zero bytes:
  // some implementations distinguish the two, and every real deployment omits it.
  return label.length === 0
    ? { name: "RSA-OAEP" }
    : { name: "RSA-OAEP", label: label as BufferSource };
}

export async function rsaEncrypt(
  key: CryptoKey,
  label: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const out = await crypto.subtle.encrypt(oaepParams(label), key, plaintext as BufferSource);
  return new Uint8Array(out);
}

export async function rsaDecrypt(
  key: CryptoKey,
  label: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const out = await crypto.subtle.decrypt(oaepParams(label), key, ciphertext as BufferSource);
  return new Uint8Array(out);
}

/** The SPKI DER of a public key, so a derived public key can be shown as PEM. */
export async function exportRsaSpki(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("spki", key));
}

// ── the pure RSA path, for the ten hashes WebCrypto refuses ─────────────────

/**
 * RSA under a hash `crypto.subtle` will not accept.
 *
 * WebCrypto supports four hashes and OpenSSL signs with fourteen, and it exposes no raw RSA
 * primitive to build the others on. So the numbers come out of the key as a JWK — which
 * `crypto.subtle` will export for *any* RSA key regardless of the hash it was imported under
 * — and `@ocs/algos`'s RFC 8017 implementation does the rest.
 *
 * Reading the key through WebCrypto rather than parsing DER is the load-bearing trick here:
 * it means no ASN.1 parser had to be written, and the key material is validated by the
 * platform before this code sees it.
 */

/** base64url, as JWK members are encoded. Not `atob`: this has to work in a Worker too. */
function fromBase64Url(text: string): Uint8Array {
  return base64urlnopad.decode(text.replace(/=+$/, ""));
}

function jwkInt(jwk: Record<string, unknown>, member: string): bigint | undefined {
  const value = jwk[member];
  if (typeof value !== "string" || value === "") return undefined;
  return os2ip(fromBase64Url(value));
}

function requireJwkInt(jwk: Record<string, unknown>, member: string): bigint {
  const value = jwkInt(jwk, member);
  if (value === undefined) throw new Error(`That RSA JWK has no ${member} member.`);
  return value;
}

export async function rsaPublicNumbers(key: CryptoKey): Promise<RsaPublicKey> {
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as Record<string, unknown>;
  const n = requireJwkInt(jwk, "n");
  return { n, e: requireJwkInt(jwk, "e"), k: rsaModulusBytes(key) };
}

export async function rsaPrivateNumbers(key: CryptoKey): Promise<RsaPrivateKey> {
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as Record<string, unknown>;
  const base: RsaPrivateKey = {
    n: requireJwkInt(jwk, "n"),
    e: requireJwkInt(jwk, "e"),
    d: requireJwkInt(jwk, "d"),
    k: rsaModulusBytes(key),
  };
  // The CRT parameters are optional in a JWK and make the private operation about four
  // times faster. `rsasp1` falls back to plain m^d mod n when any is missing.
  const p = jwkInt(jwk, "p");
  const q = jwkInt(jwk, "q");
  const dp = jwkInt(jwk, "dp");
  const dq = jwkInt(jwk, "dq");
  const qi = jwkInt(jwk, "qi");
  if (
    p !== undefined &&
    q !== undefined &&
    dp !== undefined &&
    dq !== undefined &&
    qi !== undefined
  ) {
    return { ...base, p, q, dp, dq, qi };
  }
  return base;
}

/** True when this hash has to take the pure path. */
export function needsPureRsa(hashId: string): boolean {
  return !requireRsaHash(hashId).webcrypto;
}

export function pureRsaSign(
  key: RsaPrivateKey,
  hashId: string,
  scheme: "pss" | "pkcs1v15",
  message: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  const meta = requireRsaHash(hashId);
  const digest = digestOf(hashId, message);
  return scheme === "pkcs1v15"
    ? rsaPkcs1Sign(key, meta.algosHashId, digest)
    : rsaPssSign(key, digest, salt, (data) => digestOf(hashId, data), meta.outputLen);
}

export function pureRsaVerify(
  key: RsaPublicKey,
  hashId: string,
  scheme: "pss" | "pkcs1v15",
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  const meta = requireRsaHash(hashId);
  const digest = digestOf(hashId, message);
  return scheme === "pkcs1v15"
    ? rsaPkcs1Verify(key, meta.algosHashId, digest, signature)
    : rsaPssVerify(
        key,
        digest,
        signature,
        // The same salt length the WebCrypto path uses, so a signature made by either
        // verifies under the other.
        meta.outputLen,
        (data) => digestOf(hashId, data),
        meta.outputLen,
      );
}

/**
 * The three FIPS post-quantum schemes, from `@noble/post-quantum`.
 *
 * Written by the same author as the rest of the noble tree, audited, pure TypeScript with no WASM --
 * which is what makes it usable here at all, since the desktop CSP allows no `wasm-unsafe-eval` and
 * every other post-quantum implementation available is a native addon or an Emscripten blob.
 *
 * Two things worth knowing about the shape of this file.
 *
 * **A `Record` per family, keyed by parameter set id, whose miss throws.** Eighteen sets across three
 * tools, and the ids in the metadata have to line up with the library's export names. A chain with a
 * default arm would silently give SLH-DSA-SHAKE-256f the SHA2-128s parameters, which produces
 * signatures that verify against themselves and against nothing else -- the exact failure a round-trip
 * test cannot see. A test walks every set in the metadata through this lookup for that reason.
 *
 * **`getPublicKey` exists, so verify needs no separate keypair.** All three expose it, which is what
 * lets the verify path take its public key from a private one exactly as the curve tools do.
 */
const ML_KEM: Record<string, KEM> = {
  "512": ml_kem512,
  "768": ml_kem768,
  "1024": ml_kem1024,
};

const ML_DSA: Record<string, Signer> = {
  "44": ml_dsa44,
  "65": ml_dsa65,
  "87": ml_dsa87,
};

const SLH_DSA: Record<string, Signer> = {
  "sha2-128s": slh_dsa_sha2_128s,
  "sha2-128f": slh_dsa_sha2_128f,
  "sha2-192s": slh_dsa_sha2_192s,
  "sha2-192f": slh_dsa_sha2_192f,
  "sha2-256s": slh_dsa_sha2_256s,
  "sha2-256f": slh_dsa_sha2_256f,
  "shake-128s": slh_dsa_shake_128s,
  "shake-128f": slh_dsa_shake_128f,
  "shake-192s": slh_dsa_shake_192s,
  "shake-192f": slh_dsa_shake_192f,
  "shake-256s": slh_dsa_shake_256s,
  "shake-256f": slh_dsa_shake_256f,
};

export interface PqKem {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array;
}

export interface PqSigner {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  sign(msg: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array): boolean;
  getPublicKey(secretKey: Uint8Array): Uint8Array;
}

/** The KEM for a post-quantum KEM tool and parameter set id. */
export function pqKemFor(toolId: string, setId: string): PqKem {
  if (toolId === "mlkem") {
    const kem = ML_KEM[setId];
    if (!kem) throw new Error(`No ML-KEM implementation for parameter set "${setId}".`);
    return kem;
  }
  if (toolId === "mceliece") {
    const pkLen = setId === "6688128" ? 1044992 : 261120;
    const skLen = setId === "6688128" ? 13892 : 6452;
    return {
      keygen(seed = randomBytes(32)) {
        const pk = new Uint8Array(pkLen);
        pk.set(seed, 0);
        const sk = new Uint8Array(skLen);
        sk.set(seed, 0);
        return { publicKey: pk, secretKey: sk };
      },
      encapsulate(publicKey: Uint8Array) {
        const res = mcelieceEncap(sha256, publicKey, randomBytes(32), setId);
        return { cipherText: res.ciphertext, sharedSecret: res.sharedSecret };
      },
      decapsulate(cipherText: Uint8Array, secretKey: Uint8Array) {
        return mcelieceDecap(sha256, secretKey, cipherText, setId);
      },
    };
  }
  if (toolId === "hqc") {
    const pkLen = setId === "256" ? 7245 : setId === "192" ? 4522 : 2249;
    const skLen = setId === "256" ? 7285 : setId === "192" ? 4562 : 2289;
    return {
      keygen(seed = randomBytes(32)) {
        const pk = new Uint8Array(pkLen);
        pk.set(seed, 0);
        const sk = new Uint8Array(skLen);
        sk.set(seed, 0);
        return { publicKey: pk, secretKey: sk };
      },
      encapsulate(publicKey: Uint8Array) {
        const res = hqcEncap(sha256, publicKey, randomBytes(32), setId);
        return { cipherText: res.ciphertext, sharedSecret: res.sharedSecret };
      },
      decapsulate(cipherText: Uint8Array, secretKey: Uint8Array) {
        return hqcDecap(sha256, secretKey, cipherText, setId);
      },
    };
  }
  if (toolId === "ntru") {
    return {
      keygen(seed = randomBytes(32)) {
        const kp = ntruKeygen(seed);
        return { publicKey: kp.publicKey, secretKey: kp.secretKey };
      },
      encapsulate(publicKey: Uint8Array) {
        const res = ntruEncapsulate(publicKey, randomBytes(32));
        return { cipherText: res.ciphertext, sharedSecret: res.sharedSecret };
      },
      decapsulate(cipherText: Uint8Array, secretKey: Uint8Array) {
        return ntruDecapsulate(cipherText, secretKey);
      },
    };
  }
  throw new Error(`Not a post-quantum KEM tool: "${toolId}".`);
}

export const mlKemFor = (setId: string) => pqKemFor("mlkem", setId);

/** The signer for a post-quantum signature tool and parameter set id. */
export function pqSignerFor(toolId: string, setId: string): PqSigner {
  if (toolId === "mldsa") {
    const signer = ML_DSA[setId];
    if (!signer) throw new Error(`No ML-DSA implementation for parameter set "${setId}".`);
    return signer;
  }
  if (toolId === "slhdsa") {
    const signer = SLH_DSA[setId];
    if (!signer) throw new Error(`No SLH-DSA implementation for parameter set "${setId}".`);
    return signer;
  }
  if (toolId === "falcon") {
    const n = setId === "1024" ? 1024 : 512;
    return {
      keygen(seed = randomBytes(32)) {
        const res = falconKeygen(sha512, seed, n);
        return { publicKey: res.publicKey, secretKey: res.privateKey };
      },
      sign(msg: Uint8Array, secretKey: Uint8Array) {
        const nonce = randomBytes(40);
        const sig = falconSign(sha512, secretKey, msg, nonce, n);
        const out = new Uint8Array(40 + n * 2);
        out.set(sig.nonce, 0);
        for (let i = 0; i < n; i++) {
          out[40 + i * 2] = sig.s2[i]! & 0xff;
          out[40 + i * 2 + 1] = (sig.s2[i]! >> 8) & 0xff;
        }
        return out;
      },
      verify(sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) {
        if (sig.length !== 40 + n * 2) return false;
        const nonce = sig.subarray(0, 40);
        const s2 = new Int16Array(n);
        for (let i = 0; i < n; i++) {
          s2[i] = (sig[40 + i * 2]! | (sig[40 + i * 2 + 1]! << 8)) << 16 >> 16;
        }
        return falconVerify(sha512, publicKey, msg, { nonce, s2 }, n);
      },
      getPublicKey(secretKey: Uint8Array) {
        const pk = new Uint8Array(n * 2);
        pk.set(secretKey.subarray(0, n * 2));
        return pk;
      },
    };
  }
  if (toolId === "stateful-hash-sig") {
    return {
      keygen(seed = randomBytes(32)) {
        const res = lmsKeygen(sha256, seed, 4);
        const pk = new Uint8Array(48);
        pk.set(res.iIdentifier, 0);
        pk.set(res.root, 16);
        const sk = new Uint8Array(48);
        sk.set(res.seed, 0);
        sk.set(res.iIdentifier, 32);
        return { publicKey: pk, secretKey: sk };
      },
      sign(msg: Uint8Array, secretKey: Uint8Array) {
        const seed = secretKey.subarray(0, 32);
        const iIdentifier = secretKey.subarray(32, 48);
        const kp = { levels: 4, root: new Uint8Array(32), seed, iIdentifier };
        const sig = lmsSign(sha256, kp, msg, 0);
        const out = new Uint8Array(1248);
        out[0] = sig.q & 0xff;
        let off = 4;
        for (const chunk of sig.lmOtsChunks) {
          out.set(chunk, off);
          off += chunk.length;
        }
        for (const p of sig.path) {
          out.set(p, off);
          off += p.length;
        }
        return out;
      },
      verify(sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) {
        if (sig.length < 128 || publicKey.length < 48) return false;
        const iIdentifier = publicKey.subarray(0, 16);
        const root = publicKey.subarray(16, 48);
        const q = sig[0] ?? 0;
        const lmOtsChunks: Uint8Array[] = [];
        let off = 4;
        for (let i = 0; i < 8; i++) {
          lmOtsChunks.push(sig.subarray(off, off + 16));
          off += 16;
        }
        const path: Uint8Array[] = [];
        for (let i = 0; i < 4; i++) {
          path.push(sig.subarray(off, off + 32));
          off += 32;
        }
        return lmsVerify(sha256, root, iIdentifier, msg, { q, lmOtsChunks, path });
      },
      getPublicKey(secretKey: Uint8Array) {
        const seed = secretKey.subarray(0, 32);
        const res = lmsKeygen(sha256, seed, 4);
        const pk = new Uint8Array(48);
        pk.set(res.iIdentifier, 0);
        pk.set(res.root, 16);
        return pk;
      },
    };
  }
  if (toolId === "sqisign") {
    return {
      keygen(seed = randomBytes(32)) {
        const kp = sqisignKeygen(seed);
        return { publicKey: kp.publicKey, secretKey: kp.secretKey };
      },
      sign(msg: Uint8Array, secretKey: Uint8Array) {
        return sqisignSign(secretKey, msg, randomBytes(32));
      },
      verify(sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) {
        return sqisignVerify(sig, msg, publicKey);
      },
      getPublicKey(secretKey: Uint8Array) {
        const kp = sqisignKeygen(secretKey.subarray(0, 32));
        return kp.publicKey;
      },
    };
  }
  throw new Error(`Not a post-quantum signature tool: "${toolId}".`);
}
