import type { SecurityPosture } from "@ocs/engine";

/**
 * The four public-key tools, as eager metadata.
 *
 * This family differs from the others in three ways that shape everything below:
 *
 *  1. **Key generation is an operation.** Every other family takes a key as input; here
 *     producing one is a first-class thing the tool does, and its output is two values
 *     rather than one.
 *  2. **There are more than two operations.** RSA does five, so the operation is an enum
 *     rather than a direction, and it is the `availableOn` axis that decides which fields
 *     appear at all.
 *  3. **Two key representations are unavoidable.** RSA keys are PEM or JWK because nobody
 *     has raw RSA bytes; curve keys are raw hex or base64 because that is what wallets,
 *     WireGuard and SSH actually store.
 */
export type AsymmetricOperation =
  | "generate"
  | "sign"
  | "verify"
  | "encrypt"
  | "decrypt"
  | "derive"
  /**
   * The two KEM operations, named after FIPS 203 rather than folded into encrypt/decrypt.
   *
   * A KEM has no plaintext: `encapsulate` takes a public key alone and returns a fresh random shared
   * secret plus a ciphertext carrying it. Calling that "encrypt" would promise a message input that
   * does not exist, and the panel would be lying about what the tool does.
   */
  | "encapsulate"
  | "decapsulate";

export interface AsymmetricToolMeta {
  id: string;
  label: string;
  category: string;
  operations: readonly AsymmetricOperation[];
  security: SecurityPosture;
  tags: readonly string[];
  summary: string;
  /** True when keys are PEM/JWK rather than raw bytes. RSA only. */
  usesPem: boolean;
}

export const ASYMMETRIC_TOOLS: readonly AsymmetricToolMeta[] = [
  {
    id: "rsa",
    label: "RSA",
    category: "RSA",
    operations: ["generate", "sign", "verify", "encrypt", "decrypt"],
    security: "modern",
    tags: ["rsa", "oaep", "pss", "pkcs1", "sign", "verify", "encrypt", "decrypt", "pem", "jwk"],
    summary:
      "The only algorithm here that both signs and encrypts. Large keys, slow operations, everywhere.",
    usesPem: true,
  },
  {
    id: "ecdsa",
    label: "ECDSA",
    category: "Elliptic curve",
    operations: ["generate", "sign", "verify"],
    security: "modern",
    tags: [
      "ecdsa",
      "p256",
      "p384",
      "p521",
      "secp256k1",
      "bitcoin",
      "ethereum",
      "sign",
      "verify",
      "rfc6979",
    ],
    summary:
      "Signatures over P-256, P-384, P-521 or secp256k1, with deterministic nonces per RFC 6979.",
    usesPem: false,
  },
  {
    id: "ed25519",
    label: "Ed25519",
    category: "Elliptic curve",
    operations: ["generate", "sign", "verify"],
    security: "modern",
    tags: ["ed25519", "eddsa", "rfc8032", "ssh", "signify", "sign", "verify"],
    summary:
      "The modern default for signatures. 32-byte keys, 64-byte signatures, no parameters to get wrong.",
    usesPem: false,
  },
  {
    id: "ecdh",
    label: "ECDH",
    category: "Key agreement",
    operations: ["generate", "derive"],
    security: "modern",
    tags: [
      "ecdh",
      "x25519",
      "p256",
      "p384",
      "p521",
      "key agreement",
      "diffie-hellman",
      "wireguard",
      "tls",
    ],
    summary:
      "Two parties derive a shared secret over X25519 or a NIST curve. Feed the result to a KDF.",
    usesPem: false,
  },
  {
    /**
     * ML-KEM, and the operation names are the point.
     *
     * A KEM does not encrypt a message. `encapsulate` takes a public key and *nothing else*, and
     * returns a random shared secret together with a ciphertext that only the matching secret key can
     * turn back into that secret. There is no plaintext anywhere in the interface -- which is why the
     * operations are named after the standard rather than mapped onto encrypt/decrypt, where users
     * would reasonably expect to supply a message and get it back.
     *
     * Unlike ECDH's output, the shared secret *is* a key: FIPS 203 specifies it as 32 uniformly random
     * bytes, already suitable for AES-256. `A009` says so, because the habit of running a DH output
     * through HKDF is right for ECDH and unnecessary here.
     */
    id: "mlkem",
    label: "ML-KEM",
    category: "Post-quantum",
    operations: ["generate", "encapsulate", "decapsulate"],
    security: "modern",
    tags: [
      "ml-kem",
      "mlkem",
      "kyber",
      "fips 203",
      "post-quantum",
      "pqc",
      "lattice",
      "kem",
      "key agreement",
      "encapsulate",
      "decapsulate",
    ],
    summary: "FIPS 203 key encapsulation. What TLS calls X25519MLKEM768. Not Kyber.",
    usesPem: false,
  },
  {
    id: "mldsa",
    label: "ML-DSA",
    category: "Post-quantum",
    operations: ["generate", "sign", "verify"],
    security: "modern",
    tags: [
      "ml-dsa",
      "mldsa",
      "dilithium",
      "fips 204",
      "post-quantum",
      "pqc",
      "lattice",
      "sign",
      "verify",
    ],
    summary: "FIPS 204 lattice signatures. The post-quantum default, at 3.3 KB a signature.",
    usesPem: false,
  },
  {
    /**
     * SLH-DSA exists so that the post-quantum answer does not rest on one mathematical assumption.
     *
     * ML-DSA and ML-KEM are both lattice schemes. SLH-DSA is hash-based -- its security reduces to the
     * hash function and nothing else -- so it is the hedge against a lattice break, which is why NIST
     * standardised both. What you pay is size and speed: kilobytes of signature and, for the `s`
     * variants, over a second to produce one.
     */
    id: "slhdsa",
    label: "SLH-DSA",
    category: "Post-quantum",
    operations: ["generate", "sign", "verify"],
    security: "modern",
    tags: [
      "slh-dsa",
      "slhdsa",
      "sphincs",
      "sphincs+",
      "fips 205",
      "post-quantum",
      "pqc",
      "hash-based",
      "stateless",
      "sign",
      "verify",
    ],
    summary: "FIPS 205 hash-based signatures. Slow and large, and not a lattice.",
    usesPem: false,
  },
  {
    id: "falcon",
    label: "Falcon",
    category: "Post-quantum",
    operations: ["generate", "sign", "verify"],
    security: "modern",
    tags: ["falcon", "pqc", "post-quantum", "ntru", "lattice", "sign", "verify"],
    summary: "NIST Round 3 PQC signature scheme based on NTRU lattices and fast Fourier sampling.",
    usesPem: false,
  },
  {
    id: "mceliece",
    label: "Classic McEliece",
    category: "Post-quantum",
    operations: ["generate", "encapsulate", "decapsulate"],
    security: "modern",
    tags: ["mceliece", "classic-mceliece", "pqc", "post-quantum", "code-based", "goppa", "kem"],
    summary: "Code-based KEM using Goppa codes, standing strong since 1978.",
    usesPem: false,
  },
  {
    id: "hqc",
    label: "HQC",
    category: "Post-quantum",
    operations: ["generate", "encapsulate", "decapsulate"],
    security: "modern",
    tags: ["hqc", "pqc", "post-quantum", "hamming", "code-based", "kem"],
    summary: "Hamming Quasi-Cyclic code-based KEM selected for NIST PQC standardization.",
    usesPem: false,
  },
  {
    id: "stateful-hash-sig",
    label: "Stateful Hash Signatures (LMS/XMSS)",
    category: "Post-quantum",
    operations: ["generate", "sign", "verify"],
    security: "modern",
    tags: ["lms", "xmss", "stateful-hash", "rfc8554", "rfc8391", "sp800-208", "post-quantum"],
    summary: "Stateful hash-based signature schemes (LMS/XMSS) for firmware and code signing.",
    usesPem: false,
  },
  {
    id: "shamir",
    label: "Shamir's Secret Sharing",
    category: "Secret Sharing",
    operations: ["generate", "derive"],
    security: "modern",
    tags: ["shamir", "sss", "threshold", "secret-sharing", "polynomial", "lagrange"],
    summary: "Splits a secret into N shares such that any K shares can reconstruct it.",
    usesPem: false,
  },
  {
    id: "slip39",
    label: "SLIP-0039",
    category: "Secret Sharing",
    operations: ["generate", "derive"],
    security: "modern",
    tags: ["slip39", "slip-0039", "shamir-mnemonic", "trezor", "threshold", "bip39"],
    summary: "Shamir's Secret Sharing Scheme for Mnemonic Codes (SLIP-0039 standard).",
    usesPem: false,
  },
  {
    id: "pedersen",
    label: "Pedersen Commitments",
    category: "Commitment Schemes",
    operations: ["generate", "derive"],
    security: "modern",
    tags: ["pedersen", "commitment", "homomorphic", "zero-knowledge", "blinding"],
    summary: "Information-theoretically binding and computationally hiding commitment scheme.",
    usesPem: false,
  },
  {
    id: "paillier",
    label: "Paillier Cryptosystem",
    category: "Homomorphic",
    operations: ["generate", "encrypt", "decrypt"],
    security: "modern",
    tags: ["paillier", "homomorphic", "additive", "public-key", "privacy", "e-voting"],
    summary: "Additively homomorphic public key encryption scheme invented by Pascal Paillier.",
    usesPem: false,
  },
  {
    id: "ntru",
    label: "NTRUEncrypt (HRSS)",
    category: "Post-quantum",
    operations: ["generate", "encapsulate", "decapsulate"],
    security: "modern",
    tags: ["ntru", "ntru-hrss", "pqc", "post-quantum", "lattice", "kem"],
    summary: "NTRU-HRSS-701 lattice-based post-quantum key encapsulation mechanism.",
    usesPem: false,
  },
  {
    id: "sqisign",
    label: "SQISign",
    category: "Post-quantum",
    operations: ["generate", "sign", "verify"],
    security: "modern",
    tags: ["sqisign", "isogeny", "quaternion", "pqc", "post-quantum", "compact-signatures"],
    summary: "Short Quaternion and Isogeny Signature scheme with ultra-compact public keys and signatures.",
    usesPem: false,
  },
];

const BY_ID = new Map(ASYMMETRIC_TOOLS.map((t) => [t.id, t]));

export function getAsymmetricTool(id: string): AsymmetricToolMeta | undefined {
  return BY_ID.get(id);
}

export function requireAsymmetricTool(id: string): AsymmetricToolMeta {
  const meta = BY_ID.get(id);
  if (!meta) throw new Error(`Unknown public-key tool: ${id}`);
  return meta;
}

export const ASYMMETRIC_TOOL_IDS: readonly string[] = ASYMMETRIC_TOOLS.map((t) => t.id);

/** Curves offered for signing. secp256k1 is here because Bitcoin and Ethereum use it. */
export interface CurveMeta {
  id: string;
  label: string;
  /** Private key size in bytes. */
  secretLen: number;
  /** Compressed public key size in bytes. */
  publicLen: number;
  /**
   * Uncompressed public key size, where the curve has a second encoding.
   *
   * Absent for X25519 and Ed25519, which define exactly one public-key encoding -- which is
   * one of the several small ways they leave less room for error than the NIST curves do.
   */
  uncompressedLen?: number;
  /** Signature size in bytes, in compact r||s form. Zero for a curve that does not sign. */
  signatureLen: number;
  summary: string;
}

export const ECDSA_CURVES: readonly CurveMeta[] = [
  {
    id: "p256",
    label: "P-256",
    secretLen: 32,
    publicLen: 33,
    uncompressedLen: 65,
    signatureLen: 64,
    summary: "NIST secp256r1 — TLS, WebAuthn, JWT ES256",
  },
  {
    id: "p384",
    label: "P-384",
    secretLen: 48,
    publicLen: 49,
    uncompressedLen: 97,
    signatureLen: 96,
    summary: "NIST secp384r1 — JWT ES384",
  },
  {
    id: "p521",
    label: "P-521",
    secretLen: 66,
    publicLen: 67,
    uncompressedLen: 133,
    signatureLen: 132,
    summary: "NIST secp521r1 — JWT ES512",
  },
  {
    id: "secp256k1",
    label: "secp256k1",
    secretLen: 32,
    publicLen: 33,
    uncompressedLen: 65,
    signatureLen: 64,
    summary: "Bitcoin and Ethereum",
  },
];

/** Curves offered for key agreement. X25519 first, because it is the one to choose. */
export const ECDH_CURVES: readonly CurveMeta[] = [
  {
    id: "x25519",
    label: "X25519",
    secretLen: 32,
    publicLen: 32,
    // X25519 does not sign, so there is no signature length for it.
    signatureLen: 0,
    summary: "The default — WireGuard, Signal, TLS 1.3",
  },
  ...ECDSA_CURVES.filter((c) => c.id !== "secp256k1"),
];

export function curvesFor(toolId: string): readonly CurveMeta[] {
  return toolId === "ecdh" ? ECDH_CURVES : ECDSA_CURVES;
}

export function getCurve(toolId: string, curveId: string): CurveMeta | undefined {
  return curvesFor(toolId).find((c) => c.id === curveId);
}

export function requireCurve(toolId: string, curveId: string): CurveMeta {
  const found = getCurve(toolId, curveId);
  if (!found) throw new Error(`${toolId} does not offer the curve ${curveId}`);
  return found;
}

export const DEFAULT_ECDSA_CURVE = "p256";
export const DEFAULT_ECDH_CURVE = "x25519";

export function defaultCurveFor(toolId: string): string {
  return toolId === "ecdh" ? DEFAULT_ECDH_CURVE : DEFAULT_ECDSA_CURVE;
}

/** RSA modulus sizes offered. 1024 is absent because it is broken, not merely weak. */
export const RSA_MODULUS_SIZES = [2048, 3072, 4096] as const;
export const DEFAULT_RSA_MODULUS = 2048;

/**
 * Hashes RSA can be parameterised with — every one OpenSSL will sign with, which is more
 * than WebCrypto supports.
 *
 * `webcrypto: true` marks the four `crypto.subtle` accepts. The rest go through
 * `@ocs/algos`'s pure RSA path, which exists precisely so this list can be complete; see the
 * header of `packages/algos/src/rsa.ts` for what that costs and `A008` for what the user is
 * told about it.
 *
 * Ids are spelled WebCrypto's way ("SHA-256", not "sha256") because four of them are passed
 * straight to `crypto.subtle` and one spelling used everywhere beats two mapped back and
 * forth. `algosHashId` maps to this repo's own ids where the pure path needs them.
 */
export interface RsaHashMeta {
  id: string;
  label: string;
  outputLen: number;
  /** True when `crypto.subtle` accepts it. False routes through the pure path. */
  webcrypto: boolean;
  /** The id this hash has in `@ocs/hash` and in `PKCS1_DIGEST_INFO_PREFIX`. */
  algosHashId: string;
  /** Set when the hash itself is unfit for signing, whatever the padding does. */
  broken?: boolean;
}

export const RSA_HASHES: readonly RsaHashMeta[] = [
  { id: "SHA-256", label: "SHA-256", outputLen: 32, webcrypto: true, algosHashId: "sha256" },
  { id: "SHA-384", label: "SHA-384", outputLen: 48, webcrypto: true, algosHashId: "sha384" },
  { id: "SHA-512", label: "SHA-512", outputLen: 64, webcrypto: true, algosHashId: "sha512" },
  { id: "SHA-224", label: "SHA-224", outputLen: 28, webcrypto: false, algosHashId: "sha224" },
  {
    id: "SHA-512/224",
    label: "SHA-512/224",
    outputLen: 28,
    webcrypto: false,
    algosHashId: "sha512-224",
  },
  {
    id: "SHA-512/256",
    label: "SHA-512/256",
    outputLen: 32,
    webcrypto: false,
    algosHashId: "sha512-256",
  },
  {
    id: "SHA3-224",
    label: "SHA3-224",
    outputLen: 28,
    webcrypto: false,
    algosHashId: "sha3-224",
  },
  {
    id: "SHA3-256",
    label: "SHA3-256",
    outputLen: 32,
    webcrypto: false,
    algosHashId: "sha3-256",
  },
  {
    id: "SHA3-384",
    label: "SHA3-384",
    outputLen: 48,
    webcrypto: false,
    algosHashId: "sha3-384",
  },
  {
    id: "SHA3-512",
    label: "SHA3-512",
    outputLen: 64,
    webcrypto: false,
    algosHashId: "sha3-512",
  },
  { id: "SM3", label: "SM3", outputLen: 32, webcrypto: false, algosHashId: "sm3" },
  {
    id: "RIPEMD-160",
    label: "RIPEMD-160",
    outputLen: 20,
    webcrypto: false,
    algosHashId: "ripemd160",
  },
  {
    id: "SHA-1",
    label: "SHA-1",
    outputLen: 20,
    webcrypto: true,
    algosHashId: "sha1",
    broken: true,
  },
  {
    id: "MD5",
    label: "MD5",
    outputLen: 16,
    webcrypto: false,
    algosHashId: "md5",
    broken: true,
  },
  /**
   * MD5 ‖ SHA-1, which OpenSSL will sign with and which TLS 1.0 and 1.1 required.
   *
   * The odd one out twice over: 36 octets rather than a digest size, and the only entry whose
   * PKCS#1 v1.5 encoding carries no `DigestInfo` wrapper — the concatenation is padded
   * directly, per RFC 4346 §4.7. Included because verifying a pre-TLS-1.2 handshake or an old
   * certificate signature is a real thing to need and nothing else will do it.
   */
  {
    id: "MD5-SHA1",
    label: "MD5-SHA1",
    outputLen: 36,
    webcrypto: false,
    algosHashId: "md5-sha1",
    broken: true,
  },
];

const RSA_HASH_BY_ID = new Map(RSA_HASHES.map((h) => [h.id, h]));

export function getRsaHash(id: string): RsaHashMeta | undefined {
  return RSA_HASH_BY_ID.get(id);
}

export function requireRsaHash(id: string): RsaHashMeta {
  const found = RSA_HASH_BY_ID.get(id);
  if (!found) throw new Error(`RSA is not offered with the hash ${id}`);
  return found;
}

/**
 * Hashes offered for OAEP, which is a shorter list than for signatures.
 *
 * OAEP is left on WebCrypto alone. Extending the pure path to cover encryption as well would
 * mean implementing EME-OAEP and, far more seriously, a constant-time unpadding — and a
 * padding oracle in RSA decryption is not a caveat, it is Bleichenbacher's attack. The four
 * hashes `crypto.subtle` supports are also the only ones any deployment of OAEP uses.
 */
export const RSA_OAEP_HASHES: readonly RsaHashMeta[] = RSA_HASHES.filter((h) => h.webcrypto);

export const DEFAULT_RSA_HASH = "SHA-256";

/**
 * Ed25519's fixed sizes, expressed as a `CurveMeta` so the resolver has one code path.
 *
 * Ed25519 has no curve *option* -- there is nothing to choose -- but its keys and signatures
 * still have lengths, and the alternative to this constant was a second copy of every length
 * check with the numbers inlined.
 */
export const ED25519_CURVE: CurveMeta = {
  id: "ed25519",
  label: "Ed25519",
  secretLen: 32,
  publicLen: 32,
  signatureLen: 64,
  summary: "RFC 8032",
};

/**
 * Digest sizes in bytes, keyed by the WebCrypto spelling and derived from `RSA_HASHES` so
 * there is one list rather than two that can drift.
 *
 * On the cheap side of the split so the lint rules can use it: `A004` compares the digest size
 * against the curve's, and pulling that number out of `@noble/hashes` would drag the whole
 * hash implementation into the eagerly-bundled half for the sake of fourteen integers.
 */
const HASH_OUTPUT_LENGTHS: Record<string, number> = Object.fromEntries(
  RSA_HASHES.map((h) => [h.id, h.outputLen]),
);

export function hashOutputLength(id: string): number {
  return HASH_OUTPUT_LENGTHS[id] ?? 32;
}

/** The hash whose output matches a curve's field size -- what a curve should be paired with. */
export function matchingHashFor(curveId: string): string {
  switch (curveId) {
    case "p384":
      return "SHA-384";
    case "p521":
      return "SHA-512";
    default:
      return "SHA-256";
  }
}

/**
 * A post-quantum parameter set.
 *
 * The byte lengths are duplicated from `@noble/post-quantum`'s own `lengths` object, deliberately and
 * with a test asserting they agree -- the same arrangement as the hash family's `outputLen`. They have
 * to live here because the option catalogue needs them on the *eager* side of the manifest split, and
 * `lengths` comes with the implementation. A wrong number here would be a form that refuses a valid
 * key, which the test is there to stop.
 *
 * `securityCategory` is NIST's own 1/2/3/5 scale, not a bit count. Category 1 is "at least as hard as
 * AES-128", category 5 "at least as hard as AES-256"; there is no category 4 in the PQC project's
 * numbering, which looks like a typo every time and is not one.
 */
export interface PqParamSet {
  id: string;
  label: string;
  securityCategory: 1 | 2 | 3 | 5;
  publicKeyLen: number;
  secretKeyLen: number;
  /** ML-KEM only. */
  cipherTextLen?: number;
  /** The two signature schemes only. */
  signatureLen?: number;
  summary: string;
}

/**
 * ML-KEM, FIPS 203. Formerly Kyber, and not byte-compatible with any pre-standard Kyber.
 *
 * 768 is the default because that is what every deployment picked: TLS's `X25519MLKEM768`, Signal's
 * PQXDH, and CNSA 2.0's floor for key establishment.
 */
export const ML_KEM_SETS: readonly PqParamSet[] = [
  {
    id: "768",
    label: "ML-KEM-768",
    securityCategory: 3,
    publicKeyLen: 1184,
    secretKeyLen: 2400,
    cipherTextLen: 1088,
    summary: "Category 3. What TLS, Signal and CNSA 2.0 actually use.",
  },
  {
    id: "1024",
    label: "ML-KEM-1024",
    securityCategory: 5,
    publicKeyLen: 1568,
    secretKeyLen: 3168,
    cipherTextLen: 1568,
    summary: "Category 5. Larger keys for a longer margin.",
  },
  {
    id: "512",
    label: "ML-KEM-512",
    securityCategory: 1,
    publicKeyLen: 800,
    secretKeyLen: 1632,
    cipherTextLen: 768,
    summary: "Category 1. The smallest set, and the most argued-about.",
  },
];

/** ML-DSA, FIPS 204. Formerly Dilithium, and again not compatible with pre-standard Dilithium. */
export const ML_DSA_SETS: readonly PqParamSet[] = [
  {
    id: "65",
    label: "ML-DSA-65",
    securityCategory: 3,
    publicKeyLen: 1952,
    secretKeyLen: 4032,
    signatureLen: 3309,
    summary: "Category 3. The middle set, and CNSA 2.0's choice for signatures.",
  },
  {
    id: "87",
    label: "ML-DSA-87",
    securityCategory: 5,
    publicKeyLen: 2592,
    secretKeyLen: 4896,
    signatureLen: 4627,
    summary: "Category 5.",
  },
  {
    id: "44",
    label: "ML-DSA-44",
    securityCategory: 2,
    publicKeyLen: 1312,
    secretKeyLen: 2560,
    signatureLen: 2420,
    summary: "Category 2. The smallest signature of the three, at 2420 bytes.",
  },
];

/**
 * SLH-DSA, FIPS 205. Formerly SPHINCS+, and the reason it is worth having alongside ML-DSA: it is a
 * hash-based signature, so its security rests on the hash function rather than on a lattice problem.
 * If lattices turn out to be weaker than believed, this is the fallback that is already standardised.
 *
 * Twelve parameter sets, from two independent choices. The hash family is SHA-2 or SHAKE, and the size
 * variant is `s` (small signature, slow signing) or `f` (fast signing, signature roughly twice as
 * large). The trade is stark: SLH-DSA-SHA2-128s signs in about 1.3 seconds and produces 7856 bytes,
 * where the `f` variant signs in 80 milliseconds and produces 17088.
 */
export const SLH_DSA_SETS: readonly PqParamSet[] = [
  {
    id: "sha2-128s",
    label: "SLH-DSA-SHA2-128s",
    securityCategory: 1,
    publicKeyLen: 32,
    secretKeyLen: 64,
    signatureLen: 7856,
    summary: "Category 1, smallest signature. Signing takes over a second.",
  },
  {
    id: "sha2-128f",
    label: "SLH-DSA-SHA2-128f",
    securityCategory: 1,
    publicKeyLen: 32,
    secretKeyLen: 64,
    signatureLen: 17088,
    summary: "Category 1, fast signing. Twice the signature.",
  },
  {
    id: "sha2-192s",
    label: "SLH-DSA-SHA2-192s",
    securityCategory: 3,
    publicKeyLen: 48,
    secretKeyLen: 96,
    signatureLen: 16224,
    summary: "Category 3, smallest signature.",
  },
  {
    id: "sha2-192f",
    label: "SLH-DSA-SHA2-192f",
    securityCategory: 3,
    publicKeyLen: 48,
    secretKeyLen: 96,
    signatureLen: 35664,
    summary: "Category 3, fast signing.",
  },
  {
    id: "sha2-256s",
    label: "SLH-DSA-SHA2-256s",
    securityCategory: 5,
    publicKeyLen: 64,
    secretKeyLen: 128,
    signatureLen: 29792,
    summary: "Category 5, smallest signature. The slowest set here.",
  },
  {
    id: "sha2-256f",
    label: "SLH-DSA-SHA2-256f",
    securityCategory: 5,
    publicKeyLen: 64,
    secretKeyLen: 128,
    signatureLen: 49856,
    summary: "Category 5, fast signing. Signatures approach 50 KB.",
  },
  {
    id: "shake-128s",
    label: "SLH-DSA-SHAKE-128s",
    securityCategory: 1,
    publicKeyLen: 32,
    secretKeyLen: 64,
    signatureLen: 7856,
    summary: "Category 1, smallest signature, SHAKE instead of SHA-2.",
  },
  {
    id: "shake-128f",
    label: "SLH-DSA-SHAKE-128f",
    securityCategory: 1,
    publicKeyLen: 32,
    secretKeyLen: 64,
    signatureLen: 17088,
    summary: "Category 1, fast signing, SHAKE.",
  },
  {
    id: "shake-192s",
    label: "SLH-DSA-SHAKE-192s",
    securityCategory: 3,
    publicKeyLen: 48,
    secretKeyLen: 96,
    signatureLen: 16224,
    summary: "Category 3, smallest signature, SHAKE.",
  },
  {
    id: "shake-192f",
    label: "SLH-DSA-SHAKE-192f",
    securityCategory: 3,
    publicKeyLen: 48,
    secretKeyLen: 96,
    signatureLen: 35664,
    summary: "Category 3, fast signing, SHAKE.",
  },
  {
    id: "shake-256s",
    label: "SLH-DSA-SHAKE-256s",
    securityCategory: 5,
    publicKeyLen: 64,
    secretKeyLen: 128,
    signatureLen: 29792,
    summary: "Category 5, smallest signature, SHAKE.",
  },
  {
    id: "shake-256f",
    label: "SLH-DSA-SHAKE-256f",
    securityCategory: 5,
    publicKeyLen: 64,
    secretKeyLen: 128,
    signatureLen: 49856,
    summary: "Category 5, fast signing, SHAKE.",
  },
];

export const FALCON_SETS: readonly PqParamSet[] = [
  { id: "512", label: "Falcon-512", securityCategory: 1, publicKeyLen: 1024, secretKeyLen: 2048, signatureLen: 1064, summary: "Category 1, fast Fourier lattice signature." },
  { id: "1024", label: "Falcon-1024", securityCategory: 5, publicKeyLen: 2048, secretKeyLen: 4096, signatureLen: 2088, summary: "Category 5, high security Falcon." },
];

export const MCELIECE_SETS: readonly PqParamSet[] = [
  { id: "348864", label: "Classic McEliece 348864", securityCategory: 1, publicKeyLen: 261120, secretKeyLen: 6452, cipherTextLen: 96, summary: "Category 1 code-based KEM." },
  { id: "6688128", label: "Classic McEliece 6688128", securityCategory: 5, publicKeyLen: 1044992, secretKeyLen: 13892, cipherTextLen: 208, summary: "Category 5 code-based KEM." },
];

export const HQC_SETS: readonly PqParamSet[] = [
  { id: "128", label: "HQC-128", securityCategory: 1, publicKeyLen: 2249, secretKeyLen: 2289, cipherTextLen: 4485, summary: "Category 1 Hamming Quasi-Cyclic KEM." },
  { id: "192", label: "HQC-192", securityCategory: 3, publicKeyLen: 4522, secretKeyLen: 4562, cipherTextLen: 9026, summary: "Category 3 HQC KEM." },
  { id: "256", label: "HQC-256", securityCategory: 5, publicKeyLen: 7245, secretKeyLen: 7285, cipherTextLen: 14469, summary: "Category 5 HQC KEM." },
];

export const STATEFUL_HASH_SIG_SETS: readonly PqParamSet[] = [
  { id: "lms-sha256-h10", label: "LMS SHA-256/192 h10", securityCategory: 1, publicKeyLen: 48, secretKeyLen: 48, signatureLen: 1248, summary: "Leighton-Micali Signature scheme." },
  { id: "xmss-sha256-h10", label: "XMSS SHA-256 h10", securityCategory: 1, publicKeyLen: 48, secretKeyLen: 48, signatureLen: 2500, summary: "Extended Merkle Signature Scheme." },
];

export const NTRU_SETS: readonly PqParamSet[] = [
  { id: "hrss701", label: "NTRU-HRSS-701", securityCategory: 3, publicKeyLen: 1138, secretKeyLen: 1450, cipherTextLen: 1138, summary: "Category 3 NTRU-HRSS lattice-based KEM." },
];

export const SQISIGN_SETS: readonly PqParamSet[] = [
  { id: "sqisign-lvl1", label: "SQISign Level 1", securityCategory: 1, publicKeyLen: 64, secretKeyLen: 782, signatureLen: 177, summary: "Category 1 ultra-compact isogeny signature." },
];

/** Every parameter set a post-quantum tool offers, by tool id. */
export const PQ_PARAM_SETS: Record<string, readonly PqParamSet[]> = {
  mlkem: ML_KEM_SETS,
  mldsa: ML_DSA_SETS,
  slhdsa: SLH_DSA_SETS,
  falcon: FALCON_SETS,
  mceliece: MCELIECE_SETS,
  hqc: HQC_SETS,
  "stateful-hash-sig": STATEFUL_HASH_SIG_SETS,
  ntru: NTRU_SETS,
  sqisign: SQISIGN_SETS,
};

export const DEFAULT_PARAM_SETS: Record<string, string> = {
  mlkem: "768",
  mldsa: "65",
  slhdsa: "sha2-128s",
  falcon: "512",
  mceliece: "348864",
  hqc: "128",
  "stateful-hash-sig": "lms-sha256-h10",
  ntru: "hrss701",
  sqisign: "sqisign-lvl1",
};

export function getParamSet(toolId: string, id: string): PqParamSet | undefined {
  return PQ_PARAM_SETS[toolId]?.find((set) => set.id === id);
}
