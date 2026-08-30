import type { SecurityPosture } from "@ocs/engine";

/**
 * The seven KDF tools, as eager metadata.
 *
 * Two genuinely different jobs sit in this family and conflating them is the mistake it
 * exists to prevent:
 *
 *  - **Key derivation** (HKDF): stretch or separate material that is *already* high
 *    entropy. Fast on purpose. Using it on a password is the error.
 *  - **Password hashing** (PBKDF2, scrypt, Argon2, bcrypt): make guessing expensive,
 *    because the input has maybe 30 bits of entropy. Slow on purpose.
 *
 * `purpose` records which, and the lint rules key off it.
 */
export type KdfPurpose = "key-derivation" | "password-hashing";

export interface KdfToolMeta {
  id: string;
  label: string;
  category: string;
  purpose: KdfPurpose;
  security: SecurityPosture;
  tags: readonly string[];
  summary: string;
  /**
   * True when the tool can check an existing hash as well as produce one.
   *
   * bcrypt, scrypt and Argon2 all have a standard textual encoding that carries their
   * parameters and salt, so a stored hash is self-describing and can be verified from the
   * string alone. PBKDF2 and HKDF have no such format — the parameters live outside the
   * output — so there is nothing to verify against.
   */
  supportsVerify: boolean;
}

export const KDF_TOOLS: readonly KdfToolMeta[] = [
  {
    /**
     * OpenSSL's `EVP_BytesToKey`, which is what `openssl enc -k` used before `-pbkdf2` existed.
     *
     * `broken` rather than `legacy`, and the distinction is deliberate: SHA-1 is legacy because it
     * still does its job while being too narrow for new work, whereas one hash pass over an
     * 8-byte salt provides essentially no resistance to guessing at all. Files encrypted this way
     * are recoverable at a rate limited by disk speed, not by the KDF. It is here because those
     * files exist and someone has to open them.
     */
    id: "evpkdf",
    label: "EvpKDF",
    category: "Legacy interop",
    purpose: "password-hashing",
    security: "broken",
    tags: [
      "evpkdf",
      "evp_bytestokey",
      "openssl",
      "enc",
      "legacy",
      "cryptojs",
      "key derivation",
    ],
    summary:
      "OpenSSL's EVP_BytesToKey: derives a key and IV together from a password. For old files.",
    supportsVerify: false,
  },
  {
    id: "pbkdf2",
    label: "PBKDF2",
    category: "Password hashing",
    purpose: "password-hashing",
    security: "legacy",
    tags: ["pbkdf2", "kdf", "password", "rfc2898", "rfc8018", "rfc6070", "wpa2"],
    summary:
      "Iterated HMAC from RFC 8018. Ubiquitous, FIPS-approved, and the easiest of these to attack with hardware.",
    supportsVerify: false,
  },
  {
    id: "hkdf",
    label: "HKDF",
    category: "Key derivation",
    purpose: "key-derivation",
    security: "modern",
    tags: ["hkdf", "kdf", "extract", "expand", "rfc5869", "tls", "signal"],
    summary:
      "Extract-and-expand from RFC 5869. For splitting or stretching material that is already random.",
    supportsVerify: false,
  },
  {
    id: "scrypt",
    label: "scrypt",
    category: "Password hashing",
    purpose: "password-hashing",
    security: "modern",
    tags: ["scrypt", "kdf", "password", "rfc7914", "memory-hard", "litecoin"],
    summary:
      "Memory-hard password hash from RFC 7914. Forces an attacker to buy RAM as well as cores.",
    supportsVerify: true,
  },
  {
    id: "argon2",
    label: "Argon2",
    category: "Password hashing",
    purpose: "password-hashing",
    security: "modern",
    tags: ["argon2", "argon2id", "argon2i", "argon2d", "kdf", "password", "rfc9106", "phc"],
    summary:
      "Winner of the Password Hashing Competition, standardised as RFC 9106. The current default choice.",
    supportsVerify: true,
  },
  {
    id: "bcrypt",
    label: "bcrypt",
    category: "Password hashing",
    purpose: "password-hashing",
    security: "legacy",
    tags: ["bcrypt", "kdf", "password", "blowfish", "eksblowfish", "openbsd", "phc"],
    summary:
      "The Blowfish-based password hash from OpenBSD. Self-describing output, and a 72-byte password limit.",
    supportsVerify: true,
  },
  {
    id: "bcryptpbkdf",
    label: "bcrypt-PBKDF",
    category: "Password hashing",
    purpose: "password-hashing",
    security: "modern",
    tags: [
      "bcrypt-pbkdf",
      "bcrypt_pbkdf",
      "kdf",
      "password",
      "openssh",
      "ssh-keygen",
      "openbsd",
      "blowfish",
      "eksblowfish",
    ],
    summary:
      "OpenBSD's bcrypt-PBKDF, which OpenSSH uses to encrypt private keys. bcrypt's cost without its 72-byte limit.",
    supportsVerify: false,
  },
  {
    id: "yescrypt",
    label: "yescrypt",
    category: "Password hashing",
    purpose: "password-hashing",
    security: "modern",
    tags: ["yescrypt", "kdf", "password", "shadow", "linux", "phc", "memory-hard"],
    summary: "Memory-hard password hash by Solar Designer. Default in modern Linux /etc/shadow.",
    supportsVerify: false,
  },
  {
    id: "balloon",
    label: "Balloon",
    category: "Password hashing",
    purpose: "password-hashing",
    security: "modern",
    tags: ["balloon", "kdf", "password", "rfc9383", "memory-hard", "stanford"],
    summary: "Provably memory-hard password hash from Stanford and RFC 9383.",
    supportsVerify: false,
  },
  {
    id: "sp800-108",
    label: "SP 800-108 KDF",
    category: "Key derivation",
    purpose: "key-derivation",
    security: "modern",
    tags: ["sp800-108", "sp800108", "nist", "kdf", "tpm", "bitlocker", "counter", "feedback"],
    summary: "NIST standard KDF in Counter, Feedback, and Double-Pipeline modes.",
    supportsVerify: false,
  },
  {
    id: "openpgp-s2k",
    label: "OpenPGP S2K",
    category: "Key derivation",
    purpose: "key-derivation",
    security: "legacy",
    tags: ["openpgp", "s2k", "rfc4880", "rfc9580", "pgp", "gnupg", "string-to-key"],
    summary: "OpenPGP String-to-Key: Simple, Salted, and Iterated+Salted passphrase derivation.",
    supportsVerify: false,
  },
  {
    id: "ssh-kdf",
    label: "SSHv2 KDF",
    category: "Key derivation",
    purpose: "key-derivation",
    security: "modern",
    tags: ["ssh", "ssh2", "rfc4253", "kdf", "kex", "session"],
    summary: "SSHv2 Key Exchange KDF for deriving IVs, cipher keys, and MAC integrity keys.",
    supportsVerify: false,
  },
  {
    id: "tls12-prf",
    label: "TLS 1.2 PRF",
    category: "Key derivation",
    purpose: "key-derivation",
    security: "modern",
    tags: ["tls", "tls12", "prf", "rfc5246", "p_hash", "master secret"],
    summary: "TLS 1.2 Pseudo-Random Function using P_hash HMAC expansion.",
    supportsVerify: false,
  },
  {
    id: "catena",
    label: "Catena",
    category: "Password hashing",
    purpose: "password-hashing",
    security: "modern",
    tags: ["catena", "kdf", "password", "phc", "memory-hard", "dragonfly"],
    summary: "Memory-hard password scrambler with bit-reversal graph from PHC.",
    supportsVerify: false,
  },
  {
    id: "ansi-x963",
    label: "ANSI X9.63 KDF",
    category: "Key derivation",
    purpose: "key-derivation",
    security: "modern",
    tags: ["ansi", "x963", "sec1", "iso18033", "ecdh", "kdf"],
    summary: "ANSI X9.63 / SEC 1 key derivation function for ECDH shared secrets.",
    supportsVerify: false,
  },
  {
    id: "hpke",
    label: "HPKE (RFC 9180)",
    category: "Protocol KDF",
    purpose: "key-derivation",
    security: "modern",
    tags: ["hpke", "rfc9180", "hybrid", "public-key", "kem", "kdf", "aead"],
    summary: "Hybrid Public Key Encryption (RFC 9180) combining KEM, KDF, and AEAD.",
    supportsVerify: false,
  },
  {
    id: "bip39",
    label: "BIP-39 Mnemonic",
    category: "Key derivation",
    purpose: "key-derivation",
    security: "modern",
    tags: ["bip39", "bip-39", "mnemonic", "seed", "passphrase", "bitcoin", "wallet"],
    summary: "BIP-39 mnemonic phrase generation and PBKDF2 seed derivation for wallets.",
    supportsVerify: false,
  },
  {
    id: "bip32",
    label: "BIP-32 HD Keys",
    category: "Key derivation",
    purpose: "key-derivation",
    security: "modern",
    tags: ["bip32", "bip-32", "hd-wallet", "derivation-path", "secp256k1", "bitcoin"],
    summary: "Hierarchical Deterministic (HD) key derivation for cryptographic wallets.",
    supportsVerify: false,
  },
  {
    id: "hkdf-label",
    label: "HKDF-Expand-Label",
    category: "Key derivation",
    purpose: "key-derivation",
    security: "modern",
    tags: ["hkdf-label", "tls13", "quic", "rfc8446", "hkdf", "label"],
    summary: "HKDF-Expand-Label key derivation used in TLS 1.3 and QUIC protocol key schedules.",
    supportsVerify: false,
  },
];

const BY_ID = new Map(KDF_TOOLS.map((t) => [t.id, t]));

export function getKdfTool(id: string): KdfToolMeta | undefined {
  return BY_ID.get(id);
}

export function requireKdfTool(id: string): KdfToolMeta {
  const meta = BY_ID.get(id);
  if (!meta) throw new Error(`Unknown KDF tool: ${id}`);
  return meta;
}

export const KDF_TOOL_IDS: readonly string[] = KDF_TOOLS.map((t) => t.id);

/** Hashes PBKDF2 and HKDF can be built on. Both are HMAC-based, so this mirrors the MAC family's list. */
export const KDF_HASHES: readonly { id: string; label: string; outputLen: number }[] = [
  { id: "sha256", label: "SHA-256", outputLen: 32 },
  { id: "sha512", label: "SHA-512", outputLen: 64 },
  { id: "sha384", label: "SHA-384", outputLen: 48 },
  { id: "sha1", label: "SHA-1", outputLen: 20 },
  { id: "sha3-256", label: "SHA3-256", outputLen: 32 },
  /**
   * Present for EvpKDF alone, and the reason it has to be here at all: `openssl enc -k` defaulted
   * to MD5 for about twenty years, so reading a file encrypted that way means being able to
   * reproduce it. `K009` marks the whole tool as unfit for new work rather than singling out this
   * entry -- with one MD5 pass over an 8-byte salt, the hash choice is not what makes it weak.
   */
  { id: "md5", label: "MD5", outputLen: 16 },
];

export const DEFAULT_KDF_HASH = "sha256";

/** Argon2's three variants. RFC 9106 recommends id unless you have a specific reason. */
export const ARGON2_VARIANTS: readonly { id: string; label: string; summary: string }[] = [
  {
    id: "argon2id",
    label: "Argon2id",
    summary: "Hybrid — the default RFC 9106 recommends",
  },
  {
    id: "argon2i",
    label: "Argon2i",
    summary: "Data-independent, for side-channel resistance",
  },
  {
    id: "argon2d",
    label: "Argon2d",
    summary: "Data-dependent, maximum GPU resistance",
  },
];

export const DEFAULT_ARGON2_VARIANT = "argon2id";
