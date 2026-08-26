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
    /**
     * OpenSSH's KDF, and not simply PBKDF2 with bcrypt as its PRF.
     *
     * Three things make it a separate algorithm rather than a composition. Its round is 129
     * EksBlowfish key expansions rather than one, so the work per round is fixed and `rounds` is
     * the only knob -- bcrypt's logarithmic `cost` has no counterpart here. Password and salt are
     * collapsed to SHA-512 digests first, which removes bcrypt's 72-byte limit and its NUL
     * truncation, and is why OpenSSH can key a file from any passphrase. And the output is
     * interleaved with a stride rather than concatenated, so asking for 32 bytes and asking for 64
     * do not share a prefix.
     */
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
