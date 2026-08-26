import type { SecurityPosture } from "@ocs/engine";

/**
 * The four MAC tools, as eager metadata. No implementation import is reachable from here.
 *
 * A MAC is where this app's `insecure` diagnostic level earns most of its keep: unlike a
 * digest, a MAC has a key, and almost every way of getting a MAC wrong involves the key —
 * too short, reused across contexts, or compared with `===`.
 */
export interface MacToolMeta {
  id: string;
  label: string;
  category: string;
  /** Which hash the MAC is built on, when that is fixed rather than chosen. */
  fixedHash?: string;
  security: SecurityPosture;
  tags: readonly string[];
  summary: string;
  /** Output size in bytes when fixed; absent when it follows the chosen hash. */
  outputLen?: number;
  /** True when the tool can absorb input incrementally. */
  streaming: boolean;
}

export const MAC_TOOLS: readonly MacToolMeta[] = [
  {
    id: "hmac",
    label: "HMAC",
    category: "HMAC",
    security: "modern",
    tags: ["hmac", "mac", "authentication", "rfc2104", "jwt", "webhook", "signature"],
    summary:
      "Keyed hash over any digest — RFC 2104. The default MAC, and what signs most webhooks and JWTs.",
    streaming: true,
  },
  {
    id: "kmac",
    label: "KMAC",
    category: "Keccak",
    security: "modern",
    tags: ["kmac", "mac", "sha3", "keccak", "nist", "sp800-185", "cshake"],
    summary:
      "SHA-3's own MAC from NIST SP 800-185. Keys the sponge directly rather than nesting two hashes.",
    streaming: true,
  },
  {
    id: "poly1305",
    label: "Poly1305",
    category: "One-time",
    outputLen: 16,
    security: "modern",
    tags: ["poly1305", "mac", "one-time", "rfc8439", "chacha20", "aead"],
    summary: "One-time authenticator from RFC 8439. 16-byte tag, and the key is single-use.",
    streaming: true,
  },
  {
    /**
     * SipHash-2-4, and the honest framing is that it is not a MAC.
     *
     * It is a keyed PRF for short inputs, designed for one job: stopping hash-table flooding, where an
     * attacker who knows the hash function chooses keys that all collide and turns a dictionary into a
     * linked list. Perl, Python, Ruby, Rust, Haskell and both major BSD kernels key their hash tables
     * with it. Sixty-four bits of output is far too short to authenticate a message, and the security
     * note says so rather than letting the family's name imply otherwise.
     *
     * `streaming: false`, and not for want of trying: the construction absorbs 64-bit words and its
     * final word carries the message length, so an incremental version is possible but has nothing to
     * do -- the inputs it is designed for are keys and short strings. Anything long enough to want
     * streaming is the wrong input for this tool.
     */
    id: "siphash",
    label: "SipHash-2-4",
    category: "One-time",
    outputLen: 8,
    security: "not-a-mac",
    tags: [
      "siphash",
      "siphash-2-4",
      "prf",
      "hash flooding",
      "hash table",
      "aumasson",
      "bernstein",
      "rust",
      "python",
    ],
    summary: "The keyed PRF language runtimes use for hash tables. 16-byte key, 8-byte output.",
    streaming: false,
  },
  {
    /**
     * A keyed hash the designers present as a strong PRF, and which no standards body has adopted.
     *
     * `not-a-mac`, following SipHash, and the posture is a judgement rather than an obvious reading:
     * Google's own material is careful to call it a strong pseudorandom function rather than a
     * standardised MAC, and this repo does not upgrade that on a designer's confidence. It is here
     * because reproducing a HighwayHash somebody else printed is a real thing to need -- it is what
     * Chromium, Bazel and several storage formats key -- and because a keyed hash belongs beside
     * SipHash rather than among the non-cryptographic hashes that take a public seed.
     *
     * The key is required and exactly 32 bytes. Unlike BLAKE2's optional key it is not padded and
     * has no zero default: a short key is a different function, not a weaker one.
     */
    id: "highwayhash",
    label: "HighwayHash",
    category: "HighwayHash",
    outputLen: 8,
    security: "not-a-mac",
    tags: [
      "highwayhash",
      "highwayhash64",
      "highwayhash128",
      "highwayhash256",
      "prf",
      "google",
      "siphash",
      "hash flooding",
      "not-a-mac",
    ],
    summary: "Google's keyed hash. 32-byte key, 64/128/256-bit output. A strong PRF, not a standard MAC.",
    streaming: true,
  },
  {
    id: "skeinmac",
    label: "Skein-MAC",
    category: "Skein",
    security: "modern",
    tags: ["skein", "skein-mac", "mac", "threefish", "ubi", "sha-3 finalist", "authentication"],
    summary:
      "Skein keyed the way its designers intended \u2014 a key block, not a nested hash. Any output length.",
    streaming: true,
  },
  {
    id: "asconmac",
    label: "Ascon-MAC",
    category: "Ascon",
    outputLen: 16,
    security: "modern",
    tags: ["ascon", "ascon-mac", "mac", "lightweight", "sponge", "iot", "authentication"],
    summary: "Ascon's native MAC: 128-bit key, 128-bit tag, one pass. Not part of SP 800-232.",
    streaming: true,
  },
  {
    id: "asconprf",
    label: "Ascon-PRF",
    category: "Ascon",
    security: "modern",
    tags: ["ascon", "ascon-prf", "prf", "mac", "lightweight", "sponge", "key derivation"],
    summary: "Ascon's keyed PRF: any output length, and shorter output is a prefix of longer.",
    streaming: true,
  },
  {
    id: "asconprfs",
    label: "Ascon-PRFShort",
    category: "Ascon",
    security: "modern",
    tags: ["ascon", "ascon-prfshort", "prf", "mac", "lightweight", "short", "sponge"],
    summary: "One permutation over at most 16 bytes. The short-message case, done properly.",
    streaming: false,
  },
  {
    id: "cmac",
    label: "AES-CMAC",
    category: "Block cipher",
    outputLen: 16,
    security: "modern",
    tags: ["cmac", "mac", "aes", "omac", "rfc4493", "nist", "sp800-38b"],
    summary:
      "MAC built from AES rather than a hash — RFC 4493. Used where a device already has AES and no hash.",
    streaming: false,
  },
];

const BY_ID = new Map(MAC_TOOLS.map((t) => [t.id, t]));

export function getMacTool(id: string): MacToolMeta | undefined {
  return BY_ID.get(id);
}

export function requireMacTool(id: string): MacToolMeta {
  const meta = BY_ID.get(id);
  if (!meta) throw new Error(`Unknown MAC tool: ${id}`);
  return meta;
}

export const MAC_TOOL_IDS: readonly string[] = MAC_TOOLS.map((t) => t.id);

/**
 * Hashes HMAC can be keyed with.
 *
 * The list is `hash_hmac_algos()` from PHP -- the widest set any mainstream tool offers -- plus five
 * this repo can check independently: SM3, BLAKE2b, BLAKE2s and the two Streebog widths. It is still
 * narrower than the hash family's 91, and the exclusions are deliberate rather than incidental:
 *
 *  - **XOFs and the SP 800-185 functions** (SHAKE, cSHAKE, TupleHash, ParallelHash, TurboSHAKE,
 *    KangarooTwelve, Ascon-XOF128). Keying a sponge is what KMAC is *for*; HMAC over one would produce
 *    a value with no standard behind it and nothing to compare against.
 *  - **The non-cryptographic hashes** (FNV, joaat, MurmurHash3, xxHash, and Adler/CRC in their own
 *    families). HMAC needs a hash whose keyed-collision resistance means something; over these it is
 *    theatre. PHP agrees -- `hash_hmac_algos()` omits every one of them while `hash_algos()` lists them.
 *  - **Ascon-Hash256**, and this one is a technical objection rather than a missing vector: its sponge
 *    rate is 8 bytes, so HMAC's padded key would be 8 bytes and the construction would cap key
 *    material at 64 bits. Ascon's own PRF/MAC modes are the specified answer and would be the right
 *    thing to add instead.
 *
 * Two groups that *were* excluded and are now in, on the user's explicit instruction. **Skein** and the
 * four **BLAKE1** widths have no published HMAC vector anywhere -- Skein's own answer to keying is
 * Skein-MAC, which keys the UBI tweak and is a different construction to this one. They are offered
 * because HMAC over them is well defined and someone may need to reproduce a value; what stands behind
 * them is the construction being checked against noble's `hmac` (BLAKE1 comes from noble, so it goes
 * through the audited path directly) and the block size being asserted against the hash family's own
 * metadata. Where a family has a published HMAC value, `tests/mac.test.ts` says so; for these two it
 * says the opposite, plainly.
 *
 * MD2 *is* here, having been left out before on the grounds that its 16-byte block makes the
 * construction degenerate. That is true and it is not a reason to refuse: PHP offers it, publishes a
 * value for it, and someone with an old MAC to reproduce needs the tool to agree. The note on the
 * choice says what it costs.
 *
 * `blockLen` is the load-bearing field. A wrong block size produces a perfectly stable MAC that no
 * other implementation agrees with -- which is why every family below has a published HMAC vector in
 * `tests/mac.test.ts` rather than only a digest vector.
 */
export const HMAC_HASHES: readonly {
  id: string;
  label: string;
  outputLen: number;
  blockLen: number;
  /**
   * True for anything that should not be chosen for new work. Drives the `insecure` marker on the
   * choice and makes `M003` fire.
   */
  legacy?: boolean;
  /**
   * True only where the hash has a *demonstrated* collision attack.
   *
   * `legacy` and `broken` are two different claims and `M003` says two different things, which is the
   * whole reason for the second flag. MD5 and SHA-1 have practical collisions; Tiger, Snefru, GOST-94
   * and the RIPEMD widths do not -- they are superseded, or attacked at reduced rounds, and a rule
   * that told the reader they were broken would be wrong in the direction that costs trust.
   */
  broken?: boolean;
  /** Sidebar-style grouping for the choice list, which is now long enough to need one. */
  group?: string;
}[] = [
  { id: "sha256", label: "SHA-256", outputLen: 32, blockLen: 64 },
  { id: "sha512", label: "SHA-512", outputLen: 64, blockLen: 128 },
  { id: "sha384", label: "SHA-384", outputLen: 48, blockLen: 128 },
  { id: "sha224", label: "SHA-224", outputLen: 28, blockLen: 64 },
  { id: "sha512-224", label: "SHA-512/224", outputLen: 28, blockLen: 128 },
  { id: "sha512-256", label: "SHA-512/256", outputLen: 32, blockLen: 128 },
  { id: "sha3-224", label: "SHA3-224", outputLen: 28, blockLen: 144 },
  { id: "sha3-256", label: "SHA3-256", outputLen: 32, blockLen: 136 },
  { id: "sha3-384", label: "SHA3-384", outputLen: 48, blockLen: 104 },
  { id: "sha3-512", label: "SHA3-512", outputLen: 64, blockLen: 72 },
  { id: "sha1", label: "SHA-1", outputLen: 20, blockLen: 64, legacy: true, broken: true },
  { id: "md5", label: "MD5", outputLen: 16, blockLen: 64, legacy: true, broken: true },
  { id: "sm3", label: "SM3", outputLen: 32, blockLen: 64 },
  { id: "ripemd160", label: "RIPEMD-160", outputLen: 20, blockLen: 64, legacy: true },
  { id: "blake2b", label: "BLAKE2b", outputLen: 64, blockLen: 128 },
  { id: "blake2s", label: "BLAKE2s", outputLen: 32, blockLen: 64 },

  // Streebog, whose HMAC is RFC 7836's HMAC_GOSTR3411_2012_256/512. Note the block size: 64 bytes
  // for *both* widths, which the RFC states outright (B = 64, L = 32 or 64) and which is the one
  // thing about this pair an implementation gets wrong.
  { id: "streebog256", label: "Streebog-256", outputLen: 32, blockLen: 64, group: "Streebog" },
  { id: "streebog512", label: "Streebog-512", outputLen: 64, blockLen: 64, group: "Streebog" },

  // The rest of PHP's `hash_hmac_algos()`. All legacy: the hashes are broken, weakened or superseded,
  // even where HMAC over them has no published forgery.
  { id: "md4", label: "MD4", outputLen: 16, blockLen: 64, legacy: true, broken: true, group: "Legacy" },
  { id: "md2", label: "MD2", outputLen: 16, blockLen: 16, legacy: true, broken: true, group: "Legacy" },
  { id: "ripemd128", label: "RIPEMD-128", outputLen: 16, blockLen: 64, legacy: true, group: "RIPEMD" },
  { id: "ripemd256", label: "RIPEMD-256", outputLen: 32, blockLen: 64, legacy: true, group: "RIPEMD" },
  { id: "ripemd320", label: "RIPEMD-320", outputLen: 40, blockLen: 64, legacy: true, group: "RIPEMD" },
  { id: "whirlpool", label: "Whirlpool", outputLen: 64, blockLen: 64, group: "Other" },
  { id: "tiger128-3", label: "Tiger-128,3", outputLen: 16, blockLen: 64, legacy: true, group: "Tiger" },
  { id: "tiger160-3", label: "Tiger-160,3", outputLen: 20, blockLen: 64, legacy: true, group: "Tiger" },
  { id: "tiger192-3", label: "Tiger-192,3", outputLen: 24, blockLen: 64, legacy: true, group: "Tiger" },
  { id: "tiger128-4", label: "Tiger-128,4", outputLen: 16, blockLen: 64, legacy: true, group: "Tiger" },
  { id: "tiger160-4", label: "Tiger-160,4", outputLen: 20, blockLen: 64, legacy: true, group: "Tiger" },
  { id: "tiger192-4", label: "Tiger-192,4", outputLen: 24, blockLen: 64, legacy: true, group: "Tiger" },
  { id: "haval128-3", label: "HAVAL-128,3", outputLen: 16, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval160-3", label: "HAVAL-160,3", outputLen: 20, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval192-3", label: "HAVAL-192,3", outputLen: 24, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval224-3", label: "HAVAL-224,3", outputLen: 28, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval256-3", label: "HAVAL-256,3", outputLen: 32, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval128-4", label: "HAVAL-128,4", outputLen: 16, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval160-4", label: "HAVAL-160,4", outputLen: 20, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval192-4", label: "HAVAL-192,4", outputLen: 24, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval224-4", label: "HAVAL-224,4", outputLen: 28, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval256-4", label: "HAVAL-256,4", outputLen: 32, blockLen: 128, legacy: true, broken: true, group: "HAVAL" },
  { id: "haval128-5", label: "HAVAL-128,5", outputLen: 16, blockLen: 128, legacy: true, group: "HAVAL" },
  { id: "haval160-5", label: "HAVAL-160,5", outputLen: 20, blockLen: 128, legacy: true, group: "HAVAL" },
  { id: "haval192-5", label: "HAVAL-192,5", outputLen: 24, blockLen: 128, legacy: true, group: "HAVAL" },
  { id: "haval224-5", label: "HAVAL-224,5", outputLen: 28, blockLen: 128, legacy: true, group: "HAVAL" },
  { id: "haval256-5", label: "HAVAL-256,5", outputLen: 32, blockLen: 128, legacy: true, group: "HAVAL" },
  { id: "snefru", label: "Snefru-256", outputLen: 32, blockLen: 32, legacy: true, group: "Other" },
  { id: "gost94", label: "GOST R 34.11-94", outputLen: 32, blockLen: 32, legacy: true, group: "GOST" },
  {
    id: "gost94-crypto",
    label: "GOST R 34.11-94 (CryptoPro)",
    outputLen: 32,
    blockLen: 32,
    legacy: true,
    group: "GOST",
  },

  /**
   * Skein and BLAKE1: no published HMAC vector, offered anyway. See the note above.
   *
   * Skein's block is its state size, which is what its name counts -- 32, 64 or 128 bytes. BLAKE-224
   * and BLAKE-256 share MD4's 64-byte block; the two wider ones use 128, like SHA-512.
   */
  { id: "skein256", label: "Skein-256", outputLen: 32, blockLen: 32, group: "Skein" },
  { id: "skein512", label: "Skein-512", outputLen: 64, blockLen: 64, group: "Skein" },
  { id: "skein1024", label: "Skein-1024", outputLen: 128, blockLen: 128, group: "Skein" },
  { id: "blake224", label: "BLAKE-224", outputLen: 28, blockLen: 64, group: "BLAKE" },
  { id: "blake256", label: "BLAKE-256", outputLen: 32, blockLen: 64, group: "BLAKE" },
  { id: "blake384", label: "BLAKE-384", outputLen: 48, blockLen: 128, group: "BLAKE" },
  { id: "blake512", label: "BLAKE-512", outputLen: 64, blockLen: 128, group: "BLAKE" },
];

const HASH_BY_ID = new Map(HMAC_HASHES.map((h) => [h.id, h]));

export function requireHmacHash(id: string): (typeof HMAC_HASHES)[number] {
  const hash = HASH_BY_ID.get(id);
  if (!hash) throw new Error(`HMAC is not offered over: ${id}`);
  return hash;
}

export const DEFAULT_HMAC_HASH = "sha256";

/** KMAC comes in two strengths only — the sponge capacity is what the number names. */
export const KMAC_VARIANTS: readonly { id: string; label: string; outputLen: number }[] = [
  { id: "kmac128", label: "KMAC128", outputLen: 32 },
  { id: "kmac256", label: "KMAC256", outputLen: 64 },
];

export const DEFAULT_KMAC_VARIANT = "kmac128";
