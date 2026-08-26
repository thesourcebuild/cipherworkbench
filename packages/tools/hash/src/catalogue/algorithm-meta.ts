import type { SecurityPosture } from "@ocs/engine";

/**
 * Everything about a digest algorithm that is *not* its implementation.
 *
 * This module is eager — the sidebar lists every algorithm on first paint — so it
 * must stay free of `@noble` imports, which would pull every compression function
 * into the initial bundle to render a list of names. The bindings live in
 * `../bindings.ts` and are only reached once a tool is actually opened.
 *
 * Keeping `outputLen`/`blockLen` here rather than reading them off the noble object
 * is what makes that split possible; `tests/hash.test.ts` asserts the two halves
 * agree for every id, so the duplication cannot drift.
 */

/**
 * How the digest size is determined — a three-way distinction, not a boolean, and
 * the difference between the last two is the kind of thing a tool like this exists
 * to get right:
 *
 *  fixed         — one size, not negotiable. SHA-256 is 32 bytes.
 *  xof           — an extendable-output function. Ask for any length; a shorter
 *                  output is a genuine *prefix* of a longer one, because you are
 *                  squeezing a stream. SHAKE, BLAKE3.
 *  parameterized — variable length, but the length is mixed into the
 *                  initialisation, so BLAKE2b-256 is NOT the first 32 bytes of
 *                  BLAKE2b-512 — it is an unrelated value. Calling that
 *                  "truncation" is the mistake; they are different functions.
 */
export type OutputMode = "fixed" | "xof" | "parameterized";

/**
 * Which extra controls an algorithm exposes, as `availableOn` tags.
 *
 * Originally one tag per algorithm, on the reasoning that none would need two. The SHA-3 addons
 * broke that: cSHAKE is an XOF *and* takes a customisation string *and* a function name. So
 * `variantTags` below returns a set and `ToolDefinition.variantTag` accepts an array.
 */
export const TAG_VARIABLE_OUTPUT = "variable";
export const TAG_SEEDED = "seeded";
export const TAG_SEEDED_64 = "seeded64";
export const TAG_HASH_VARIANT = "hashVariant";

/**
 * The SHA-3 addon axes. These are what forced `variantTag` to return a *set* rather than one
 * string: cSHAKE is variable-output AND customisable AND takes a function name, and ParallelHash
 * adds a block size on top. The comment above used to say no algorithm needed two tags. cSHAKE
 * needs three.
 */
/**
 * A fixed set of output lengths, rendered as a select, and a fixed set of pass counts.
 *
 * `TAG_OUTPUT_CHOICE` is deliberately exclusive with `TAG_VARIABLE_OUTPUT`: an algorithm has
 * either a range or a list, never both controls at once.
 */
export const TAG_OUTPUT_CHOICE = "outputChoice";
export const TAG_PASSES = "passes";

export const TAG_CUSTOMIZATION = "customization";
export const TAG_FUNCTION_NAME = "functionName";
export const TAG_BLOCK_SIZE = "blockSize";
export const TAG_DOMAIN = "domain";
export const TAG_TUPLE = "tuple";
export const TAG_BLAKE_KEY = "blakeKey";
export const TAG_BLAKE_SALT = "blakeSalt";
export const TAG_BLAKE_CONTEXT = "blakeContext";

export interface HashAlgorithmMeta {
  id: string;
  label: string;
  /** Sidebar grouping — the algorithm's family, not its security. */
  category: string;
  /** Digest size in bytes. For a non-fixed algorithm this is the default the UI starts on. */
  outputLen: number;
  /** Compression block size (or sponge rate) in bytes. Needed by HMAC and by the key-length lint rules. */
  blockLen: number;
  outputMode: OutputMode;
  /** Hard ceiling on a `parameterized` algorithm's output. Absent for `fixed`; XOFs have no real limit. */
  maxOutputLen?: number;
  /**
   * The exact legal output lengths in bytes, when an algorithm has a fixed set rather than a range.
   *
   * Presence of this turns the output-length control from a number field into a select -- HAVAL
   * accepts five lengths and nothing between them, so a numeric field would invite 17 and then have
   * to refuse or silently round it. `outputLen` remains the default the UI starts on.
   */
  outputLengths?: readonly number[];
  /**
   * True when a shorter output really is the first bytes of the longest one.
   *
   * Tiger-128 is the first 16 bytes of Tiger-192; HAVAL-128 is unrelated to HAVAL-256's first 16.
   * Both look identical in the form, and someone truncating a digest by hand gets a right answer in
   * one case and a wrong one in the other, so it is worth stating rather than implying.
   */
  truncation?: boolean;
  /**
   * Legal pass counts, in display order, for the algorithms whose round count is an argument.
   *
   * HAVAL takes 3, 4 or 5 and Tiger 3 or 4. Both are one implementation with a loop bound, so they
   * are one tool each with a control rather than fifteen and six entries.
   */
  passes?: readonly number[];
  /** Which of `passes` the form opens on. Explicit, because neither the first nor the last is right for both. */
  defaultPasses?: number;
  /** Below this many passes the algorithm has a practical collision attack. Read by `H001`. */
  brokenBelowPasses?: number;
  /** Accepts a caller-chosen seed — the xxHash pair. Surfaces the `seed` option. */
  seeded?: boolean;
  /**
   * Accepts a 64-bit seed, as bytes rather than as a number. SpookyHash and t1ha.
   *
   * A separate flag from `seeded` because the *control* is different, not because the idea is: xxHash
   * and MetroHash take 32 bits, which fits a number field exactly, and these two take 64, which does
   * not fit a JavaScript number at all. Storing it as eight bytes of hex is the only spelling that can
   * express `0xffffffffffffffff` -- and t1ha's own reference vectors use exactly that seed, so a
   * numeric control would make some of them unreachable from the app.
   */
  seeded64?: boolean;
  /**
   * Named variants of one algorithm, when the choice is not an output length or a pass count.
   *
   * MetroHash's two constant sets and t1ha's two versions. Both are "which of these functions",
   * which `outputLengths` and `passes` cannot express -- MetroHash 64 variant 1 and variant 2 have the
   * same width and the same round count and are different functions. The id is what reaches the
   * binding, so it is the reference's own name.
   */
  variants?: readonly {
    readonly id: string;
    readonly label: string;
    /**
     * The digest width this variant produces, when the variant *is* the width.
     *
     * Quark's four instances have four state sizes and four digest lengths, and the length is not a
     * choice on top of the instance -- u-Quark produces 17 bytes and nothing else. So `outputLengths`
     * cannot express it (the length is not independently selectable) and neither can a single
     * `outputLen` on the algorithm (three of the four would be wrong). Declaring it here keeps one
     * control, and `resolveOutputLen` reads it so the header, the length the form reports and the bytes
     * that come out cannot disagree.
     *
     * Absent for MetroHash and t1ha, whose variants share a width with each other.
     */
    readonly outputLen?: number;
  }[];
  /** Which of `variants` the form opens on. Explicit, because the first is not always right. */
  defaultVariant?: string;
  /** Accepts a customisation string S: cSHAKE, TupleHash, ParallelHash, KangarooTwelve. */
  customizable?: boolean;
  /** Accepts cSHAKE's function-name string N, which only cSHAKE has. */
  namedFunction?: boolean;
  /** Accepts ParallelHash's block size B. */
  blockSized?: boolean;
  /** Accepts TurboSHAKE's domain-separation byte D. */
  domainSeparated?: boolean;
  /**
   * Reads its input from the `tuple` list option instead of the input panel -- TupleHash only.
   *
   * The input of TupleHash is a *tuple*, and its incremental API makes each `update()` one
   * element: feeding a file in 64 KiB chunks would hash a tuple of chunks, which is a different
   * value and an absurd one. So this drives `supportsFile: false` and `streaming: false` in the
   * manifest, the same shape the KDF family uses for tools whose inputs are all options.
   */
  tupleInput?: boolean;
  /**
   * BLAKE2 and BLAKE3: accepts a key, turning the hash into a MAC in one step.
   *
   * Its own flag rather than reusing `customizable`, because the two are different kinds of thing
   * that happen to both be extra bytes: a customisation string separates domains and is public, a
   * key is a secret and has to be marked `secret: true` so the share link strips it.
   */
  keyed?: boolean;
  /** BLAKE2 only: RFC 7693's salt and personalisation fields, both fixed-width. */
  saltedPersonalised?: boolean;
  /** BLAKE3 only: `derive_key` context, which the specification makes exclusive with a key. */
  contextual?: boolean;
  security: SecurityPosture;
  tags: readonly string[];
  summary: string;
}

/**
 * Declaration order is display order — the sidebar groups by `category` and keeps
 * categories in the order they first appear here. That is deliberately not
 * alphabetical: MD before SHA-1 before SHA-2 before SHA-3 is the order they
 * superseded one another in, which is the order someone choosing between them
 * wants to read.
 */
export const HASH_ALGORITHMS: readonly HashAlgorithmMeta[] = [
  // ── MD ────────────────────────────────────────────────────────────────────
  {
    id: "md2",
    label: "MD2",
    category: "MD",
    outputLen: 16,
    // MD2 is byte-oriented throughout: 16-byte blocks, no 32-bit words anywhere.
    blockLen: 16,
    outputMode: "fixed",
    security: "broken",
    tags: ["md2", "digest", "legacy", "rfc1319", "certificate"],
    summary: "128-bit digest from RFC 1319. Obsolete; kept for identifying old certificates.",
  },
  {
    id: "md4",
    label: "MD4",
    category: "MD",
    outputLen: 16,
    blockLen: 64,
    outputMode: "fixed",
    security: "broken",
    tags: ["md4", "digest", "legacy", "rfc1320", "ntlm", "rsync"],
    summary: "128-bit digest from RFC 1320, MD5's predecessor. Broken; still what NTLM uses.",
  },
  {
    id: "md5",
    label: "MD5",
    category: "MD",
    outputLen: 16,
    blockLen: 64,
    outputMode: "fixed",
    security: "broken",
    tags: ["md5", "digest", "checksum", "legacy", "rfc1321"],
    summary: "128-bit digest from RFC 1321. Broken for any adversarial use.",
  },
  {
    /**
     * MD6, Rivest's SHA-3 round-1 submission, and the only tree hash in the app.
     *
     * In the MD category because that is what he called it and where anyone would look for it, but it
     * shares nothing with MD4 and MD5 beyond the name: those are Merkle-Damgard over 64-byte blocks,
     * and this is a Merkle *tree* over 512-byte leaves with a compression function that is one
     * recurrence over 89 words and no S-boxes at all.
     *
     * Withdrawn from the SHA-3 competition after round 1 -- the team could not prove the security
     * margin they wanted within the performance target, and said so themselves rather than waiting to
     * be eliminated. `legacy` rather than `broken` for that reason: there is no attack on it, and the
     * reason not to reach for it is that it was never standardised and nothing else implements it.
     */
    id: "md6",
    label: "MD6",
    category: "MD",
    outputLen: 32,
    /**
     * 512, the leaf size, and it is not a compression block in the Merkle-Damgard sense.
     *
     * This is the only entry where `blockLen` describes a *tree leaf*. Nothing in the hash family reads
     * it except HMAC's padding -- and MD6 is deliberately not offered there, since the submission's own
     * answer to keying is a key input to the compression function rather than a nested construction.
     */
    blockLen: 512,
    outputMode: "parameterized",
    /**
     * Three sizes as a dropdown rather than a number field.
     *
     * MD6 accepts any `d` from 1 to 512 bits, and a numeric control would therefore be *honest* -- but
     * the round count is `40 + d/4`, so every value is a different function and nobody has published a
     * value at 137 bits. Three named sizes are what people actually want, and `outputLengths` is the
     * mechanism the HAVAL and Tiger merges already established.
     */
    outputLengths: [16, 32, 64],
    /**
     * False, and this is the one to be careful about.
     *
     * MD6-128 is *not* the first 16 bytes of MD6-512: the digest size goes into the control word and
     * changes the round count, so the two are unrelated functions. Someone truncating an MD6-512 by
     * hand gets a wrong answer with no error, which is exactly what this flag exists to say.
     */
    truncation: false,
    security: "legacy",
    tags: [
      "md6",
      "rivest",
      "sha-3 candidate",
      "sha-3 competition",
      "tree hash",
      "merkle tree",
      "digest",
      "md6-128",
      "md6-256",
      "md6-512",
    ],
    summary: "Rivest's SHA-3 candidate: a Merkle tree over 512-byte leaves. 128, 256 or 512 bits.",
  },

  // ── SHA-1 ─────────────────────────────────────────────────────────────────
  {
    id: "sha1",
    label: "SHA-1",
    category: "SHA-1",
    outputLen: 20,
    blockLen: 64,
    outputMode: "fixed",
    security: "broken",
    tags: ["sha1", "sha-1", "digest", "legacy", "fips180", "git"],
    summary:
      "160-bit digest from FIPS 180-4. Collision-broken; still ubiquitous in git and legacy TLS.",
  },

  // ── SHA-2 ─────────────────────────────────────────────────────────────────
  {
    id: "sha224",
    label: "SHA-224",
    category: "SHA-2",
    outputLen: 28,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha224", "sha-224", "sha2", "digest", "fips180"],
    summary: "224-bit digest — SHA-256's compression function with a different IV, truncated.",
  },
  {
    id: "sha256",
    label: "SHA-256",
    category: "SHA-2",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha256", "sha-256", "sha2", "digest", "fips180", "checksum"],
    summary:
      "256-bit digest from FIPS 180-4. The default choice for file checksums and signatures.",
  },
  {
    id: "sha384",
    label: "SHA-384",
    category: "SHA-2",
    outputLen: 48,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha384", "sha-384", "sha2", "digest", "fips180"],
    summary: "384-bit digest — SHA-512 truncated, and immune to its length-extension weakness.",
  },
  {
    id: "sha512",
    label: "SHA-512",
    category: "SHA-2",
    outputLen: 64,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha512", "sha-512", "sha2", "digest", "fips180"],
    summary: "512-bit digest from FIPS 180-4. Faster than SHA-256 on 64-bit hardware.",
  },
  {
    id: "sha512-224",
    label: "SHA-512/224",
    category: "SHA-2",
    outputLen: 28,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha512-224", "sha2", "digest", "fips180", "truncated"],
    summary: "224-bit output from the SHA-512 core, with its own initial values.",
  },
  {
    id: "sha512-256",
    label: "SHA-512/256",
    category: "SHA-2",
    outputLen: 32,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha512-256", "sha2", "digest", "fips180", "truncated"],
    summary:
      "256-bit output from the SHA-512 core — SHA-256's size at SHA-512's speed, with no length extension.",
  },

  // ── SHA-3 ─────────────────────────────────────────────────────────────────
  {
    id: "sha3-224",
    label: "SHA3-224",
    category: "SHA-3",
    outputLen: 28,
    blockLen: 144,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha3", "sha3-224", "keccak", "digest", "fips202"],
    summary: "224-bit Keccak sponge with the FIPS 202 padding.",
  },
  {
    id: "sha3-256",
    label: "SHA3-256",
    category: "SHA-3",
    outputLen: 32,
    blockLen: 136,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha3", "sha3-256", "keccak", "digest", "fips202"],
    summary: "256-bit Keccak sponge from FIPS 202. Structurally unrelated to SHA-2.",
  },
  {
    id: "sha3-384",
    label: "SHA3-384",
    category: "SHA-3",
    outputLen: 48,
    blockLen: 104,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha3", "sha3-384", "keccak", "digest", "fips202"],
    summary: "384-bit Keccak sponge from FIPS 202.",
  },
  {
    id: "sha3-512",
    label: "SHA3-512",
    category: "SHA-3",
    outputLen: 64,
    blockLen: 72,
    outputMode: "fixed",
    security: "modern",
    tags: ["sha3", "sha3-512", "keccak", "digest", "fips202"],
    summary: "512-bit Keccak sponge from FIPS 202.",
  },

  // ── Keccak (original padding) ─────────────────────────────────────────────
  {
    id: "keccak-224",
    label: "Keccak-224",
    category: "Keccak",
    outputLen: 28,
    blockLen: 144,
    outputMode: "fixed",
    security: "legacy",
    tags: ["keccak", "keccak-224", "digest", "pre-fips"],
    summary: "224-bit Keccak with the original submission's padding, not SHA-3's.",
  },
  {
    id: "keccak-256",
    label: "Keccak-256",
    category: "Keccak",
    outputLen: 32,
    blockLen: 136,
    outputMode: "fixed",
    security: "legacy",
    tags: ["keccak", "keccak-256", "digest", "ethereum", "evm", "pre-fips"],
    summary: "256-bit Keccak with the original padding — Ethereum's hash, not SHA3-256.",
  },
  {
    id: "keccak-384",
    label: "Keccak-384",
    category: "Keccak",
    outputLen: 48,
    blockLen: 104,
    outputMode: "fixed",
    security: "legacy",
    tags: ["keccak", "keccak-384", "digest", "pre-fips"],
    summary: "384-bit Keccak with the original submission's padding.",
  },
  {
    id: "keccak-512",
    label: "Keccak-512",
    category: "Keccak",
    outputLen: 64,
    blockLen: 72,
    outputMode: "fixed",
    security: "legacy",
    tags: ["keccak", "keccak-512", "digest", "pre-fips"],
    summary: "512-bit Keccak with the original submission's padding.",
  },

  // ── XOF ───────────────────────────────────────────────────────────────────
  {
    id: "shake128",
    label: "SHAKE128",
    category: "XOF",
    outputLen: 32,
    blockLen: 168,
    outputMode: "xof",
    security: "modern",
    tags: ["shake", "shake128", "xof", "sha3", "keccak", "fips202"],
    summary:
      "Extendable output at a 128-bit security level. Ask for as many bytes as you need.",
  },
  {
    id: "shake256",
    label: "SHAKE256",
    category: "XOF",
    outputLen: 64,
    blockLen: 136,
    outputMode: "xof",
    security: "modern",
    tags: ["shake", "shake256", "xof", "sha3", "keccak", "fips202"],
    summary: "Extendable output at a 256-bit security level.",
  },

  // ── SHA-3 derived functions (NIST SP 800-185, and their faster successors) ─
  /**
   * Six Keccak constructions that are not plain digests.
   *
   * They share a sponge with SHA-3 and differ in padding and domain separation, which is why
   * they sit here rather than in a family of their own -- and why each needs parameters that a
   * digest does not. Getting a parameter wrong produces a perfectly well-formed value that
   * matches nothing, so every one of them carries a long `detail` on its option.
   */
  {
    id: "cshake128",
    label: "cSHAKE128",
    category: "SHAKE",
    outputLen: 32,
    blockLen: 168,
    outputMode: "xof",
    customizable: true,
    namedFunction: true,
    security: "modern",
    tags: ["cshake", "cshake128", "sp800-185", "xof", "customizable", "keccak"],
    summary:
      "SHAKE128 plus a customisation string, so two uses of one hash cannot collide by accident.",
  },
  {
    id: "cshake256",
    label: "cSHAKE256",
    category: "SHAKE",
    outputLen: 64,
    blockLen: 136,
    outputMode: "xof",
    customizable: true,
    namedFunction: true,
    security: "modern",
    tags: ["cshake", "cshake256", "sp800-185", "xof", "customizable", "keccak"],
    summary: "cSHAKE at the 256-bit security level.",
  },
  {
    id: "tuplehash128",
    label: "TupleHash128",
    category: "TupleHash",
    outputLen: 32,
    blockLen: 168,
    outputMode: "fixed",
    customizable: true,
    tupleInput: true,
    security: "modern",
    tags: ["tuplehash", "sp800-185", "tuple", "unambiguous", "keccak"],
    summary: "Hashes a list of strings unambiguously: (ab, c) and (abc) are different values.",
  },
  {
    id: "tuplehash256",
    label: "TupleHash256",
    category: "TupleHash",
    outputLen: 64,
    blockLen: 136,
    outputMode: "fixed",
    customizable: true,
    tupleInput: true,
    security: "modern",
    tags: ["tuplehash", "sp800-185", "tuple", "keccak"],
    summary: "TupleHash at the 256-bit security level.",
  },
  {
    id: "tuplehash128xof",
    label: "TupleHashXOF128",
    category: "TupleHash",
    outputLen: 32,
    blockLen: 168,
    outputMode: "xof",
    customizable: true,
    tupleInput: true,
    security: "modern",
    tags: ["tuplehash", "tuplehashxof", "sp800-185", "tuple", "xof", "keccak"],
    summary: "TupleHash128 with an arbitrary output length.",
  },
  {
    id: "tuplehash256xof",
    label: "TupleHashXOF256",
    category: "TupleHash",
    outputLen: 64,
    blockLen: 136,
    outputMode: "xof",
    customizable: true,
    tupleInput: true,
    security: "modern",
    tags: ["tuplehash", "tuplehashxof", "sp800-185", "tuple", "xof", "keccak"],
    summary: "TupleHash256 with an arbitrary output length.",
  },
  {
    id: "parallelhash128",
    label: "ParallelHash128",
    category: "ParallelHash",
    outputLen: 32,
    blockLen: 168,
    outputMode: "fixed",
    customizable: true,
    blockSized: true,
    security: "modern",
    tags: ["parallelhash", "sp800-185", "parallel", "keccak"],
    summary: "Hashes fixed-size blocks independently, then hashes those digests.",
  },
  {
    id: "parallelhash256",
    label: "ParallelHash256",
    category: "ParallelHash",
    outputLen: 64,
    blockLen: 136,
    outputMode: "fixed",
    customizable: true,
    blockSized: true,
    security: "modern",
    tags: ["parallelhash", "sp800-185", "parallel", "keccak"],
    summary: "ParallelHash at the 256-bit security level.",
  },
  {
    id: "parallelhash128xof",
    label: "ParallelHashXOF128",
    category: "ParallelHash",
    outputLen: 32,
    blockLen: 168,
    outputMode: "xof",
    customizable: true,
    blockSized: true,
    security: "modern",
    tags: ["parallelhash", "parallelhashxof", "sp800-185", "parallel", "xof", "keccak"],
    summary: "ParallelHash128 with an arbitrary output length.",
  },
  {
    id: "parallelhash256xof",
    label: "ParallelHashXOF256",
    category: "ParallelHash",
    outputLen: 64,
    blockLen: 136,
    outputMode: "xof",
    customizable: true,
    blockSized: true,
    security: "modern",
    tags: ["parallelhash", "parallelhashxof", "sp800-185", "parallel", "xof", "keccak"],
    summary: "ParallelHash256 with an arbitrary output length.",
  },
  {
    id: "turboshake128",
    label: "TurboSHAKE128",
    category: "TurboSHAKE",
    outputLen: 32,
    blockLen: 168,
    outputMode: "xof",
    domainSeparated: true,
    security: "modern",
    tags: ["turboshake", "turboshake128", "xof", "keccak", "fast"],
    summary: "SHAKE128 with 12 Keccak rounds rather than 24. Roughly twice the speed.",
  },
  {
    id: "turboshake256",
    label: "TurboSHAKE256",
    category: "TurboSHAKE",
    outputLen: 64,
    blockLen: 136,
    outputMode: "xof",
    domainSeparated: true,
    security: "modern",
    tags: ["turboshake", "turboshake256", "xof", "keccak", "fast"],
    summary: "TurboSHAKE at the 256-bit security level.",
  },
  {
    id: "kt128",
    label: "KangarooTwelve (KT128)",
    category: "TurboSHAKE",
    outputLen: 32,
    blockLen: 168,
    outputMode: "xof",
    customizable: true,
    security: "modern",
    tags: ["kangarootwelve", "k12", "kt128", "xof", "keccak", "tree hashing", "fast"],
    summary: "TurboSHAKE128 plus tree hashing, so a long input parallelises.",
  },
  {
    id: "kt256",
    label: "KangarooTwelve (KT256)",
    category: "TurboSHAKE",
    outputLen: 64,
    blockLen: 136,
    outputMode: "xof",
    customizable: true,
    security: "modern",
    tags: ["kangarootwelve", "k12", "kt256", "xof", "keccak", "tree hashing", "fast"],
    summary: "KangarooTwelve at the 256-bit security level.",
  },

  // ── RIPEMD ────────────────────────────────────────────────────────────────
  {
    /**
     * The other three RIPEMD widths, implemented in `@ocs/algos` because no library carries them.
     *
     * All four share one design; 128 and 256 run four rounds where 160 and 320 run five, and the
     * doubled widths keep both lanes' state instead of cross-adding them. None is a truncation of
     * another: RIPEMD-128 is not the first sixteen bytes of RIPEMD-160, and RIPEMD-256 is not
     * RIPEMD-128 extended -- they are separate functions with separate initial states.
     */
    id: "ripemd128",
    label: "RIPEMD-128",
    category: "RIPEMD",
    outputLen: 16,
    blockLen: 64,
    outputMode: "fixed",
    security: "broken",
    tags: ["ripemd", "ripemd128", "digest", "legacy", "broken"],
    summary: "128-bit RIPEMD. A distinct function from RIPEMD-160, not a truncation of it.",
  },
  {
    id: "ripemd256",
    label: "RIPEMD-256",
    category: "RIPEMD",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "legacy",
    tags: ["ripemd", "ripemd256", "digest", "legacy"],
    summary: "256-bit output at RIPEMD-128's security level. Wider, not stronger.",
  },
  {
    id: "ripemd320",
    label: "RIPEMD-320",
    category: "RIPEMD",
    outputLen: 40,
    blockLen: 64,
    outputMode: "fixed",
    security: "legacy",
    tags: ["ripemd", "ripemd320", "digest", "legacy"],
    summary: "320-bit output at RIPEMD-160's security level. Wider, not stronger.",
  },
  {
    id: "ripemd160",
    label: "RIPEMD-160",
    category: "RIPEMD",
    outputLen: 20,
    blockLen: 64,
    outputMode: "fixed",
    security: "legacy",
    tags: ["ripemd", "ripemd160", "digest", "bitcoin", "legacy"],
    summary:
      "160-bit digest. Not broken, but too narrow for new work; used in Bitcoin addresses.",
  },

  // ── Composite ─────────────────────────────────────────────────────────────
  {
    /**
     * MD5 ‖ SHA-1, the 36-byte digest TLS 1.0 and 1.1 signed in their handshakes.
     *
     * Not a hash function but a *construction*: the message is hashed independently by both
     * algorithms and the two digests concatenated. It is here because OpenSSL exposes it as
     * `md5-sha1` and because verifying an old TLS handshake or a pre-1.2 certificate
     * signature needs it — not because anyone should compute one for a new purpose.
     *
     * `blockLen` is 64 because both halves have a 64-byte block; HMAC over this would be
     * well-defined but is not something any standard specifies, so the MAC family does not
     * offer it.
     */
    id: "md5-sha1",
    label: "MD5-SHA1",
    category: "Composite",
    outputLen: 36,
    blockLen: 64,
    outputMode: "fixed",
    security: "broken",
    tags: ["md5-sha1", "md5sha1", "tls", "tls1.0", "tls1.1", "ssl3", "openssl", "legacy"],
    summary:
      "MD5 and SHA-1 of the same message, concatenated — 36 bytes. What TLS 1.0/1.1 signed.",
  },

  // ── BLAKE ─────────────────────────────────────────────────────────────────
  /**
   * BLAKE-224/256/384/512: the original, and a different function from BLAKE2.
   *
   * The SHA-3 finalist that lost to Keccak, and the one whose loss is most often described as
   * unlucky -- it had the largest security margin of the five finalists. Its HAIFA construction with
   * a ChaCha-derived round function is what BLAKE2 then simplified and BLAKE3 restructured, so this
   * is the ancestor rather than an alternative: 14 and 16 rounds where BLAKE2 uses 12 and 10.
   *
   * `legacy` rather than `modern`, and the note says why: nothing is wrong with it, and there is no
   * reason to choose it over its own descendants.
   */
  {
    id: "blake224",
    label: "BLAKE-224",
    category: "BLAKE",
    outputLen: 28,
    blockLen: 64,
    outputMode: "fixed",
    security: "legacy",
    tags: ["blake", "blake1", "blake224", "sha-3 finalist", "haifa", "legacy"],
    summary: "The original BLAKE at 224 bits — a SHA-3 finalist, and BLAKE2's ancestor.",
  },
  {
    id: "blake256",
    label: "BLAKE-256",
    category: "BLAKE",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "legacy",
    tags: ["blake", "blake1", "blake256", "sha-3 finalist", "haifa", "decred", "sia", "legacy"],
    summary: "The original BLAKE at 256 bits, 14 rounds. Still what Decred and Sia mine.",
  },
  {
    id: "blake384",
    label: "BLAKE-384",
    category: "BLAKE",
    outputLen: 48,
    blockLen: 128,
    outputMode: "fixed",
    security: "legacy",
    tags: ["blake", "blake1", "blake384", "sha-3 finalist", "haifa", "legacy"],
    summary: "The original BLAKE at 384 bits, on the 64-bit core.",
  },
  {
    id: "blake512",
    label: "BLAKE-512",
    category: "BLAKE",
    outputLen: 64,
    blockLen: 128,
    outputMode: "fixed",
    security: "legacy",
    tags: ["blake", "blake1", "blake512", "sha-3 finalist", "haifa", "legacy"],
    summary: "The original BLAKE at 512 bits, 16 rounds.",
  },
  {
    id: "blake2b",
    label: "BLAKE2b",
    category: "BLAKE",
    outputLen: 64,
    blockLen: 128,
    outputMode: "parameterized",
    maxOutputLen: 64,
    security: "modern",
    keyed: true,
    saltedPersonalised: true,
    tags: ["blake2", "blake2b", "digest", "rfc7693", "fast", "mac", "keyed", "salt"],
    summary:
      "1 to 64 bytes of output, tuned for 64-bit CPUs. Keyed for a MAC, salted, personalised.",
  },
  {
    id: "blake2s",
    label: "BLAKE2s",
    category: "BLAKE",
    outputLen: 32,
    blockLen: 64,
    outputMode: "parameterized",
    maxOutputLen: 32,
    security: "modern",
    keyed: true,
    saltedPersonalised: true,
    tags: ["blake2", "blake2s", "digest", "rfc7693", "fast", "embedded", "mac", "keyed"],
    summary:
      "1 to 32 bytes of output, tuned for 8- to 32-bit platforms. Keyed, salted, personalised.",
  },
  {
    id: "blake3",
    label: "BLAKE3",
    category: "BLAKE",
    outputLen: 32,
    blockLen: 64,
    outputMode: "xof",
    security: "modern",
    keyed: true,
    contextual: true,
    tags: ["blake3", "digest", "xof", "fast", "parallel", "mac", "keyed", "kdf", "derive_key"],
    summary:
      "Extendable output, the fastest here on large inputs, and three modes: hash, keyed, derive_key.",
  },

  // ── National standards ────────────────────────────────────────────────────
  {
    /**
     * Xoodyak-Hash -- the Cyclist duplex in hash mode, from the Keccak team.
     *
     * The same object the `xoodyak` AEAD tool drives, run unkeyed. Its rate is 16 bytes and Cyclist
     * squeezes, so a longer digest *extends* a shorter one -- unlike KMAC or Skein, where the requested
     * length is bound into the computation.
     *
     * `truncation` is deliberately absent even though that is exactly what an extending squeeze means:
     * the flag exists to disambiguate a *list* of fixed lengths (Tiger's three, HAVAL's five), and the
     * test that reads it indexes `outputLengths`, which an XOF does not have. Every XOF here extends.
     */
    // `xoodyak-hash`, not `xoodyak`: the AEAD in the cipher family already owns that id, and tool
    // ids are global -- `tests/registry.test.ts` fails on a collision, which is how this was caught.
    id: "xoodyak-hash",
    label: "Xoodyak-Hash",
    category: "NIST lightweight",
    outputLen: 32,
    blockLen: 16,
    outputMode: "xof",
    security: "modern",
    tags: ["xoodyak", "xoodoo", "cyclist", "nist lightweight", "lwc", "finalist", "keccak team", "digest"],
    summary: "The Keccak team's lightweight sponge, unkeyed. 256-bit default, and it squeezes.",
  },
  {
    /**
     * Esch256 -- SPARKLE's hash. Add-rotate-XOR with no table anywhere.
     *
     * A 128-bit rate feeding a 384-bit state, which only works because the absorb expands the block
     * through the linear layer and injects it into six words rather than XORing it into four.
     */
    id: "esch256",
    label: "Esch256",
    category: "NIST lightweight",
    outputLen: 32,
    blockLen: 16,
    outputMode: "fixed",
    security: "modern",
    tags: ["esch", "esch256", "sparkle", "schwaemm", "alzette", "nist lightweight", "lwc", "finalist", "arx", "digest"],
    summary: "SPARKLE's 256-bit hash. Add-rotate-XOR, no tables, 384-bit state.",
  },
  {
    /**
     * Esch384 -- the same construction at a 512-bit state and eight injected words.
     *
     * Not a truncation or an extension of Esch256: the state is wider, the permutation runs more steps,
     * and the digest is squeezed in three sixteen-byte pieces rather than two.
     */
    id: "esch384",
    label: "Esch384",
    category: "NIST lightweight",
    outputLen: 48,
    blockLen: 16,
    outputMode: "fixed",
    security: "modern",
    tags: ["esch", "esch384", "sparkle", "alzette", "nist lightweight", "lwc", "finalist", "arx", "digest"],
    summary: "Esch at a 512-bit state and a 384-bit digest. Not a widening of Esch256.",
  },
  {
    /**
     * PHOTON-Beetle-Hash -- and its initial state is the message.
     *
     * The first sixteen bytes are loaded straight into the state rather than absorbed, so there is no
     * initial constant at all. The rate is then four bytes, which is the smallest in this repo and the
     * reason it is slow: a 32-byte state permuted twelve rounds for every four bytes of input.
     */
    // Suffixed for the same reason as `xoodyak-hash`: the AEAD owns `photonbeetle`.
    id: "photonbeetle-hash",
    label: "PHOTON-Beetle-Hash",
    category: "NIST lightweight",
    outputLen: 32,
    // A 4-byte rate. HMAC over it is not offered -- see `HMAC_HASHES` -- for the same reason
    // Ascon-Hash256 is not: the rate caps the useful key material far below the digest width.
    blockLen: 4,
    outputMode: "fixed",
    security: "modern",
    tags: ["photon-beetle", "photonbeetle", "photon", "beetle", "nist lightweight", "lwc", "finalist", "sponge", "digest"],
    summary: "A nibble-oriented AES-shaped sponge. Its first 16 message bytes are the initial state.",
  },
  {
    /**
     * Romulus-H -- a Hirose double-block-length hash over SKINNY-128-384+.
     *
     * Two cipher calls per 32-byte block, one of them with a flipped input bit, both feeding forward the
     * same chaining value. That is what produces a 256-bit hash from a 128-bit block cipher, and it is
     * the construction Romulus-T uses internally to authenticate its own ciphertext.
     */
    id: "romulus-h",
    label: "Romulus-H",
    category: "NIST lightweight",
    outputLen: 32,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["romulus", "romulus-h", "skinny", "hirose", "nist lightweight", "lwc", "finalist", "digest"],
    summary: "A Hirose double-block hash over SKINNY. 256 bits from a 128-bit block cipher.",
  },

  // -- Lightweight sponges -----------------------------------------------------
  //
  // Three hardware-oriented sponges that are *not* NIST lightweight finalists: GIMLI was a round-2
  // candidate, and Quark and PHOTON predate the competition entirely. Their own category rather than
  // being filed under "NIST lightweight", because that heading is a claim about standing.
  {
    /**
     * GIMLI-Hash -- a 384-bit permutation designed for every platform at once.
     *
     * A 3x4 matrix of 32-bit words: the non-linear layer works down each column independently and the
     * only sideways movement is a swap in the top row every second round. That vectorises on 128-bit
     * SIMD, fits four registers on a 32-bit micro, and bitslices on an 8-bit one -- which is the entire
     * argument for the design, and unusual in this neighbourhood where the target is normally a gate
     * count.
     *
     * Two GIMLI-Hash conventions are in circulation and they agree on nothing. This is the paper's and
     * the NIST submission's: `0x01` at the padding position and `0x01` into the *last* byte of the
     * state. FELICS's suite implements a SHAKE-shaped variant instead. See `gimli.ts`.
     */
    id: "gimli",
    label: "GIMLI-Hash",
    category: "Lightweight sponge",
    outputLen: 32,
    blockLen: 16,
    outputMode: "fixed",
    security: "modern",
    tags: [
      "gimli", "gimli-hash", "gimli-24", "ches 2017", "bernstein", "schwabe", "nist lightweight",
      "lwc", "round 2", "sponge", "permutation", "digest",
    ],
    summary: "A 384-bit permutation built to be fast on SIMD, 32-bit and 8-bit alike. 256-bit digest.",
  },
  {
    /**
     * Quark -- the smallest hash here by hardware area, and the slowest by a wide margin in software.
     *
     * A sponge over stream-cipher machinery: two non-linear feedback shift registers and a linear one,
     * clocked `4 * width` times per permutation. u-Quark is 1,379 gate equivalents, which is the point
     * of it -- and its rate is *one byte*, so it spends 544 rounds of Boolean algebra per message byte
     * and runs at roughly 12 KiB/s here against 18 MiB/s for XXH3. That is the algorithm, not the
     * implementation; see `quark.ts` for what is done about it.
     *
     * The four instances are one tool with an instance control, on the `## One tool or many` reasoning:
     * nobody reaches for "s-Quark" without having first decided on Quark. Each carries its own digest
     * width, because for Quark the instance *is* the width -- which is what `variantOutputLen` exists
     * for.
     */
    id: "quark",
    label: "Quark",
    category: "Lightweight sponge",
    // u-Quark's, the default. The other three are on their variant entries.
    outputLen: 17,
    /**
     * u-Quark's rate: one byte.
     *
     * HMAC over Quark is not offered -- see `HMAC_HASHES` -- and this is the clearest case of the
     * reason Ascon-Hash256 is excluded: a one-byte rate caps the useful key material at eight bits.
     */
    blockLen: 1,
    /**
     * `fixed`, not `parameterized`, and that is the honest reading: there is no length control at all.
     * The instance select is the only choice, and each instance produces one width. `variantOutputLen`
     * is what makes the two agree.
     *
     * `truncation` is deliberately absent -- the test that reads it indexes `outputLengths`, which this
     * has none of. The property it would record still holds and is asserted in
     * `tests/algos-lightweight-hash.test.ts`: u-Quark is not a prefix of c-Quark, because the four
     * instances have different IVs, register lengths and round counts.
     */
    outputMode: "fixed",
    variants: [
      { id: "u-quark", label: "u-Quark (64-bit security)", outputLen: 17 },
      { id: "d-quark", label: "d-Quark (80-bit security)", outputLen: 22 },
      { id: "s-quark", label: "s-Quark (112-bit security)", outputLen: 32 },
      { id: "c-quark", label: "c-Quark (160-bit security)", outputLen: 48 },
    ],
    defaultVariant: "u-quark",
    security: "legacy",
    tags: [
      "quark", "u-quark", "uquark", "d-quark", "dquark", "s-quark", "squark", "c-quark", "cquark",
      "ches 2010", "aumasson", "henzen", "knellwolf", "meier", "naya-plasencia", "grain", "katan",
      "sponge", "lightweight", "digest",
    ],
    summary:
      "The smallest hash here in hardware -- 1,379 gates -- and much the slowest in software. Four instances.",
  },
  {
    /**
     * PHOTON-128/16/16 -- a 6x6 grid of nibbles, and nothing stored.
     *
     * The AES-shaped lightweight sponge whose family also produced PHOTON-Beetle. Note it is a
     * *different* permutation from that one's: PHOTON-256 is an 8x8 grid with its own coefficients, so
     * sharing the name is not sharing the function.
     *
     * Its S-box is PRESENT's, its MixColumns matrix is the sixth power of a six-coefficient serial
     * matrix, and its 72 round constants are eighteen numbers -- so the whole algorithm stores nothing
     * and every table is checked against the reference at load. That makes it the strongest instance of
     * the derive-don't-transcribe rule in the hash family.
     */
    id: "photon",
    label: "PHOTON-128/16/16",
    category: "Lightweight sponge",
    outputLen: 16,
    /**
     * A 2-byte rate, the smallest here after PHOTON-Beetle's four.
     *
     * HMAC is not offered, for the same reason: two bytes of rate cannot carry a key.
     */
    blockLen: 2,
    outputMode: "fixed",
    security: "legacy",
    tags: [
      "photon", "photon-128", "photon-128/16/16", "crypto 2011", "guo", "peyrin", "poschmann",
      "present", "nibble", "sponge", "lightweight", "digest",
    ],
    summary: "A 6x6 nibble grid over PRESENT's S-box. 144-bit state, 128-bit digest, nothing stored.",
  },
  {
    /**
     * FSB -- the one hash here whose security reduces to a coding problem rather than to an argument
     * about a permutation. A NIST SHA-3 round-1 submission, withdrawn on performance grounds.
     *
     * `legacy`: no attack, no standard, and nothing else implements it.
     *
     * **Nothing external checks this implementation, and that is stated rather than implied.** There is
     * no published FSB digest anywhere reachable -- `fsbdoc.pdf` contains no test vector and not one hex
     * string of any length, and the submission zip has no KAT directory. What covers it is two
     * independent formulations of the compression required to agree, which is the arrangement
     * `crcReference` gives the CRC engine, plus verification of the *matrix table's* provenance. See
     * `packages/algos/src/fsb.ts`; do not describe it as verified against a vector.
     *
     * It is the only tool in this repo carrying a large committed data blob: 266 KB, the parity of pi's
     * first 2,179,072 fractional decimal digits. That is checkable and is checked on a prefix -- see
     * `fsb-pi.ts` -- which is what makes committing it defensible rather than blind.
     *
     * FSB-48 exists in the reference as a reduced set for testing and is implemented but not offered: a
     * 48-bit digest is not a hash. The five submission sizes are what this tool exposes.
     */
    id: "fsb",
    label: "FSB",
    category: "Syndrome",
    outputLen: 32,
    /**
     * The message bits consumed per round, in bytes, at the default 256-bit size.
     *
     * Genuinely a compression block rather than a sponge rate -- but it *varies with the digest length*
     * (60 bytes at 160 bits, 96 at 256, 155 at 512), which no other entry here does. HMAC is not
     * offered, so nothing reads this for padding.
     */
    blockLen: 96,
    outputMode: "parameterized",
    outputLengths: [20, 28, 32, 48, 64],
    /**
     * Not a truncation: each digest length has its own `r`, so Whirlpool sees a different-width syndrome
     * and FSB-160 is unrelated to FSB-256's first twenty bytes.
     */
    truncation: false,
    security: "legacy",
    tags: [
      "fsb", "fast syndrome based", "syndrome", "sha-3", "round 1", "augot", "finiasz", "gaborit",
      "sendrier", "coding theory", "quasi-cyclic", "whirlpool", "digest",
    ],
    summary:
      "Security reduces to syndrome decoding, not to a permutation. Its matrix comes from the digits of pi.",
  },
  {
    /**
     * RadioGatun[32] -- Daemen's belt-and-mill design, and the direct ancestor of Keccak.
     *
     * A 19-word *mill* doing the nonlinear work and a 13-stage *belt* carrying information forward, each
     * feeding the other. The sponge construction that became SHA-3 grew out of analysing it, which is
     * most of why it is worth having: this is what Keccak looked like one step earlier.
     */
    id: "radiogatun32",
    label: "RadioGatun[32]",
    category: "RadioGatun",
    outputLen: 32,
    // The rate: 13 * 3 words of 4 bytes. Unusually large, and not a power of two.
    blockLen: 156,
    outputMode: "fixed",
    /**
     * `legacy`, and precisely: there is no attack on RadioGatun[32] better than generic, but the
     * designers' own security claim is 2^304 for the 64-bit variant and the 32-bit one is claimed at
     * half that -- and nothing deploys either, so a value produced here is being compared against a
     * reference implementation rather than against a system. Keccak superseded it.
     */
    security: "legacy",
    tags: ["radiogatun", "radiogatun32", "radiogatun[32]", "belt and mill", "daemen", "keccak ancestor", "panama successor", "digest"],
    summary: "Keccak's direct ancestor: a 19-word mill and a 13-stage belt, at 32-bit words.",
  },
  {
    /**
     * RadioGatun[64] -- the same construction at 64-bit words, and the designers' preferred size.
     *
     * Not a widening in any meaningful sense: it is the *same* implementation with the rotation amounts
     * reduced modulo 64 instead of 32. That single difference is why one function serves both, and why
     * a version that reduced by 32 throughout would be correct at one width and wrong at the other.
     */
    id: "radiogatun64",
    label: "RadioGatun[64]",
    category: "RadioGatun",
    outputLen: 32,
    blockLen: 312,
    outputMode: "fixed",
    security: "legacy",
    tags: ["radiogatun", "radiogatun64", "radiogatun[64]", "belt and mill", "daemen", "64-bit", "digest"],
    summary: "RadioGatun at 64-bit words -- the same code, rotations reduced mod 64.",
  },
  {
    /**
     * Panama -- the 1998 design RadioGatun replaced, and a rare case of a hash that is *broken*.
     *
     * Rijmen, Van Rompay, Preneel and Vandewalle found a collision attack in 2001, and Daemen and Van
     * Assche improved it to 2^6 evaluations in 2007 -- which is a collision you can find by hand. It is
     * here to reproduce values, and its posture says so.
     *
     * The interesting structural fact: it is a 17-word mill over a *32-stage* buffer, so the state is a
     * kilobyte and a short message never fills it. Only a long input reaches the point where the buffer
     * update reads what it wrote 32 blocks earlier -- which is why the million-'a' vector matters more
     * here than for most hashes.
     */
    id: "panama",
    label: "Panama",
    category: "Panama",
    outputLen: 32,
    blockLen: 32,
    outputMode: "fixed",
    /**
     * `broken`, and this one is not a judgement call: a 2^6 collision attack is published and confirmed.
     * `H001` reads this.
     */
    security: "broken",
    tags: ["panama", "belt and mill", "daemen", "clapp", "broken", "collision", "digest"],
    summary: "The 1998 belt-and-mill hash. Collisions cost 2^6 evaluations; kept to reproduce values.",
  },
  {
    /**
     * Kupyna-256 -- DSTU 7564:2014, Ukraine's national hash, on Kalyna's tables.
     *
     * The two Ukrainian standards were designed together and share their primitives exactly: Kupyna's
     * four S-boxes and its MixColumns *are* DSTU 7624's, which this repo already has for the Kalyna
     * cipher. So `kupyna.ts` stores nothing -- the eight lookup tables are derived at load, and Kalyna's
     * own published vectors are what stands behind both.
     *
     * The compression is Groestl-shaped rather than Streebog-shaped: `state ^= P(state ^ m) ^ Q(m)`, two
     * independent permutations of the same block. P XORs its round constant in and Q *adds* one that
     * counts down, which is the detail that a version treating them as variants of each other gets wrong.
     */
    id: "kupyna256",
    label: "Kupyna-256",
    category: "Kupyna",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["kupyna", "kupyna-256", "dstu 7564", "dstu7564", "ukraine", "national standard", "kalyna", "digest"],
    summary: "Ukraine's DSTU 7564 hash at 256 bits, built on Kalyna's own S-boxes.",
  },
  {
    /**
     * Kupyna-384. The 1024-bit state, truncated -- and the truncation is from the *tail*.
     *
     * The digest is the last six columns of the eight, so Kupyna-384 genuinely is the trailing 48 bytes
     * of Kupyna-512's digest. `truncation: true` records that, and `tests/algos-beltmill.test.ts` asserts
     * both halves: 384 is a suffix of 512, and 256 is unrelated to either because it runs a different
     * permutation over half the state.
     */
    id: "kupyna384",
    label: "Kupyna-384",
    category: "Kupyna",
    outputLen: 48,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["kupyna", "kupyna-384", "dstu 7564", "dstu7564", "ukraine", "national standard", "digest"],
    summary: "Kupyna over a 1024-bit state, truncated to 384 bits from the tail.",
  },
  {
    id: "kupyna512",
    label: "Kupyna-512",
    category: "Kupyna",
    outputLen: 64,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["kupyna", "kupyna-512", "dstu 7564", "dstu7564", "ukraine", "national standard", "digest"],
    summary: "Kupyna at 512 bits: a 1024-bit state and fourteen rounds.",
  },
  {
    /**
     * HAS-160 -- the Korean TTA standard TTAS.KO-12.0011, and what KCDSA signs with.
     *
     * SHA-1's shape with two changes: a wider message expansion -- twenty derived words rather than a
     * rolling XOR -- and a per-round rotation of the B register instead of a fixed one. No tables.
     */
    id: "has160",
    label: "HAS-160",
    category: "HAS-160",
    outputLen: 20,
    blockLen: 64,
    outputMode: "fixed",
    /**
     * `legacy` on the width rather than on a published break. 160 bits is 80 bits of collision
     * resistance, which is where SHA-1 was retired from -- and Korea's own KS X 1213 moved to SHA-2. The
     * best published attack reaches 65 of the 80 rounds, so this is not `broken`; saying so would be the
     * overclaim `M003` exists to avoid.
     */
    security: "legacy",
    tags: ["has-160", "has160", "kcdsa", "tta", "ttas.ko-12.0011", "korea", "national standard", "digest"],
    summary: "Korea's TTA standard, and what KCDSA signs. SHA-1's shape, wider expansion.",
  },
  {
    /**
     * LSH-224 -- the Korean standard KS X 3262, and what KCDSA moved to after HAS-160.
     *
     * A wide-pipe ARX design with no S-box: the chaining value is *twice* the digest width, and each of
     * twenty-six steps adds, rotates, XORs a constant, adds again, rotates again and permutes sixteen
     * words. The message is expanded on the fly rather than scheduled up front.
     *
     * Not a truncation of LSH-256 -- it has its own initial chaining value, so it is a different function
     * over the same compression. `truncation` is absent on all four LSH entries for that reason.
     */
    id: "lsh224",
    label: "LSH-224",
    category: "LSH",
    outputLen: 28,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["lsh", "lsh-224", "lsh-256-224", "ks x 3262", "kisa", "korea", "national standard", "arx", "digest"],
    summary: "Korea's KS X 3262 at 224 bits. Wide-pipe ARX, no tables, 128-byte block.",
  },
  {
    id: "lsh256",
    label: "LSH-256",
    category: "LSH",
    outputLen: 32,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["lsh", "lsh-256", "ks x 3262", "kisa", "korea", "national standard", "arx", "digest"],
    summary: "LSH at 256 bits: a 512-bit chaining value over a 128-byte block, twenty-six steps.",
  },
  {
    /**
     * LSH-384. The 512-bit family: 64-bit words, twenty-eight steps, a 256-byte block.
     *
     * Its gamma rotation covers *seven* words where LSH-256's covers six, because `gamma[7]` is 56 at this
     * width and 0 at the narrower one. That single difference is why the two families are two engines
     * rather than one parameterised path -- see `lsh.ts`.
     */
    id: "lsh384",
    label: "LSH-384",
    category: "LSH",
    outputLen: 48,
    blockLen: 256,
    outputMode: "fixed",
    security: "modern",
    tags: ["lsh", "lsh-384", "lsh-512-384", "ks x 3262", "kisa", "korea", "national standard", "arx", "digest"],
    summary: "LSH's 512-bit family truncated to 384. Sixty-four-bit words, 256-byte block.",
  },
  {
    id: "lsh512",
    label: "LSH-512",
    category: "LSH",
    outputLen: 64,
    blockLen: 256,
    outputMode: "fixed",
    security: "modern",
    tags: ["lsh", "lsh-512", "ks x 3262", "kisa", "korea", "national standard", "arx", "digest"],
    summary: "LSH at 512 bits: a 1024-bit chaining value, twenty-eight steps, no tables.",
  },
  {
    id: "sm3",
    label: "SM3",
    category: "SM",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["sm3", "digest", "oscca", "china", "gmt", "gb-t-32905", "sm2"],
    summary:
      "256-bit digest from GB/T 32905-2016 — China's national standard, and what SM2 signs with.",
  },
  {
    /**
     * Six of PHP's names behind two controls.
     *
     * Tiger's digest length and pass count are arguments to one function, not six functions: the
     * 128- and 160-bit forms are literal truncations of the 192-bit digest -- which is what
     * `truncation: true` records -- and the pass count is a loop bound. Splitting that into six
     * sidebar entries said nothing the two dropdowns do not say better.
     *
     * Tiger2 stays its own tool. It differs only in the padding byte, but PHP, Jacksum and RHash
     * all name it separately, and folding it into a third dropdown would hide it.
     */
    id: "tiger",
    label: "Tiger",
    category: "Tiger",
    outputLen: 24,
    blockLen: 64,
    outputMode: "parameterized",
    outputLengths: [16, 20, 24],
    truncation: true,
    passes: [3, 4],
    defaultPasses: 3,
    security: "legacy",
    tags: [
      "tiger", "tiger128,3", "tiger160,3", "tiger192,3", "tiger128,4", "tiger160,4", "tiger192,4",
      "tiger128", "tiger160", "tiger192", "gnutella", "magnet", "tth", "php", "digest",
    ],
    summary: "192-bit Tiger, truncatable to 160 or 128, over 3 or 4 passes.",
  },
  {
    id: "tiger2",
    label: "Tiger2",
    category: "Tiger",
    outputLen: 24,
    blockLen: 64,
    outputMode: "fixed",
    security: "legacy",
    tags: ["tiger2", "tiger", "tiger2-192", "digest", "legacy"],
    summary: "Tiger with the conventional 0x80 padding byte. Unrelated output, same construction.",
  },
  {
    /**
     * Fifteen functions behind two controls.
     *
     * HAVAL is a three-by-five grid, and neither axis is a truncation: the round function's
     * permutation differs per pass count, and each digest length has its own tailoring function
     * folding the 256-bit state down. So all fifteen genuinely are distinct functions -- which is a
     * fact about the implementation, and was previously (wrongly) given as the reason for fifteen
     * sidebar entries. AES-GCM and AES-CBC are distinct functions in one tool too; a CRC-32 model
     * and a CRC-32/BZIP2 model are distinct functions in one tool with a 67-model dropdown. What
     * decides the question is whether someone thinks of them as one thing with a knob, and here
     * they plainly do.
     *
     * `security` is the worst of the fifteen, because a badge cannot say "depends". `H001` reads
     * `effectiveSecurity` instead, so the Checks panel speaks about the configuration actually
     * selected -- which is the part a reader can act on.
     */
    id: "haval",
    label: "HAVAL",
    category: "HAVAL",
    outputLen: 32,
    blockLen: 128,
    outputMode: "parameterized",
    outputLengths: [16, 20, 24, 28, 32],
    passes: [3, 4, 5],
    /**
     * Three, which is what every other implementation defaults to.
     *
     * Not the safest choice -- three-pass HAVAL has practical collisions and `H001` says so, with a
     * fix that raises it to five. But this tool exists to reproduce stored values, and Crypto++,
     * Jacksum and mhash all default to three passes, so opening on five would give the wrong answer
     * on first load to everyone who came here with a HAVAL digest to check. Prefer a warning to a
     * default nothing else shares.
     */
    defaultPasses: 3,
    /** Fewer than five passes has a practical collision attack. Read by `H006`. */
    brokenBelowPasses: 5,
    security: "broken",
    tags: [
      "haval", "haval128,3", "haval160,3", "haval192,3", "haval224,3", "haval256,3", "haval128,4",
      "haval160,4", "haval192,4", "haval224,4", "haval256,4", "haval128,5", "haval160,5",
      "haval192,5", "haval224,5", "haval256,5", "haval128", "haval160", "haval192", "haval224",
      "haval256", "php", "digest",
    ],
    summary:
      "HAVAL over 3, 4 or 5 passes at five digest lengths -- fifteen distinct functions, two controls.",
  },
  {
    id: "snefru",
    label: "Snefru-256",
    category: "Snefru",
    outputLen: 32,
    blockLen: 32,
    outputMode: "fixed",
    security: "legacy",
    tags: ["snefru", "snefru256", "merkle", "xerox", "php", "digest"],
    summary: "Merkle's 1990 hash, eight passes, 256 bits. PHP's `snefru` and `snefru256` alike.",
  },
  {
    id: "gost94",
    label: "GOST R 34.11-94",
    category: "GOST",
    outputLen: 32,
    blockLen: 32,
    outputMode: "fixed",
    security: "legacy",
    tags: ["gost", "gost 34.11-94", "gost 28147-89", "russia", "php", "digest", "legacy"],
    summary: "The 1994 Russian standard, test S-boxes. Superseded by Streebog — see the two entries above.",
  },
  {
    id: "gost94-crypto",
    label: "GOST R 34.11-94 (CryptoPro)",
    category: "GOST",
    outputLen: 32,
    blockLen: 32,
    outputMode: "fixed",
    security: "legacy",
    tags: [
      "gost",
      "gost-crypto",
      "cryptopro",
      "rfc 4357",
      "gost 34.11-94",
      "russia",
      "php",
      "digest",
    ],
    summary: "GOST R 34.11-94 with the CryptoPro parameter set — the one deployments used.",
  },
  {
    id: "fnv132",
    label: "FNV-1 (32-bit)",
    category: "FNV",
    outputLen: 4,
    // FNV consumes one byte at a time; there is no compression block to report.
    blockLen: 1,
    outputMode: "fixed",
    security: "not-a-mac",
    tags: ["fnv", "fnv-1", "fnv132", "php", "non-cryptographic", "hash table"],
    summary: "Fowler–Noll–Vo, 32-bit. Multiply then XOR — the original ordering.",
  },
  {
    id: "fnv1a32",
    label: "FNV-1a (32-bit)",
    category: "FNV",
    outputLen: 4,
    blockLen: 1,
    outputMode: "fixed",
    security: "not-a-mac",
    tags: ["fnv", "fnv-1a", "fnv1a32", "php", "non-cryptographic", "hash table"],
    summary: "Fowler–Noll–Vo 1a, 32-bit. XOR then multiply — the better of the two.",
  },
  {
    id: "fnv164",
    label: "FNV-1 (64-bit)",
    category: "FNV",
    outputLen: 8,
    blockLen: 1,
    outputMode: "fixed",
    security: "not-a-mac",
    tags: ["fnv", "fnv-1", "fnv164", "php", "non-cryptographic", "hash table"],
    summary: "Fowler–Noll–Vo, 64-bit.",
  },
  {
    id: "fnv1a64",
    label: "FNV-1a (64-bit)",
    category: "FNV",
    outputLen: 8,
    blockLen: 1,
    outputMode: "fixed",
    security: "not-a-mac",
    tags: ["fnv", "fnv-1a", "fnv1a64", "php", "non-cryptographic", "hash table"],
    summary: "Fowler–Noll–Vo 1a, 64-bit. The widest of the four PHP offers.",
  },
  {
    id: "joaat",
    label: "Jenkins one-at-a-time",
    category: "Jenkins",
    outputLen: 4,
    blockLen: 1,
    outputMode: "fixed",
    security: "not-a-mac",
    tags: ["joaat", "jenkins", "one-at-a-time", "php", "non-cryptographic", "hash table"],
    summary: "Bob Jenkins's one-at-a-time hash, 32-bit. PHP's `joaat`.",
  },
  {
    id: "murmur3a",
    label: "MurmurHash3 (32-bit)",
    category: "MurmurHash",
    outputLen: 4,
    // MurmurHash3's block, not a compression function's: 4 bytes for the 32-bit variant.
    blockLen: 4,
    outputMode: "fixed",
    security: "not-a-mac",
    tags: ["murmur", "murmur3", "murmur3a", "x86_32", "php", "non-cryptographic"],
    summary: "MurmurHash3 x86_32, PHP's `murmur3a`. The 32-bit one.",
  },
  {
    id: "murmur3c",
    label: "MurmurHash3 (x86 128-bit)",
    category: "MurmurHash",
    outputLen: 16,
    blockLen: 16,
    outputMode: "fixed",
    security: "not-a-mac",
    tags: ["murmur", "murmur3", "murmur3c", "x86_128", "php", "non-cryptographic"],
    summary: "MurmurHash3 x86_128, PHP's `murmur3c`. Four 32-bit lanes.",
  },
  {
    id: "murmur3f",
    label: "MurmurHash3 (x64 128-bit)",
    category: "MurmurHash",
    outputLen: 16,
    blockLen: 16,
    outputMode: "fixed",
    security: "not-a-mac",
    tags: ["murmur", "murmur3", "murmur3f", "x64_128", "php", "non-cryptographic"],
    summary: "MurmurHash3 x64_128, PHP's `murmur3f`. Two 64-bit lanes.",
  },
  {
    id: "skein256",
    label: "Skein-256",
    category: "Skein",
    outputLen: 32,
    blockLen: 32,
    outputMode: "parameterized",
    security: "modern",
    tags: ["skein", "threefish", "sha-3 finalist", "nist", "schneier", "digest"],
    summary: "The 256-bit-state Skein, built on Threefish-256. Any output length you ask for.",
  },
  {
    id: "skein512",
    label: "Skein-512",
    category: "Skein",
    outputLen: 64,
    blockLen: 64,
    outputMode: "parameterized",
    security: "modern",
    tags: ["skein", "threefish", "sha-3 finalist", "nist", "schneier", "digest", "skeinsum"],
    summary: "Skein's primary variant: 512-bit state, Threefish-512, arbitrary output length.",
  },
  {
    id: "skein1024",
    label: "Skein-1024",
    category: "Skein",
    outputLen: 128,
    blockLen: 128,
    outputMode: "parameterized",
    security: "modern",
    tags: ["skein", "threefish", "sha-3 finalist", "nist", "schneier", "digest"],
    summary: "The 1024-bit-state Skein. Eighty rounds, and the widest state the spec defines.",
  },
  {
    id: "groestl224",
    label: "Groestl-224",
    category: "Groestl",
    outputLen: 28,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["groestl", "grostl", "sha-3 finalist", "nist", "aes", "wide pipe", "digest"],
    summary: "SHA-3 finalist built from AES's S-box. 512-bit state, 10 rounds.",
  },
  {
    id: "groestl256",
    label: "Groestl-256",
    category: "Groestl",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["groestl", "grostl", "sha-3 finalist", "nist", "aes", "wide pipe", "digest"],
    summary: "SHA-3 finalist built from AES's S-box. 512-bit state, 10 rounds.",
  },
  {
    id: "groestl384",
    label: "Groestl-384",
    category: "Groestl",
    outputLen: 48,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["groestl", "grostl", "sha-3 finalist", "nist", "aes", "wide pipe", "digest"],
    summary: "SHA-3 finalist built from AES's S-box. 1024-bit state, 14 rounds.",
  },
  {
    id: "groestl512",
    label: "Groestl-512",
    category: "Groestl",
    outputLen: 64,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["groestl", "grostl", "sha-3 finalist", "nist", "aes", "wide pipe", "digest"],
    summary: "SHA-3 finalist built from AES's S-box. 1024-bit state, 14 rounds.",
  },
  {
    id: "jh224",
    label: "JH-224",
    category: "JH",
    outputLen: 28,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["jh", "sha-3 finalist", "nist", "hongjun wu", "bitslice", "digest"],
    summary: "SHA-3 finalist with a 1024-bit state and a bitsliced S-box pair.",
  },
  {
    id: "jh256",
    label: "JH-256",
    category: "JH",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["jh", "sha-3 finalist", "nist", "hongjun wu", "bitslice", "digest"],
    summary: "SHA-3 finalist with a 1024-bit state and a bitsliced S-box pair.",
  },
  {
    id: "jh384",
    label: "JH-384",
    category: "JH",
    outputLen: 48,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["jh", "sha-3 finalist", "nist", "hongjun wu", "bitslice", "digest"],
    summary: "SHA-3 finalist with a 1024-bit state and a bitsliced S-box pair.",
  },
  {
    id: "jh512",
    label: "JH-512",
    category: "JH",
    outputLen: 64,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["jh", "sha-3 finalist", "nist", "hongjun wu", "bitslice", "digest"],
    summary: "SHA-3 finalist with a 1024-bit state and a bitsliced S-box pair.",
  },
  {
    id: "cubehash224",
    label: "CubeHash-224",
    category: "CubeHash",
    outputLen: 28,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["cubehash", "bernstein", "sha-3 candidate", "nist", "digest"],
    summary: "Bernstein's SHA-3 candidate. No tables and no constants at all.",
  },
  {
    id: "cubehash256",
    label: "CubeHash-256",
    category: "CubeHash",
    outputLen: 32,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["cubehash", "bernstein", "sha-3 candidate", "nist", "digest"],
    summary: "Bernstein's SHA-3 candidate. No tables and no constants at all.",
  },
  {
    id: "cubehash384",
    label: "CubeHash-384",
    category: "CubeHash",
    outputLen: 48,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["cubehash", "bernstein", "sha-3 candidate", "nist", "digest"],
    summary: "Bernstein's SHA-3 candidate. No tables and no constants at all.",
  },
  {
    id: "cubehash512",
    label: "CubeHash-512",
    category: "CubeHash",
    outputLen: 64,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["cubehash", "bernstein", "sha-3 candidate", "nist", "digest"],
    summary: "Bernstein's SHA-3 candidate. No tables and no constants at all.",
  },
  {
    id: "luffa224",
    label: "Luffa-224",
    category: "Luffa",
    outputLen: 28,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["luffa", "sha-3 candidate", "nist", "sponge", "digest"],
    summary: "SHA-3 candidate with 3 independent 256-bit lanes. 32-byte blocks.",
  },
  {
    id: "luffa256",
    label: "Luffa-256",
    category: "Luffa",
    outputLen: 32,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["luffa", "sha-3 candidate", "nist", "sponge", "digest"],
    summary: "SHA-3 candidate with 3 independent 256-bit lanes. 32-byte blocks.",
  },
  {
    id: "luffa384",
    label: "Luffa-384",
    category: "Luffa",
    outputLen: 48,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["luffa", "sha-3 candidate", "nist", "sponge", "digest"],
    summary: "SHA-3 candidate with 4 independent 256-bit lanes. 32-byte blocks.",
  },
  {
    id: "luffa512",
    label: "Luffa-512",
    category: "Luffa",
    outputLen: 64,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["luffa", "sha-3 candidate", "nist", "sponge", "digest"],
    summary: "SHA-3 candidate with 5 independent 256-bit lanes. 32-byte blocks.",
  },
  {
    id: "fugue224",
    label: "Fugue-224",
    category: "Fugue",
    outputLen: 28,
    blockLen: 4,
    outputMode: "fixed",
    security: "modern",
    tags: ["fugue", "sha-3 candidate", "nist", "ibm", "aes", "digest"],
    summary: "SHA-3 candidate over a ring of 30 columns. One word absorbed per round.",
  },
  {
    id: "fugue256",
    label: "Fugue-256",
    category: "Fugue",
    outputLen: 32,
    blockLen: 4,
    outputMode: "fixed",
    security: "modern",
    tags: ["fugue", "sha-3 candidate", "nist", "ibm", "aes", "digest"],
    summary: "SHA-3 candidate over a ring of 30 columns. One word absorbed per round.",
  },
  {
    id: "fugue384",
    label: "Fugue-384",
    category: "Fugue",
    outputLen: 48,
    blockLen: 4,
    outputMode: "fixed",
    security: "modern",
    tags: ["fugue", "sha-3 candidate", "nist", "ibm", "aes", "digest"],
    summary: "SHA-3 candidate over a ring of 36 columns. One word absorbed per round.",
  },
  {
    id: "fugue512",
    label: "Fugue-512",
    category: "Fugue",
    outputLen: 64,
    blockLen: 4,
    outputMode: "fixed",
    security: "modern",
    tags: ["fugue", "sha-3 candidate", "nist", "ibm", "aes", "digest"],
    summary: "SHA-3 candidate over a ring of 36 columns. One word absorbed per round.",
  },
  {
    id: "shavite224",
    label: "SHAvite-3-224",
    category: "SHAvite-3",
    outputLen: 28,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["shavite", "shavite-3", "sha-3 candidate", "nist", "aes", "davies-meyer", "digest"],
    summary: "SHA-3 candidate built from AES rounds. 6 Feistel rounds, 64-byte blocks.",
  },
  {
    id: "shavite256",
    label: "SHAvite-3-256",
    category: "SHAvite-3",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["shavite", "shavite-3", "sha-3 candidate", "nist", "aes", "davies-meyer", "digest"],
    summary: "SHA-3 candidate built from AES rounds. 6 Feistel rounds, 64-byte blocks.",
  },
  {
    id: "shavite384",
    label: "SHAvite-3-384",
    category: "SHAvite-3",
    outputLen: 48,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["shavite", "shavite-3", "sha-3 candidate", "nist", "aes", "davies-meyer", "digest"],
    summary: "SHA-3 candidate built from AES rounds. 14 Feistel rounds, 128-byte blocks.",
  },
  {
    /** The shortest of the five. Its initial values are covered by one published vector, not eighteen. */
    id: "shabal192",
    label: "Shabal-192",
    category: "Shabal",
    outputLen: 24,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["shabal", "sha-3 candidate", "nist", "saphir", "digest"],
    summary: "SHA-3 candidate with a stream-cipher shape. 64-byte blocks, 192-bit digest.",
  },
  {
    id: "shabal224",
    label: "Shabal-224",
    category: "Shabal",
    outputLen: 28,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["shabal", "sha-3 candidate", "nist", "saphir", "digest"],
    summary: "SHA-3 candidate with a stream-cipher shape. 64-byte blocks, 224-bit digest.",
  },
  {
    id: "shabal256",
    label: "Shabal-256",
    category: "Shabal",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["shabal", "sha-3 candidate", "nist", "saphir", "digest"],
    summary: "SHA-3 candidate with a stream-cipher shape. 64-byte blocks, 256-bit digest.",
  },
  {
    id: "shabal384",
    label: "Shabal-384",
    category: "Shabal",
    outputLen: 48,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["shabal", "sha-3 candidate", "nist", "saphir", "digest"],
    summary: "SHA-3 candidate with a stream-cipher shape. 64-byte blocks, 384-bit digest.",
  },
  {
    id: "shabal512",
    label: "Shabal-512",
    category: "Shabal",
    outputLen: 64,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["shabal", "sha-3 candidate", "nist", "saphir", "digest"],
    summary: "SHA-3 candidate with a stream-cipher shape. 64-byte blocks, 512-bit digest.",
  },
    /**
     * ECHO's block is *larger* at the shorter digest lengths -- 192 bytes at 224 and 256, 128 at 384
     * and 512 -- because the 4x4 grid of 128-bit words is split between chaining value and message,
     * and the wide variants keep twice as much chaining value. That reads backwards and is correct.
     */
  {
    id: "echo224",
    label: "ECHO-224",
    category: "ECHO",
    outputLen: 28,
    blockLen: 192,
    outputMode: "fixed",
    security: "modern",
    tags: ["echo", "sha-3 candidate", "nist", "aes", "wide pipe", "digest"],
    summary: "SHA-3 candidate: two AES rounds per word over a 4x4 grid. 192-byte blocks.",
  },
  {
    id: "echo256",
    label: "ECHO-256",
    category: "ECHO",
    outputLen: 32,
    blockLen: 192,
    outputMode: "fixed",
    security: "modern",
    tags: ["echo", "sha-3 candidate", "nist", "aes", "wide pipe", "digest"],
    summary: "SHA-3 candidate: two AES rounds per word over a 4x4 grid. 192-byte blocks.",
  },
  {
    id: "echo384",
    label: "ECHO-384",
    category: "ECHO",
    outputLen: 48,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["echo", "sha-3 candidate", "nist", "aes", "wide pipe", "digest"],
    summary: "SHA-3 candidate: two AES rounds per word over a 4x4 grid. 128-byte blocks.",
  },
  {
    id: "echo512",
    label: "ECHO-512",
    category: "ECHO",
    outputLen: 64,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["echo", "sha-3 candidate", "nist", "aes", "wide pipe", "digest"],
    summary: "SHA-3 candidate: two AES rounds per word over a 4x4 grid. 128-byte blocks.",
  },
    /**
     * `blockLen` really is 4 -- the smallest block of any hash in this repo by a factor of eight.
     * Hamsi expands four bytes into eight 32-bit words through a linear code and runs three rounds of
     * a Serpent-derived permutation on the result, so the "block" is tiny and the work per byte is
     * large. Nothing reads this number yet; HMAC is not offered over Hamsi, since the submission
     * publishes no keyed construction and no HMAC-Hamsi value exists to check against.
     */
  {
    id: "hamsi224",
    label: "Hamsi-224",
    category: "Hamsi",
    outputLen: 28,
    blockLen: 4,
    outputMode: "fixed",
    security: "modern",
    tags: ["hamsi", "sha-3 candidate", "nist", "serpent", "linear code", "digest"],
    summary: "SHA-3 candidate: a 4-byte block expanded through a linear code, then Serpent rounds.",
  },
  {
    id: "hamsi256",
    label: "Hamsi-256",
    category: "Hamsi",
    outputLen: 32,
    blockLen: 4,
    outputMode: "fixed",
    security: "modern",
    tags: ["hamsi", "sha-3 candidate", "nist", "serpent", "linear code", "digest"],
    summary: "SHA-3 candidate: a 4-byte block expanded through a linear code, then Serpent rounds.",
  },
  {
    id: "hamsi384",
    label: "Hamsi-384",
    category: "Hamsi",
    outputLen: 48,
    blockLen: 8,
    outputMode: "fixed",
    security: "modern",
    tags: ["hamsi", "sha-3 candidate", "nist", "serpent", "linear code", "digest"],
    summary: "SHA-3 candidate: a 8-byte block expanded through a linear code, then Serpent rounds.",
  },
  {
    id: "hamsi512",
    label: "Hamsi-512",
    category: "Hamsi",
    outputLen: 64,
    blockLen: 8,
    outputMode: "fixed",
    security: "modern",
    tags: ["hamsi", "sha-3 candidate", "nist", "serpent", "linear code", "digest"],
    summary: "SHA-3 candidate: a 8-byte block expanded through a linear code, then Serpent rounds.",
  },
    /**
     * The only algorithm here whose message expansion is a number-theoretic transform: an FFT over
     * GF(257) turns the block into four times as many message words as it has bytes.
     */
  {
    id: "simd224",
    label: "SIMD-224",
    category: "SIMD",
    outputLen: 28,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["simd", "sha-3 candidate", "nist", "ntt", "fft", "digest"],
    summary: "SHA-3 candidate: an NTT over GF(257) expands the block. 64-byte blocks.",
  },
  {
    id: "simd256",
    label: "SIMD-256",
    category: "SIMD",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["simd", "sha-3 candidate", "nist", "ntt", "fft", "digest"],
    summary: "SHA-3 candidate: an NTT over GF(257) expands the block. 64-byte blocks.",
  },
  {
    id: "simd384",
    label: "SIMD-384",
    category: "SIMD",
    outputLen: 48,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["simd", "sha-3 candidate", "nist", "ntt", "fft", "digest"],
    summary: "SHA-3 candidate: an NTT over GF(257) expands the block. 128-byte blocks.",
  },
  {
    id: "simd512",
    label: "SIMD-512",
    category: "SIMD",
    outputLen: 64,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["simd", "sha-3 candidate", "nist", "ntt", "fft", "digest"],
    summary: "SHA-3 candidate: an NTT over GF(257) expands the block. 128-byte blocks.",
  },
  {
    /**
     * The only member of its family: STB defines belt-hash at 256 bits and nowhere else.
     *
     * `blockLen` is 32 rather than 64. That is the standard's block, and it matters here because
     * HMAC would pad to it -- BelT has its own keyed construction (belt-hmac) and this repo does
     * not offer HMAC over it, so nothing reads that number yet. It is right anyway.
     */
    id: "belt-hash",
    label: "BelT-Hash",
    category: "BelT",
    outputLen: 32,
    blockLen: 32,
    outputMode: "fixed",
    security: "modern",
    tags: ["belt", "belt-hash", "stb", "stb 34.101.31", "belarus", "national standard", "digest"],
    summary:
      "STB 34.101.31, the Belarusian national hash. 256 bits, built from BelT's block cipher.",
  },
  {
    id: "shavite512",
    label: "SHAvite-3-512",
    category: "SHAvite-3",
    outputLen: 64,
    blockLen: 128,
    outputMode: "fixed",
    security: "modern",
    tags: ["shavite", "shavite-3", "sha-3 candidate", "nist", "aes", "davies-meyer", "digest"],
    summary: "SHA-3 candidate built from AES rounds. 14 Feistel rounds, 128-byte blocks.",
  },
  {
    id: "asconhash256",
    label: "Ascon-Hash256",
    category: "Ascon",
    outputLen: 32,
    blockLen: 8,
    outputMode: "fixed",
    security: "modern",
    tags: [
      "ascon",
      "ascon-hash256",
      "nist",
      "sp 800-232",
      "lightweight",
      "sponge",
      "iot",
      "digest",
    ],
    summary:
      "NIST's lightweight hash, SP 800-232. A 320-bit sponge chosen for constrained devices.",
  },
  {
    id: "asconxof128",
    label: "Ascon-XOF128",
    category: "Ascon",
    outputLen: 32,
    blockLen: 8,
    outputMode: "xof",
    security: "modern",
    tags: ["ascon", "ascon-xof128", "xof", "nist", "sp 800-232", "lightweight", "sponge"],
    summary: "Extendable output from the Ascon permutation. Ask for as many bytes as you need.",
  },
  {
    id: "streebog512",
    label: "Streebog-512",
    category: "Streebog",
    outputLen: 64,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: [
      "streebog",
      "gost",
      "gost r 34.11-2012",
      "rfc 6986",
      "russia",
      "national standard",
      "digest",
    ],
    summary:
      "512-bit digest from GOST R 34.11-2012 — Russia's national standard, and what GOST signatures hash with.",
  },
  {
    id: "streebog256",
    label: "Streebog-256",
    category: "Streebog",
    outputLen: 32,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: [
      "streebog",
      "gost",
      "gost r 34.11-2012",
      "rfc 6986",
      "russia",
      "national standard",
      "digest",
    ],
    summary: "256-bit digest from GOST R 34.11-2012, with its own IV rather than a truncation.",
  },
  {
    id: "whirlpool",
    label: "Whirlpool",
    category: "Whirlpool",
    outputLen: 64,
    blockLen: 64,
    outputMode: "fixed",
    security: "modern",
    tags: ["whirlpool", "digest", "iso", "10118-3", "nessie", "truecrypt"],
    summary:
      "512-bit digest from ISO/IEC 10118-3, built from a 512-bit AES-like cipher. Sound, and slow.",
  },

  // ── Non-cryptographic ─────────────────────────────────────────────────────
  {
    /**
     * The five families added alongside xxHash and MurmurHash3. All `not-a-mac`, all here because
     * reproducing a value some other program printed is a real thing to need.
     *
     * Each is one tool rather than three or four, because in every case the widths and variants are
     * knobs on one submission -- nobody reaches for "MetroHash64 variant 2" without having decided on
     * MetroHash first. The old names are all tags, so searching finds them.
     */
    id: "cityhash",
    label: "CityHash",
    category: "CityHash",
    outputLen: 8,
    // CityHash64's long path reads 64-byte blocks. The 32-bit form has no block at all -- it steps 20
    // bytes at a time -- and the 128-bit form consumes 128; 64 is the one worth reporting.
    blockLen: 64,
    outputMode: "parameterized",
    outputLengths: [4, 8, 16],
    truncation: false,
    security: "not-a-mac",
    tags: ["cityhash", "cityhash32", "cityhash64", "cityhash128", "google", "fast", "not-a-mac"],
    summary:
      "Google's 2011 hash: a different hand-tuned function per input length band. Not a MAC.",
  },
  {
    /**
     * `truncation: true`, and it is the rare merged tool here where that is genuinely so.
     *
     * `Hash32` is the low half of `Hash64`, which is the first word of `Hash128` -- so written
     * little-endian the three widths are prefixes of each other and truncating one by hand gives the
     * right answer. CityHash and MetroHash both look identical in the form and are not truncations at
     * all, which is exactly why the flag exists.
     */
    id: "spookyhash",
    label: "SpookyHash V2",
    category: "SpookyHash",
    outputLen: 8,
    // 96 bytes: twelve 64-bit words, which is the block the long path consumes.
    blockLen: 96,
    outputMode: "parameterized",
    outputLengths: [4, 8, 16],
    truncation: true,
    seeded64: true,
    security: "not-a-mac",
    tags: ["spookyhash", "spooky", "spookyhash32", "spookyhash64", "spookyhash128", "spookyv2",
      "jenkins", "fast", "not-a-mac"],
    summary:
      "Bob Jenkins' 2012 hash. One 128-bit computation; the narrower outputs are its prefixes.",
  },
  {
    /**
     * Two widths crossed with two constant sets, so four functions behind two dropdowns.
     *
     * The variants are the reason `variants` exists as a metadata field: MetroHash64 variant 1 and
     * variant 2 have the same width, the same structure and the same round count, so neither
     * `outputLengths` nor `passes` can express the choice between them.
     */
    id: "metrohash",
    label: "MetroHash",
    category: "MetroHash",
    outputLen: 8,
    // 32 bytes: the four-lane main loop's stride. The tail then steps 16, 8, 4, 2 and 1.
    blockLen: 32,
    outputMode: "parameterized",
    outputLengths: [8, 16],
    truncation: false,
    seeded: true,
    variants: [
      { id: "1", label: "Variant 1" },
      { id: "2", label: "Variant 2" },
    ],
    defaultVariant: "1",
    security: "not-a-mac",
    tags: ["metrohash", "metrohash64", "metrohash128", "rogers", "fast", "not-a-mac"],
    summary:
      "Four functions found by automated search over hash constructions. Two widths, two variants.",
  },
  {
    /**
     * t1ha1 and t1ha2, at 64 bits, plus t1ha2 at 128 -- so the output length and the variant are not
     * independent, and the resolver refuses the one combination that does not exist.
     *
     * `t1ha0` is deliberately absent. It is a *dispatcher*: on a 64-bit machine without AES-NI it is
     * t1ha1, with AES-NI it is one of two other functions, and on 32-bit it is `t1ha0_32le`. A tool
     * whose answer depends on the CPU it ran on is the wrong thing to offer -- the same reason FarmHash
     * is absent from this repo entirely.
     */
    id: "t1ha",
    label: "t1ha",
    category: "t1ha",
    outputLen: 8,
    // 32 bytes: the main loop's stride in both versions.
    blockLen: 32,
    outputMode: "parameterized",
    outputLengths: [8, 16],
    truncation: false,
    seeded64: true,
    variants: [
      { id: "t1ha1", label: "t1ha1" },
      { id: "t1ha2", label: "t1ha2" },
    ],
    defaultVariant: "t1ha2",
    security: "not-a-mac",
    tags: ["t1ha", "t1ha1", "t1ha2", "fast positive hash", "yuriev", "fast", "not-a-mac"],
    summary:
      "Fast Positive Hash. Two versions at 64 bits, and t1ha2 also at 128. Not a MAC.",
  },
  {
    /**
     * wyhash final 3 -- and the one entry in this family with published vectors that cross every branch.
     *
     * Its whole diffusion is a 128-bit multiply with both halves kept and XORed together. No S-box, no
     * round constants, no permutation. That makes it very fast in C and the *slowest* of the
     * non-cryptographic hashes here, because JavaScript has no way to reach the high half of a 64x64
     * product without `bigint`.
     *
     * **Final 3, not final 4.** The two differ in their secret quadruple and their mixing, and produce
     * unrelated output. Final 3 is what ships because it is the version a reachable published vector
     * exists for -- Zig's standard library carries seven, and states that they run the reference's own
     * `test_vector.cpp`. Final 4's own test program only *prints* its values, so nothing offline can
     * check it. This is the same judgement GIMLI's two padding conventions got.
     */
    id: "wyhash",
    label: "wyhash",
    category: "wyhash",
    outputLen: 8,
    // 48 bytes: the three-lane main loop's stride. The tail then steps 16 and dispatches at 4.
    blockLen: 48,
    outputMode: "fixed",
    seeded64: true,
    security: "not-a-mac",
    tags: [
      "wyhash", "wyhash final 3", "wyhash3", "wang yi", "fast", "not-a-mac", "hash table",
    ],
    summary:
      "Wang Yi's hash. One 128-bit multiply is the whole mixing function. Final 3. Not a MAC.",
  },
  {
    /**
     * rapidhash -- wyhash's successor, at all four published versions behind one control.
     *
     * The four are **different functions, not refinements**: they disagree on every input. v1.0 has a
     * three-word secret and a non-zero default seed; v2 onwards has eight words and defaults to zero;
     * v3.0 stops folding the length into the seed; v2.0 and v2.2 differ only in where their medium
     * branch ends (56 against 64) and in one secret index. So the version *is* the algorithm, and
     * someone holding a value needs the one that produced it -- which is the `## One tool or many`
     * answer here: one tool, one dropdown, four functions.
     *
     * This entry used to say no published vector existed for rapidhash. That was wrong, and the
     * correction is worth keeping: `komiya-atsushi/rapidhash-js` generates vectors for all four
     * versions by compiling the reference C at a named revision, and 300 of them are asserted in
     * `tests/algos-rapidhash.test.ts`. The earlier search had looked at the reference repository, the
     * README and `hash4j` and stopped; it had not looked for a *port that committed its test data*,
     * which is the lesson this repo already recorded for Deoxys-II.
     */
    id: "rapidhash",
    label: "rapidhash",
    category: "wyhash",
    outputLen: 8,
    // 112 bytes: the seven-lane main loop's stride, at every version that has one.
    blockLen: 112,
    outputMode: "fixed",
    seeded64: true,
    variants: [
      { id: "v1.0", label: "v1.0" },
      { id: "v2.0", label: "v2.0" },
      { id: "v2.2", label: "v2.2" },
      { id: "v3.0", label: "v3.0" },
    ],
    defaultVariant: "v3.0",
    security: "not-a-mac",
    tags: [
      "rapidhash", "rapidhash v1", "rapidhash v2", "rapidhash v3", "rapidhash1", "rapidhash2",
      "rapidhash3", "nicoshev", "wyhash", "fast", "not-a-mac",
    ],
    summary:
      "wyhash's successor at all four published versions. Each is a different function, not a refinement.",
  },
  {
    /**
     * FarmHash, at the three 64-bit namespaces -- and the reason this repo refused it for a long time.
     *
     * **The public `farmhash::Hash64` dispatches on CPU features**: SSE4.2 and AES-NI select one
     * function, their absence another, and a 32-bit build a third. Two machines print different values
     * for the same bytes, so it cannot be a tool here at all -- this app exists to reproduce a value
     * somebody else printed.
     *
     * What makes it offerable is that the *namespaces* are deterministic and the reference's own
     * self-test checks them individually rather than checking `Hash64`. So the control names the
     * namespace, which is both reproducible and what upstream verifies. `t1ha0` remains absent for the
     * same underlying reason with no such escape: its CPU variants are not separately named in its API.
     *
     * The three are one tool with a dropdown rather than three tools, on the `## One tool or many`
     * reasoning -- nobody reaches for "farmhashuo" without having first decided on FarmHash.
     */
    id: "farmhash",
    label: "FarmHash",
    category: "FarmHash",
    outputLen: 8,
    // 64 bytes: every namespace's main loop stride. `xo` additionally dispatches at 32, 64, 96 and 256.
    blockLen: 64,
    outputMode: "fixed",
    seeded64: true,
    variants: [
      { id: "na", label: "farmhashna" },
      { id: "uo", label: "farmhashuo" },
      { id: "xo", label: "farmhashxo" },
    ],
    defaultVariant: "na",
    security: "not-a-mac",
    tags: [
      "farmhash", "farmhashna", "farmhashuo", "farmhashxo", "geoff pike", "google", "cityhash",
      "fast", "not-a-mac",
    ],
    summary:
      "CityHash's successor, by its author. Names the namespace, because the public entry point picks by CPU.",
  },
  {
    /**
     * CityHashCrc, at 128 and 256 bits -- the two variants built on the CRC-32C *instruction*.
     *
     * **Different functions from CityHash128, not accelerated versions of it.** `citycrc.h` sits behind
     * `#ifdef __SSE4_2__`, which invites exactly the wrong reading: the instruction is used inside the
     * compression loop as a nonlinear mix, so the output is unrelated to CityHash128's and CityHash's
     * own self-test checks them in separate columns.
     *
     * There is no CPU dependence, unlike FarmHash's `Hash64` -- this is one function that the reference
     * merely declines to compile without the instruction. Reproducing the instruction in software gives
     * the identical answer, which is what makes this offerable where a dispatcher is not.
     *
     * The 128-bit form *is* CityHash128 at 900 bytes and below, and diverges above. That is a property
     * of the algorithm rather than an optimisation here, and a test pins the boundary.
     */
    id: "cityhashcrc",
    label: "CityHashCrc",
    category: "CityHash",
    outputLen: 16,
    // 240 bytes: the CRC loop's minimum and its stride. Short inputs are zero-padded up to it.
    blockLen: 240,
    outputMode: "parameterized",
    outputLengths: [16, 32],
    truncation: false,
    security: "not-a-mac",
    tags: [
      "cityhashcrc", "cityhash", "cityhashcrc128", "cityhashcrc256", "crc32c", "sse4.2",
      "geoff pike", "google", "fast", "not-a-mac",
    ],
    summary:
      "CityHash's CRC-32C-mixed variants. Unrelated output to CityHash128, not a faster route to it.",
  },
  {
    /**
     * MetroHash128CRC, at both constant sets.
     *
     * Same shape of confusion as CityHashCrc and the same answer: the CRC-32C instruction is a mixing
     * step, so this does not agree with MetroHash128 and the reference's `testvector.h` lists them
     * separately. Reach for `metrohash` to match MetroHash128.
     *
     * 128-bit only -- there is no MetroHash64CRC -- so there is no output-length control here, unlike
     * the `metrohash` tool.
     *
     * Its two variants differ in constants and rotation amounts and in nothing else, which is why the
     * implementation is one body over a table. Three of its six input paths use the CRC and three do
     * not, and the reference's 63-byte test key exists to hit all of them: 32 + 16 + 8 + 4 + 2 + 1.
     */
    id: "metrohash128crc",
    label: "MetroHash128CRC",
    category: "MetroHash",
    outputLen: 16,
    // 32 bytes: the four-lane loop's stride, as with plain MetroHash.
    blockLen: 32,
    outputMode: "fixed",
    seeded: true,
    variants: [
      { id: "1", label: "Variant 1" },
      { id: "2", label: "Variant 2" },
    ],
    defaultVariant: "1",
    security: "not-a-mac",
    tags: [
      "metrohash128crc", "metrohash", "crc32c", "sse4.2", "rogers", "fast", "not-a-mac",
    ],
    summary:
      "MetroHash128 with CRC-32C as its mixing step. A different function, not a faster one.",
  },
  {
    /**
     * XXH3 and XXH128, the two the reference site offers and no pure-JavaScript library provides.
     *
     * Implemented in `@ocs/algos` rather than taken from `hash-wasm` — which does have both, and is
     * what the reference site uses — because instantiating WebAssembly costs a
     * `'wasm-unsafe-eval'` CSP relaxation the packaged app does not otherwise need. `hash-wasm` is
     * a devDependency serving as the differential oracle instead.
     *
     * `not-a-mac`, like the rest of the family. XXH3 is faster and better distributed than XXH64
     * and is no more of a MAC than a CRC is: the seed is not a key and recovering it from a few
     * known digests is straightforward.
     */
    id: "xxh3",
    label: "XXH3 (64-bit)",
    category: "xxHash",
    outputLen: 8,
    // XXH3's long path consumes 64-byte stripes, which is the closest thing it has to a block.
    blockLen: 64,
    outputMode: "fixed",
    seeded: true,
    security: "not-a-mac",
    tags: ["xxh3", "xxhash3", "xxhash", "checksum", "fast", "not-a-mac"],
    summary: "The modern xxHash. Faster than XXH64 and much better distributed. Not a MAC.",
  },
  {
    id: "xxh128",
    label: "XXH128",
    category: "xxHash",
    outputLen: 16,
    blockLen: 64,
    outputMode: "fixed",
    seeded: true,
    security: "not-a-mac",
    tags: ["xxh128", "xxhash128", "xxhash3", "xxhash", "checksum", "fast", "not-a-mac"],
    summary: "XXH3 at 128 bits. Its low half is exactly XXH3-64. Still not a MAC.",
  },
  {
    id: "xxh32",
    label: "XXH32",
    category: "xxHash",
    outputLen: 4,
    // Not a compression block — xxHash's 16-byte stripe. Reported here because the
    // field exists, but nothing should build an HMAC on it.
    blockLen: 16,
    outputMode: "fixed",
    seeded: true,
    security: "not-a-mac",
    tags: ["xxhash", "xxh32", "xh32", "checksum", "fast", "non-cryptographic"],
    summary: "32-bit non-cryptographic hash. Very fast, trivially forgeable.",
  },
  {
    id: "xxh64",
    label: "XXH64",
    category: "xxHash",
    outputLen: 8,
    blockLen: 32,
    outputMode: "fixed",
    seeded: true,
    security: "not-a-mac",
    tags: ["xxhash", "xxh64", "xh64", "checksum", "fast", "non-cryptographic"],
    summary: "64-bit non-cryptographic hash. Wider than XXH32, equally unsuited to security.",
  },
];

const BY_ID = new Map(HASH_ALGORITHMS.map((a) => [a.id, a]));

export function getHashAlgorithm(id: string): HashAlgorithmMeta | undefined {
  return BY_ID.get(id);
}

export function requireHashAlgorithm(id: string): HashAlgorithmMeta {
  const meta = BY_ID.get(id);
  if (!meta) throw new Error(`Unknown hash algorithm: ${id}`);
  return meta;
}

export const HASH_ALGORITHM_IDS: readonly string[] = HASH_ALGORITHMS.map((a) => a.id);

/**
 * The pass count to run, snapped to the algorithm's own list.
 *
 * Same reasoning as `resolveOutputLen` above: an option value left in the spec after switching
 * away from HAVAL must not reach Tiger, which has no fifth pass.
 */
export function resolvePasses(
  meta: HashAlgorithmMeta,
  requested: number | undefined,
): number | undefined {
  if (!meta.passes) return undefined;
  const fallback = meta.defaultPasses ?? meta.passes[0]!;
  if (requested === undefined) return fallback;
  return meta.passes.includes(requested) ? requested : fallback;
}

/**
 * The posture of the configuration actually selected, which can be better than the tool's badge.
 *
 * A merged tool's `security` is the worst of its variants, because a badge is one word and cannot
 * say "depends". HAVAL at five passes has no published collision; at three, Wang's attack finds one
 * by hand. Telling a reader that five-pass HAVAL is broken would be false, and a rule that
 * overclaims about the easy case is not believed about the hard one -- the same reasoning that gave
 * `M003` its two wordings.
 *
 * Deliberately narrow: it only ever *improves* on the declared posture, and only for an algorithm
 * that declares `brokenBelowPasses`. Nothing here can make a tool look safer than its metadata says
 * by accident.
 */
export function effectiveSecurity(
  meta: HashAlgorithmMeta,
  passes: number | undefined,
): SecurityPosture {
  if (meta.security !== "broken" || meta.brokenBelowPasses === undefined) return meta.security;
  const count = passes ?? meta.defaultPasses ?? meta.passes?.[0];
  if (count === undefined) return meta.security;
  return count < meta.brokenBelowPasses ? "broken" : "legacy";
}

/** True when the algorithm lets the caller choose an output length at all. */
export function hasVariableOutput(meta: HashAlgorithmMeta): boolean {
  return meta.outputMode !== "fixed";
}

/**
 * Every `availableOn` tag this algorithm's options should match.
 *
 * Derived from the metadata rather than listed per algorithm, so exposing a new control is one
 * boolean on one entry and a new algorithm cannot forget to surface one of its own parameters.
 * cSHAKE returns three tags, which is why `ToolDefinition.variantTag` accepts an array.
 */
export function variantTags(meta: HashAlgorithmMeta): string[] {
  const tags: string[] = [];
  // A list and a range are two different controls, and an algorithm gets exactly one of them.
  if (meta.outputLengths) tags.push(TAG_OUTPUT_CHOICE);
  else if (hasVariableOutput(meta)) tags.push(TAG_VARIABLE_OUTPUT);
  if (meta.passes) tags.push(TAG_PASSES);
  if (meta.seeded) tags.push(TAG_SEEDED);
  if (meta.seeded64) tags.push(TAG_SEEDED_64);
  if (meta.variants) tags.push(TAG_HASH_VARIANT);
  if (meta.customizable) tags.push(TAG_CUSTOMIZATION);
  if (meta.namedFunction) tags.push(TAG_FUNCTION_NAME);
  if (meta.blockSized) tags.push(TAG_BLOCK_SIZE);
  if (meta.domainSeparated) tags.push(TAG_DOMAIN);
  if (meta.tupleInput) tags.push(TAG_TUPLE);
  if (meta.keyed) tags.push(TAG_BLAKE_KEY);
  if (meta.saltedPersonalised) tags.push(TAG_BLAKE_SALT);
  if (meta.contextual) tags.push(TAG_BLAKE_CONTEXT);
  return tags;
}

/** True when the input panel supplies this algorithm's message. False for the TupleHash set. */
export function usesInputPanel(meta: HashAlgorithmMeta): boolean {
  return meta.tupleInput !== true;
}

/**
 * Upper bound for the output-length control. XOFs have no real ceiling, so this
 * caps them at something a UI can sensibly render rather than at a limit the
 * algorithm imposes.
 */
export const XOF_OUTPUT_CAP = 1024;

/** The width a named variant produces, when the variant is what decides the width. */
export function variantOutputLen(
  meta: HashAlgorithmMeta,
  variant: string | undefined,
): number | undefined {
  if (!meta.variants) return undefined;
  const chosen = meta.variants.find((v) => v.id === variant) ?? meta.variants.find((v) => v.id === meta.defaultVariant);
  return chosen?.outputLen;
}

export function maxOutputLen(meta: HashAlgorithmMeta): number {
  // A variant-carried width is its own ceiling, and the widest variant is the algorithm's.
  if (meta.variants?.some((v) => v.outputLen !== undefined)) {
    return Math.max(...meta.variants.map((v) => v.outputLen ?? 0));
  }
  if (meta.outputMode === "fixed") return meta.outputLen;
  // A fixed set is its own ceiling. Falling through to the XOF cap here would tell callers that
  // HAVAL can produce 1024 bytes, which is how a length control came to offer sizes it has no form
  // for -- and `resolveOutputLen` would then snap them silently back to the default.
  if (meta.outputLengths) return meta.outputLengths[meta.outputLengths.length - 1]!;
  return meta.maxOutputLen ?? XOF_OUTPUT_CAP;
}

/**
 * The digest length these settings will actually produce.
 *
 * Deliberately lives here, in the metadata module, rather than in `../bindings.ts`
 * where it is used. Two callers need it and only one of them may import `@noble`:
 * the compute path, and `describeSpec`, which is reachable from the eager barrel.
 * Duplicating the clamp would let the tool header claim "64 bytes" while the result
 * panel showed the 32 that BLAKE2s actually produced — so there is one copy, and it
 * is the one on the cheap side of the split.
 *
 * Out-of-range values are clamped rather than rejected: the user gets a correct
 * digest plus `H005` telling them the number in the field is not what they are
 * looking at, which beats an error message and no result.
 */
export function resolveOutputLen(
  meta: HashAlgorithmMeta,
  requested: number | undefined,
  variant?: string,
): number {
  // A variant that declares its own width wins over everything: for Quark the instance *is* the
  // length, so there is nothing for a request to override.
  const fromVariant = variantOutputLen(meta, variant);
  if (fromVariant !== undefined) return fromVariant;
  if (meta.outputMode === "fixed") return meta.outputLen;
  if (requested === undefined || !Number.isInteger(requested) || requested < 1) {
    return meta.outputLen;
  }
  /**
   * A fixed set is snapped to, not clamped into.
   *
   * Clamping is right for a range -- BLAKE2s above 32 bytes means "give me the most you have". It is
   * wrong for a list: HAVAL has no 17-byte form, and producing one by rounding would invent a
   * function. Anything off the list falls back to the default, which is what a stale option value
   * left over from another algorithm looks like.
   */
  if (meta.outputLengths) {
    return meta.outputLengths.includes(requested) ? requested : meta.outputLen;
  }
  return Math.min(requested, maxOutputLen(meta));
}
