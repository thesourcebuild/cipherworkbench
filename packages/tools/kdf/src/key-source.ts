import { argon2d, argon2i, argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { scrypt } from "@noble/hashes/scrypt.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { md5, sha1 } from "@noble/hashes/legacy.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { bcryptPbkdf } from "@ocs/algos";

/**
 * The six key derivations, and the option catalogue that lets another family offer them.
 *
 * Split out of `bindings.ts` for one concrete reason: that module imports `bcryptjs` at top level for
 * `hashBcrypt`, so importing *anything* from it pulls a password-hashing library in. The cipher family
 * derives keys and never hashes passwords, and it reaches this module with a dynamic `await import`
 * inside `computeCipher` -- so opening AES downloads no KDF code at all, and choosing Argon2 downloads
 * Argon2 and nothing else. `bindings.ts` re-exports everything here, so the KDF family's own callers
 * are unchanged.
 *
 * The derivations themselves are unmoved and unedited. They are verified against RFC 6070 (PBKDF2),
 * RFC 5869 (HKDF), RFC 7914 (scrypt), RFC 9106 (Argon2) and the installed OpenSSL's `enc -P` output
 * (EvpKDF) in `tests/kdf.test.ts`.
 */

type NobleHash = Parameters<typeof pbkdf2>[0];

const HASHES: Record<string, NobleHash> = {
  sha256,
  sha384,
  sha512,
  sha1,
  "sha3-256": sha3_256,
  blake2b,
  // EvpKDF only. See the note beside MD5 in `KDF_HASHES`.
  md5,
};

export function requireHash(id: string): NobleHash {
  const hash = HASHES[id];
  if (!hash) throw new Error(`No KDF hash bound for: ${id}`);
  return hash;
}

export function derivePbkdf2(
  hashId: string,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  return pbkdf2(requireHash(hashId), password, salt, { c: iterations, dkLen });
}

export function deriveHkdf(
  hashId: string,
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  dkLen: number,
): Uint8Array {
  return hkdf(requireHash(hashId), ikm, salt, info, dkLen);
}

export function deriveScrypt(
  password: Uint8Array,
  salt: Uint8Array,
  N: number,
  r: number,
  p: number,
  dkLen: number,
): Uint8Array {
  return scrypt(password, salt, { N, r, p, dkLen });
}

export type Argon2Variant = "argon2id" | "argon2i" | "argon2d";

/**
 * `secret` and `associatedData` are Argon2's two optional inputs, both defined by RFC 9106.
 *
 * The secret is what people mean by a "pepper": a server-side value kept outside the
 * database, so a stolen table cannot be attacked without also stealing the application
 * config. Associated data binds the hash to a context — a user id, a tenant — so a hash
 * cannot be moved between records.
 *
 * They are threaded through rather than omitted because RFC 9106's own test vectors set
 * both, so a tool without them cannot reproduce the canonical values.
 */
export function deriveArgon2(
  variant: Argon2Variant,
  password: Uint8Array,
  salt: Uint8Array,
  memoryKib: number,
  timeCost: number,
  parallelism: number,
  dkLen: number,
  secret?: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array {
  const fn = variant === "argon2i" ? argon2i : variant === "argon2d" ? argon2d : argon2id;
  return fn(password, salt, {
    m: memoryKib,
    t: timeCost,
    p: parallelism,
    dkLen,
    ...(secret && secret.length > 0 ? { key: secret } : {}),
    ...(associatedData && associatedData.length > 0 ? { personalization: associatedData } : {}),
  });
}

/**
 * bcrypt-PBKDF -- OpenBSD's KDF, from `@ocs/algos`.
 *
 * The SHA-512 is passed in because `@ocs/algos` is deliberately dependency-free; handing it
 * noble's keeps one SHA-512 in the bundle rather than two. `Uint8Array.from` unwraps noble's
 * branded return type, which is not assignable back into its own input position -- the same
 * copy `deriveEvpKdf` makes below, and for the same reason.
 */
export function deriveBcryptPbkdf(
  password: Uint8Array,
  salt: Uint8Array,
  rounds: number,
  dkLen: number,
): Uint8Array {
  return bcryptPbkdf((data) => Uint8Array.from(sha512(data)), password, salt, rounds, dkLen);
}

/**
 * EVP_BytesToKey -- OpenSSL's original password-to-key-and-IV derivation.
 *
 * Implemented here rather than bound to a library because nothing exports it: it predates every
 * modern KDF interface, and OpenSSL's own C function is the specification. The construction is
 * short enough to state in full, which is the only reason writing it is preferable to not
 * offering it at all:
 *
 *     D_1 = H^count(password || salt)
 *     D_i = H^count(D_(i-1) || password || salt)
 *     output = D_1 || D_2 || ... truncated to the requested length
 *
 * where `H^count` means the hash applied `count` times, feeding each digest back in. With
 * `count = 1` and MD5 -- the historical defaults -- this is what `openssl enc -k` used for two
 * decades, which is why files encrypted that way still need it.
 *
 * It is *not* a password KDF by any modern standard: one MD5 pass over an 8-byte salt is
 * essentially free to brute-force. `K009` says so. It is here for reading old data, and
 * `tests/kdf.test.ts` checks it against the `openssl enc -P` output of the installed OpenSSL
 * rather than against itself.
 */
export function deriveEvpKdf(
  hashId: string,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  const hash = requireHash(hashId);
  const out = new Uint8Array(dkLen);
  let filled = 0;
  // The previous block, empty for the first round -- the `D_(i-1)` above.
  let previous = new Uint8Array(0);

  while (filled < dkLen) {
    const seed = new Uint8Array(previous.length + password.length + salt.length);
    seed.set(previous, 0);
    seed.set(password, previous.length);
    seed.set(salt, previous.length + password.length);

    // Copied out of noble's branded return type into a plain array: its `TArg` wrapper is not
    // assignable back into its own input position, which is exactly what feeding a digest back in
    // requires.
    let block = Uint8Array.from(hash(seed));
    // `count - 1` further passes over the digest alone. OpenSSL's loop shape, and the reason a
    // count of 1 means "hash once" rather than "hash zero times".
    for (let pass = 1; pass < iterations; pass++) block = Uint8Array.from(hash(block));

    const take = Math.min(block.length, dkLen - filled);
    out.set(block.subarray(0, take), filled);
    filled += take;
    previous = block;
  }

  return out;
}

// ── the key-source catalogue, for a family that wants a derived key ───────────

import type { OptionDef } from "@ocs/engine";
import { decodeBytesOption } from "@ocs/engine";
import type { OptionValues } from "@ocs/contracts/options";
import { optNumber, optString } from "@ocs/contracts/pure";
import { KDF_HASHES, DEFAULT_KDF_HASH } from "./catalogue/tool-meta";

/**
 * Where a key comes from: typed in, or derived from a password.
 *
 * `custom` is the behaviour every cipher tool had before this existed and stays the default, so
 * nothing about a fresh spec changes. The other six are the KDF family's own tools, reached through
 * the same functions above -- there is one PBKDF2 in this repo, not two.
 */
export const KEY_SOURCES = [
  "directinput",
  "pbkdf2",
  "evpkdf",
  "hkdf",
  "scrypt",
  "argon2",
  "bcryptpbkdf",
] as const;
export type KeySource = (typeof KEY_SOURCES)[number];

/**
 * `variantTag` is a flat namespace already shared by modes, parameter sets, instances and directions,
 * so these are prefixed. Without it a future mode or parameter set called `scrypt` would silently
 * reveal a password field.
 */
export const keySourceTag = (source: KeySource): string => `key:${source}`;

/** Every source but `custom` -- what the password, salt and derivation controls are gated on. */
export const DERIVED_TAGS: readonly string[] = KEY_SOURCES.filter((s) => s !== "directinput").map(
  keySourceTag,
);

export const OPTION_KEY_SOURCE = "keySource";
export const OPTION_PASSWORD = "password";
export const OPTION_KDF_SALT = "kdfSalt";
export const OPTION_KDF_DERIVES = "kdfDerives";
export const OPTION_KDF_ENVELOPE = "kdfEnvelope";
export const OPTION_KDF_HASH = "kdfHash";
export const OPTION_PBKDF2_ITERATIONS = "pbkdf2Iterations";
export const OPTION_EVP_ITERATIONS = "evpIterations";
export const OPTION_HKDF_INFO = "hkdfInfo";
export const OPTION_SCRYPT_N = "kdfScryptN";
export const OPTION_SCRYPT_R = "kdfScryptR";
export const OPTION_SCRYPT_P = "kdfScryptP";
export const OPTION_ARGON2_VARIANT = "kdfArgon2Variant";
export const OPTION_ARGON2_MEMORY = "kdfArgon2Memory";
export const OPTION_ARGON2_TIME = "kdfArgon2Time";
export const OPTION_ARGON2_PARALLELISM = "kdfArgon2Parallelism";
export const OPTION_BCRYPT_ROUNDS = "kdfBcryptRounds";

/**
 * What the KDF is asked to produce.
 *
 * `key-iv` asks for `keyLen + ivLen` bytes and splits them, key first -- which is what `openssl enc`
 * and CryptoJS both do, and is verified against the installed OpenSSL's own `-P` output rather than
 * against a round trip. A round trip cannot see a key and an IV swapped.
 */
export const KDF_DERIVES = ["key-iv", "key"] as const;
export type KdfDerives = (typeof KDF_DERIVES)[number];

/** Whether the ciphertext carries OpenSSL's `Salted__` header. */
export const KDF_ENVELOPES = ["none", "openssl"] as const;
export type KdfEnvelope = (typeof KDF_ENVELOPES)[number];

export const DEFAULT_KEY_SOURCE: KeySource = "directinput";
export const DEFAULT_KDF_DERIVES: KdfDerives = "key-iv";
export const DEFAULT_KDF_ENVELOPE: KdfEnvelope = "none";
/** `openssl enc -pbkdf2`'s own default, so the first thing anyone tries reproduces OpenSSL. */
export const DEFAULT_PBKDF2_ITERATIONS = 10_000;
/** `EVP_BytesToKey`'s count, which OpenSSL calls once. Not a cost parameter in any real sense. */
export const DEFAULT_EVP_ITERATIONS = 1;
export const DEFAULT_SCRYPT_N = 1 << 15;
export const DEFAULT_SCRYPT_R = 8;
export const DEFAULT_SCRYPT_P = 1;
export const DEFAULT_ARGON2_MEMORY_KIB = 65_536;
export const DEFAULT_ARGON2_TIME = 3;
export const DEFAULT_ARGON2_PARALLELISM = 4;
export const DEFAULT_BCRYPT_ROUNDS = 16;

/**
 * The controls a family splices into its own catalogue to offer a derived key.
 *
 * A builder rather than a constant because the caller owns its group taxonomy, and the three slots do
 * different jobs. `select` takes the source dropdown, which is a choice made once. `input` takes the
 * password and the salt -- material handed to the tool *with* the message, which is what
 * `OptionGroupMeta.placement: "input"` is for, and it puts them where the Key field was. `settings`
 * takes the cost parameters, also chosen once but only meaningful once a KDF is selected, so they get
 * a group of their own that disappears entirely under Custom.
 *
 * Every control below `keySource` is gated on the sources it belongs to, so a tool left on Custom looks
 * exactly as it did. The tags are namespaced -- see `keySourceTag`.
 */
export function keySourceOptions<TGroup extends string>(groups: {
  /**
   * Where the source select itself goes, which is a different question from where the password goes.
   *
   * Three slots rather than two because the answers genuinely differ. The cipher family puts the select
   * in the rail beside Mode and Key size -- it is one of the three choices that decide *which function
   * runs*, and it is picked once -- while the password and salt belong in the Input panel with the
   * message they are handed alongside.
   */
  select: TGroup;
  input: TGroup;
  settings: TGroup;
}): OptionDef<TGroup>[] {
  const { select, input, settings } = groups;
  const derived = [...DERIVED_TAGS];
  return [
    {
      id: OPTION_KEY_SOURCE,
      label: "Key source",
      group: select,
      kind: "enum",
      choices: [
        { value: "directinput", label: "Direct Input", summary: "Type the key bytes yourself" },
        { value: "pbkdf2", label: "PBKDF2", summary: "RFC 8018, and openssl enc -pbkdf2" },
        {
          value: "evpkdf",
          label: "EvpKDF",
          summary: "OpenSSL's EVP_BytesToKey, and CryptoJS's",
        },
        { value: "hkdf", label: "HKDF", summary: "RFC 5869. For key material, not passwords" },
        { value: "scrypt", label: "Scrypt", summary: "RFC 7914. Memory-hard" },
        { value: "argon2", label: "Argon2", summary: "RFC 9106. The current recommendation" },
        {
          value: "bcryptpbkdf",
          label: "bcrypt-PBKDF",
          summary: "OpenSSH's, for an OPENSSH key",
        },
      ],
      summary: "Where the key comes from.",
      detail:
        "Custom is the raw key: you type or generate the bytes, which is what a specification's test vector gives you. The other six derive it from a password, which is what almost every real file uses. Choosing one replaces the Key field with a password and that KDF's own parameters, and the key is derived when you compute rather than shown in advance, so nothing has to be copied between two tools. Which one to pick is decided by whatever produced your data rather than by which is strongest: PBKDF2 for openssl enc -pbkdf2, EvpKDF for older openssl enc and for CryptoJS, bcrypt-PBKDF for an OPENSSH private key. For something new, Argon2 or scrypt.",
      order: 14,
    },
    {
      /*
       * `utf-8` rather than hex, which is the opposite of the Key field's default and right for the
       * same reason `M007` gives: a password is a typed secret, and hex would silently read "1234" as
       * two bytes rather than four characters. The encoding selector is still there for anyone holding
       * the bytes.
       */
      id: OPTION_PASSWORD,
      label: "Password",
      group: input,
      kind: "bytes",
      bytesLength: { min: 0, max: 4096 },
      defaultBytesEncoding: "utf-8",
      secret: true,
      availableOn: derived,
      summary: "The passphrase the key is derived from.",
      detail:
        "Read as UTF-8 text by default, because that is what every implementation does with a typed password -- switch the encoding if you have bytes rather than text. It never leaves this machine, and being marked secret it is left out of a share link and of saved state, which the share dialog reports.",
      order: 12,
    },
    {
      /*
       * Text (UTF-8) by default, matching key and IV options.
       */
      id: OPTION_KDF_SALT,
      label: "Salt",
      group: input,
      kind: "bytes",
      bytesLength: { min: 0, max: 64, generate: 8 },
      defaultBytesEncoding: "utf-8",
      availableOn: derived,
      summary: "Public, and unique per password.",
      detail:
        "Not secret; it exists so that one precomputed table cannot attack every password at once, which means it has to differ between messages rather than be unguessable. Eight bytes is what OpenSSL uses and what the Salted__ header carries; sixteen is the modern recommendation. With the OpenSSL envelope selected this field is optional when encrypting -- leave it empty for a fresh random salt per message, which is OpenSSL's own default, or set it to reproduce a specific value the way openssl enc -S does. Decrypting from that envelope ignores this field and reads the salt out of the ciphertext.",
      order: 14,
    },
    {
      id: OPTION_KDF_DERIVES,
      label: "Derives",
      group: settings,
      kind: "enum",
      choices: [
        { value: "key-iv", label: "Key and IV", summary: "What openssl enc and CryptoJS do" },
        { value: "key", label: "Key only", summary: "Enter the IV yourself" },
      ],
      availableOn: derived,
      summary: "Whether the IV comes from the password too.",
      detail:
        "Key and IV asks the KDF for the key length plus the IV length in one call and splits the result, key first. That is exactly what openssl enc does, and what CryptoJS does for AES.encrypt with a passphrase -- and it is the only setting under which this app reproduces their output, so it is the default and the IV field disappears while it is on. Key only derives the key and leaves the IV to you, which is what a format that transmits the IV separately needs.",
      order: 10,
    },
    {
      id: OPTION_KDF_ENVELOPE,
      label: "Envelope",
      group: settings,
      kind: "enum",
      choices: [
        { value: "none", label: "None", summary: "Ciphertext only" },
        { value: "openssl", label: "OpenSSL Salted__", summary: "Salt carried in the output" },
      ],
      availableOn: derived,
      summary: "Whether the salt travels with the ciphertext.",
      detail:
        "None means the output is the ciphertext alone and the salt is something you keep beside it. OpenSSL Salted__ is the framing openssl enc writes unless given -nosalt: the eight ASCII bytes Salted__, then the eight salt bytes, then the ciphertext -- so a password is the only thing a recipient needs. Selecting it makes the salt optional when encrypting (empty means a fresh random one, as OpenSSL does) and ignored when decrypting, where the salt is read out of the input.",
      order: 12,
    },
    {
      id: OPTION_KDF_HASH,
      label: "KDF hash",
      group: settings,
      kind: "enum",
      choices: KDF_HASHES.map((hash) => ({
        value: hash.id,
        label: hash.label,
        summary: `${hash.outputLen}-byte digest`,
        ...(hash.id === "md5" || hash.id === "sha1" ? { insecure: true } : {}),
      })),
      availableOn: [keySourceTag("pbkdf2"), keySourceTag("evpkdf"), keySourceTag("hkdf")],
      summary: "The hash inside the KDF.",
      detail:
        "It has to match whatever produced your data or nothing will agree. SHA-256 is openssl enc's default for both -pbkdf2 and -md, and is the right choice for anything new. MD5 is here because openssl enc -k defaulted to it for about twenty years and CryptoJS still does, so reading a file from either means being able to reproduce it -- and under EvpKDF the hash is not what makes the construction weak.",
      order: 15,
    },
    {
      id: OPTION_PBKDF2_ITERATIONS,
      label: "Iterations",
      group: settings,
      kind: "number",
      arg: {
        placeholder: String(DEFAULT_PBKDF2_ITERATIONS),
        min: 1,
        max: 10_000_000,
        step: 1000,
      },
      availableOn: [keySourceTag("pbkdf2")],
      summary: "PBKDF2's cost.",
      detail:
        "The whole of PBKDF2's defence, and the one number an attacker also pays. It defaults to 10,000 because that is openssl enc -pbkdf2's own default and therefore what reproducing OpenSSL needs; OWASP's figure for storing a password is 600,000 at SHA-256, and if you are encrypting something new rather than reading something old there is no reason to stay at the default. Both ends must use the same number.",
      order: 20,
    },
    {
      id: OPTION_EVP_ITERATIONS,
      label: "Count",
      group: settings,
      kind: "number",
      arg: { placeholder: String(DEFAULT_EVP_ITERATIONS), min: 1, max: 100_000, step: 1 },
      availableOn: [keySourceTag("evpkdf")],
      summary: "EVP_BytesToKey's count.",
      detail:
        "How many times the hash is applied per block, and OpenSSL calls it with 1 -- which is why this defaults to 1 rather than to something that looks safer. It is not a cost parameter in any useful sense: raising it does not turn EvpKDF into a password KDF, it turns it into a slightly slower one that no other implementation will match.",
      order: 21,
    },
    {
      id: OPTION_HKDF_INFO,
      label: "Info",
      group: settings,
      kind: "bytes",
      bytesLength: { min: 0, max: 1024 },
      defaultBytesEncoding: "utf-8",
      availableOn: [keySourceTag("hkdf")],
      summary: "Context string, bound into the output.",
      detail:
        "RFC 5869's optional context: a protocol name, a direction, a key purpose. Two keys derived from one secret with different info are unrelated, which is how one shared secret safely produces a send key and a receive key. It is neither secret nor a salt, and both ends must use the same value.",
      order: 22,
    },
    {
      id: OPTION_SCRYPT_N,
      label: "Cost (N)",
      group: settings,
      kind: "number",
      arg: { placeholder: String(DEFAULT_SCRYPT_N), min: 2, max: 1 << 22, step: 1 },
      availableOn: [keySourceTag("scrypt")],
      summary: "Must be a power of two.",
      detail:
        "Memory and time both scale with N, which is what makes scrypt hard to attack with custom hardware: 2^15 with r=8 needs about 32 MiB. It has to be a power of two and every implementation refuses anything else.",
      order: 23,
    },
    {
      id: OPTION_SCRYPT_R,
      label: "Block size (r)",
      group: settings,
      kind: "number",
      arg: { placeholder: String(DEFAULT_SCRYPT_R), min: 1, max: 64, step: 1 },
      availableOn: [keySourceTag("scrypt")],
      summary: "8 in every deployment.",
      detail:
        "Sets how much memory each of the N slots takes, so memory is roughly 128 * N * r bytes. Eight is what RFC 7914 recommends and what everything uses; changing it changes the answer.",
      order: 24,
    },
    {
      id: OPTION_SCRYPT_P,
      label: "Parallelism (p)",
      group: settings,
      kind: "number",
      arg: { placeholder: String(DEFAULT_SCRYPT_P), min: 1, max: 16, step: 1 },
      availableOn: [keySourceTag("scrypt")],
      summary: "Independent work, not threads.",
      detail:
        "Multiplies the work without multiplying the memory, and this implementation runs it sequentially -- p is part of the answer rather than a speed setting. One is the usual choice.",
      order: 25,
    },
    {
      id: OPTION_ARGON2_VARIANT,
      label: "Variant",
      group: settings,
      kind: "enum",
      choices: [
        { value: "argon2id", label: "Argon2id", summary: "The one to use" },
        { value: "argon2i", label: "Argon2i", summary: "Data-independent addressing" },
        { value: "argon2d", label: "Argon2d", summary: "Data-dependent addressing" },
      ],
      availableOn: [keySourceTag("argon2")],
      summary: "Argon2id unless you are reproducing something.",
      detail:
        "Argon2id is the hybrid RFC 9106 recommends and what every current guideline names: Argon2i alone resists side-channel attacks but is weaker against time-memory trade-offs, and Argon2d is the reverse. The three produce entirely different output, so this has to match whatever you are checking against.",
      order: 18,
    },
    {
      id: OPTION_ARGON2_MEMORY,
      label: "Memory",
      group: settings,
      kind: "number",
      arg: {
        placeholder: String(DEFAULT_ARGON2_MEMORY_KIB),
        unit: "KiB",
        min: 8,
        max: 4 << 20,
        step: 1024,
      },
      availableOn: [keySourceTag("argon2")],
      summary: "In KiB, and this is the real cost.",
      detail:
        "Memory is what makes Argon2 expensive to attack in parallel on a GPU, so it is the parameter to raise first. RFC 9106 recommends 64 MiB with t=3 for an interactive login and OWASP's floor is 19 MiB with t=2. Note this runs in your own browser, so asking for a gigabyte will do exactly that.",
      order: 26,
    },
    {
      id: OPTION_ARGON2_TIME,
      label: "Iterations (t)",
      group: settings,
      kind: "number",
      arg: { placeholder: String(DEFAULT_ARGON2_TIME), min: 1, max: 64, step: 1 },
      availableOn: [keySourceTag("argon2")],
      summary: "Passes over the memory.",
      detail:
        "Time cost, multiplying the work without changing the memory. Raise memory before this: three passes over 64 MiB is a much harder target than ten over 8 MiB.",
      order: 27,
    },
    {
      id: OPTION_ARGON2_PARALLELISM,
      label: "Parallelism (p)",
      group: settings,
      kind: "number",
      arg: { placeholder: String(DEFAULT_ARGON2_PARALLELISM), min: 1, max: 16, step: 1 },
      availableOn: [keySourceTag("argon2")],
      summary: "Lanes, and part of the answer.",
      detail:
        "How many lanes the memory is split into. It changes the output, so it must match what you are checking against -- it is not a hint about how many cores to use, and this implementation is single-threaded regardless.",
      order: 28,
    },
    {
      id: OPTION_BCRYPT_ROUNDS,
      label: "Rounds",
      group: settings,
      kind: "number",
      arg: { placeholder: String(DEFAULT_BCRYPT_ROUNDS), min: 1, max: 2048, step: 1 },
      availableOn: [keySourceTag("bcryptpbkdf")],
      summary: "Linear, unlike bcrypt's cost.",
      detail:
        "bcrypt-PBKDF's only knob, and doubling it doubles the work rather than quadrupling it -- there is no log2 cost here. ssh-keygen uses 16, which is what an OPENSSH private key almost always carries, so that is the default.",
      order: 29,
    },
  ];
}

// ── reading the spec, validating it, and deriving ─────────────────────────────

/** A catalogue view narrow enough that any family's catalogue satisfies it. */
type ByteOptionCatalogue = {
  get(
    id: string,
  ): { defaultBytesEncoding?: "hex" | "base64" | "base64url" | "utf-8" | "latin1" } | undefined;
};

export interface KeySourceParams {
  source: KeySource;
  derives: KdfDerives;
  envelope: KdfEnvelope;
  password: Uint8Array;
  salt: Uint8Array;
  hash: string;
  iterations: number;
  info: Uint8Array;
  scryptN: number;
  scryptR: number;
  scryptP: number;
  argon2Variant: Argon2Variant;
  argon2MemoryKib: number;
  argon2Time: number;
  argon2Parallelism: number;
  bcryptRounds: number;
}

export function readKeySource(options: OptionValues): KeySource {
  const raw = optString(options, OPTION_KEY_SOURCE);
  return KEY_SOURCES.includes(raw as KeySource) ? (raw as KeySource) : DEFAULT_KEY_SOURCE;
}

/**
 * The two selects that a `variantTag` has to read, without needing a catalogue.
 *
 * `keySourceParams` needs one to decode the byte options; these do not, which matters because
 * `variantTag` is called during catalogue construction and cannot ask the catalogue about itself.
 */
export function readKdfDerives(options: OptionValues): KdfDerives {
  const raw = optString(options, OPTION_KDF_DERIVES);
  return KDF_DERIVES.includes(raw as KdfDerives) ? (raw as KdfDerives) : DEFAULT_KDF_DERIVES;
}

export function readKdfEnvelope(options: OptionValues): KdfEnvelope {
  const raw = optString(options, OPTION_KDF_ENVELOPE);
  return KDF_ENVELOPES.includes(raw as KdfEnvelope)
    ? (raw as KdfEnvelope)
    : DEFAULT_KDF_ENVELOPE;
}

/**
 * Everything the derivation needs, read once.
 *
 * The two iteration counts are separate options with separate defaults -- PBKDF2's 10,000 and
 * EvpKDF's 1 -- because one shared control cannot open on both, and defaulting either way would make
 * the other fail to reproduce its own reference implementation. They collapse into one field here
 * because only one of the two is ever reachable at a time.
 */
export function keySourceParams(
  catalogue: ByteOptionCatalogue,
  options: OptionValues,
): KeySourceParams {
  const bytes = (id: string): Uint8Array => {
    const decoded = decodeBytesOption(catalogue, options, id);
    return decoded.ok ? decoded.bytes : new Uint8Array(0);
  };
  const source = readKeySource(options);
  const derives = optString(options, OPTION_KDF_DERIVES);
  const envelope = optString(options, OPTION_KDF_ENVELOPE);
  const variant = optString(options, OPTION_ARGON2_VARIANT);
  return {
    source,
    derives: KDF_DERIVES.includes(derives as KdfDerives)
      ? (derives as KdfDerives)
      : DEFAULT_KDF_DERIVES,
    envelope: KDF_ENVELOPES.includes(envelope as KdfEnvelope)
      ? (envelope as KdfEnvelope)
      : DEFAULT_KDF_ENVELOPE,
    password: bytes(OPTION_PASSWORD),
    salt: bytes(OPTION_KDF_SALT),
    hash: optString(options, OPTION_KDF_HASH) ?? DEFAULT_KDF_HASH,
    iterations:
      source === "evpkdf"
        ? (optNumber(options, OPTION_EVP_ITERATIONS) ?? DEFAULT_EVP_ITERATIONS)
        : (optNumber(options, OPTION_PBKDF2_ITERATIONS) ?? DEFAULT_PBKDF2_ITERATIONS),
    info: bytes(OPTION_HKDF_INFO),
    scryptN: optNumber(options, OPTION_SCRYPT_N) ?? DEFAULT_SCRYPT_N,
    scryptR: optNumber(options, OPTION_SCRYPT_R) ?? DEFAULT_SCRYPT_R,
    scryptP: optNumber(options, OPTION_SCRYPT_P) ?? DEFAULT_SCRYPT_P,
    argon2Variant: variant === "argon2i" || variant === "argon2d" ? variant : "argon2id",
    argon2MemoryKib: optNumber(options, OPTION_ARGON2_MEMORY) ?? DEFAULT_ARGON2_MEMORY_KIB,
    argon2Time: optNumber(options, OPTION_ARGON2_TIME) ?? DEFAULT_ARGON2_TIME,
    argon2Parallelism:
      optNumber(options, OPTION_ARGON2_PARALLELISM) ?? DEFAULT_ARGON2_PARALLELISM,
    bcryptRounds: optNumber(options, OPTION_BCRYPT_ROUNDS) ?? DEFAULT_BCRYPT_ROUNDS,
  };
}

/**
 * What is wrong with these parameters, decided **without deriving anything**.
 *
 * That constraint is the whole reason this function exists separately. A resolver runs on every
 * keystroke -- the cipher family's has fourteen callers, every lint rule among them -- and Argon2 at
 * 64 MiB takes long enough that deriving there would freeze the page. So the resolver calls this, and
 * the derivation happens once inside an async `compute`.
 *
 * Refuses only what the algorithm genuinely cannot do, which is the rule the cipher family already
 * follows: a weak-but-legal parameter is a diagnostic, not a refusal.
 */
export function keySourceProblem(
  params: KeySourceParams,
  direction: "encrypt" | "decrypt",
): { problem: string; optionId: string } | undefined {
  if (params.source === "directinput") return undefined;

  if (params.password.length === 0) {
    return { problem: "Enter a password to derive the key from.", optionId: OPTION_PASSWORD };
  }

  /*
   * A salt is required except where the envelope will supply one. Encrypting into the OpenSSL
   * envelope generates a random salt when the field is empty, which is OpenSSL's own behaviour, and
   * decrypting from it reads the salt out of the input -- so in both of those cases an empty field is
   * correct rather than incomplete.
   */
  const envelopeSupplies = params.envelope === "openssl";
  if (params.salt.length === 0 && !envelopeSupplies) {
    if (params.source === "hkdf") {
      // RFC 5869 defines an empty salt as valid, so this is HKDF's own answer rather than an omission.
    } else {
      return {
        problem: "Enter a salt, or press Generate. It is not secret, but it has to be there.",
        optionId: OPTION_KDF_SALT,
      };
    }
  }

  if (params.source === "scrypt") {
    const { scryptN } = params;
    if (scryptN < 2 || (scryptN & (scryptN - 1)) !== 0) {
      return {
        problem: `scrypt's N has to be a power of two; ${scryptN} is not. Every implementation refuses anything else.`,
        optionId: OPTION_SCRYPT_N,
      };
    }
  }

  if (params.source === "bcryptpbkdf" && direction === "encrypt" && params.salt.length === 0) {
    // OpenBSD's bcrypt_pbkdf returns -1 for an empty salt and fills the output with random bytes,
    // which is the one case in the KDF family that is refused rather than reported.
    return { problem: "bcrypt-PBKDF refuses an empty salt.", optionId: OPTION_KDF_SALT };
  }

  return undefined;
}

/**
 * The derived bytes, `dkLen` of them.
 *
 * One dispatcher over the six functions above, so a caller asks for a length and gets bytes without
 * knowing which KDF is which. `key-iv` is not handled here: the caller asks for `keyLen + ivLen` and
 * splits, because only the caller knows how long its IV is.
 */
export function deriveKeySourceBytes(params: KeySourceParams, dkLen: number): Uint8Array {
  switch (params.source) {
    case "directinput":
      throw new Error("deriveKeySourceBytes was called with the key source set to Custom.");
    case "pbkdf2":
      return derivePbkdf2(params.hash, params.password, params.salt, params.iterations, dkLen);
    case "evpkdf":
      return deriveEvpKdf(params.hash, params.password, params.salt, params.iterations, dkLen);
    case "hkdf":
      return deriveHkdf(params.hash, params.password, params.salt, params.info, dkLen);
    case "scrypt":
      return deriveScrypt(
        params.password,
        params.salt,
        params.scryptN,
        params.scryptR,
        params.scryptP,
        dkLen,
      );
    case "argon2":
      return deriveArgon2(
        params.argon2Variant,
        params.password,
        params.salt,
        params.argon2MemoryKib,
        params.argon2Time,
        params.argon2Parallelism,
        dkLen,
      );
    case "bcryptpbkdf":
      return deriveBcryptPbkdf(params.password, params.salt, params.bcryptRounds, dkLen);
  }
}

// ── OpenSSL's Salted__ envelope ───────────────────────────────────────────────

/** `Salted__`, the eight ASCII bytes `openssl enc` writes before the salt. */
export const OPENSSL_MAGIC = Uint8Array.from([0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f]);
export const OPENSSL_SALT_BYTES = 8;
export const OPENSSL_HEADER_BYTES = OPENSSL_MAGIC.length + OPENSSL_SALT_BYTES;

/** The header, ready to prepend. */
export function opensslHeader(salt: Uint8Array): Uint8Array {
  const out = new Uint8Array(OPENSSL_HEADER_BYTES);
  out.set(OPENSSL_MAGIC, 0);
  out.set(salt.subarray(0, OPENSSL_SALT_BYTES), OPENSSL_MAGIC.length);
  return out;
}

/**
 * The salt and the ciphertext, read out of an OpenSSL envelope.
 *
 * Refuses rather than guessing: a truncated or absent header means the input is not what the setting
 * says it is, and decrypting the first sixteen bytes as ciphertext would produce rubbish with no
 * error. The message names what was expected, because "invalid input" would leave a reader with
 * nowhere to go.
 */
export function readOpensslEnvelope(
  input: Uint8Array,
): { ok: true; salt: Uint8Array; body: Uint8Array } | { ok: false; problem: string } {
  if (input.length < OPENSSL_HEADER_BYTES) {
    return {
      ok: false,
      problem: `An OpenSSL envelope starts with ${OPENSSL_HEADER_BYTES} bytes -- "Salted__" and an 8-byte salt -- and this input is only ${input.length}. Set Envelope to None if the salt is not carried in the data.`,
    };
  }
  for (let i = 0; i < OPENSSL_MAGIC.length; i++) {
    if (input[i] !== OPENSSL_MAGIC[i]) {
      return {
        ok: false,
        problem:
          'This input does not begin with "Salted__", so it is not an OpenSSL envelope. Set Envelope to None, or check that the ciphertext was not decoded from the wrong encoding.',
      };
    }
  }
  return {
    ok: true,
    salt: input.slice(OPENSSL_MAGIC.length, OPENSSL_HEADER_BYTES),
    body: input.slice(OPENSSL_HEADER_BYTES),
  };
}
