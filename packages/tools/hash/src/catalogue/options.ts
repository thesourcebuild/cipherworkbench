import {
  createOptionCatalogue,
  type OptionCatalogue,
  type OptionDef,
} from "@ocs/engine";
import {
  DEFAULT_PARALLEL_BLOCK_SIZE,
  DEFAULT_TURBOSHAKE_DOMAIN,
  MAX_ITERATIONS,
  MAX_PARALLEL_BLOCK_SIZE,
  OPTION_BLOCK_SIZE,
  OPTION_BLAKE_CONTEXT,
  OPTION_BLAKE_KEY,
  OPTION_BLAKE_PERSONAL,
  OPTION_BLAKE_SALT,
  OPTION_CUSTOMIZATION,
  OPTION_DOMAIN,
  OPTION_FUNCTION_NAME,
  OPTION_ITERATIONS,
  OPTION_OUTPUT_LENGTH,
  OPTION_PASSES,
  OPTION_SEED,
  OPTION_SEED_64,
  OPTION_HASH_VARIANT,
  OPTION_TUPLE,
} from "../pure";
import {
  TAG_BLOCK_SIZE,
  TAG_BLAKE_CONTEXT,
  TAG_BLAKE_KEY,
  TAG_BLAKE_SALT,
  TAG_CUSTOMIZATION,
  TAG_DOMAIN,
  TAG_FUNCTION_NAME,
  TAG_OUTPUT_CHOICE,
  TAG_PASSES,
  TAG_HASH_VARIANT,
  TAG_SEEDED,
  TAG_SEEDED_64,
  TAG_TUPLE,
  TAG_VARIABLE_OUTPUT,
  XOF_OUTPUT_CAP,
  type HashAlgorithmMeta,
} from "./algorithm-meta";
import type { HashOptionGroup } from "./groups";

export { TAG_SEEDED, TAG_SEEDED_64, TAG_VARIABLE_OUTPUT };

/**
 * The whole hash family shares one option list. Only two entries, and both earn
 * their place:
 *
 *  - `iterations` exists because `sha256(sha256(x))` is a real, widely deployed
 *    construction (Bitcoin's double-SHA256, various legacy password schemes) that
 *    people genuinely come here to reproduce. It is also the single most common
 *    way this tool could be misused — hence `H002`, which fires the moment it
 *    goes above 1 and points at PBKDF2 instead.
 *  - `outputLength` is only meaningful for an extendable-output function, so it
 *    carries `availableOn: ["xof"]` and simply does not render for SHA-256.
 */
export const OPTIONS: readonly OptionDef<HashOptionGroup>[] = [
  {
    id: OPTION_ITERATIONS,
    label: "Iterations",
    group: "transform",
    kind: "number",
    arg: { placeholder: "1", unit: "passes", min: 1, max: MAX_ITERATIONS, step: 1 },
    summary: "Re-hash the digest this many times.",
    detail:
      "1 is a plain digest. 2 gives the double-hash construction used by Bitcoin block and transaction ids — sha256(sha256(x)) — and by a handful of older protocols. Each pass hashes the previous digest's raw bytes, not its hex spelling; if you are trying to reproduce a value that iterated over the hex text instead, the results will differ. This is not a substitute for a password KDF at any count: see the note this raises.",
    order: 10,
  },
  {
    id: OPTION_OUTPUT_LENGTH,
    label: "Output length",
    group: "output",
    kind: "number",
    arg: { placeholder: "32", unit: "bytes", min: 1, max: XOF_OUTPUT_CAP, step: 1 },
    availableOn: [TAG_VARIABLE_OUTPUT],
    summary: "How many bytes of output to produce.",
    detail:
      "Only shown for algorithms that let you choose, and it means two different things depending on which. For an extendable-output function (SHAKE, BLAKE3) you are squeezing a stream, so asking for 16 bytes gives exactly the first 16 bytes of a longer request. For BLAKE2b and BLAKE2s the length is mixed into the initial state, so BLAKE2b-256 is a completely different value from the first 32 bytes of BLAKE2b-512 — they are separate functions that happen to share a name. Values above an algorithm's ceiling are clamped rather than rejected: BLAKE2s stops at 32 bytes and BLAKE2b at 64.",
    order: 10,
  },
  {
    id: OPTION_SEED,
    label: "Seed",
    group: "transform",
    kind: "number",
    arg: { placeholder: "0", min: 0, max: 4294967295, step: 1 },
    availableOn: [TAG_SEEDED],
    summary: "Salts the whole computation. xxHash only.",
    detail:
      "A 32-bit value mixed into xxHash's starting state. Zero is the default and what every tool that prints an xxHash without mentioning a seed used — `xxhsum`, most content-addressing schemes, most hash tables. Change it only to match something that specified a seed, because a different seed gives a completely unrelated value rather than a variation on the same one. Note that a seed does not make xxHash a MAC: it is not secret in any of these uses, and recovering it from a few known hashes is straightforward.",
    order: 20,
  },
  {
    id: OPTION_SEED_64,
    label: "Seed",
    group: "transform",
    kind: "bytes",
    bytesLength: { min: 0, max: 8 },
    defaultBytesEncoding: "hex",
    availableOn: [TAG_SEEDED_64],
    summary: "A 64-bit seed, as bytes. SpookyHash and t1ha.",
    detail:
      "Eight bytes rather than a number field, because a 64-bit seed does not fit a JavaScript number and t1ha's own published vectors use seeds as large as `ffffffffffffffff`. Empty means zero, which is what every tool that prints one of these hashes without mentioning a seed used. Fewer than eight bytes are read as the low end of the value, so `01` is 1. A different seed gives a completely unrelated hash rather than a variation on the same one, and it is not a MAC key: it is public in every use these hashes are designed for, and recovering it from a few known outputs is straightforward.",
    order: 22,
  },
  {
    id: OPTION_TUPLE,
    label: "Tuple elements",
    group: "message",
    kind: "list",
    bytesLength: { min: 0, max: 1 << 20 },
    defaultBytesEncoding: "utf-8",
    maxItems: 64,
    availableOn: [TAG_TUPLE],
    summary: "The ordered list of strings to hash.",
    detail:
      'TupleHash\'s input is a tuple, not a message, and the boundaries between elements are part of it: hashing ("ab", "c") gives a different value from hashing ("abc"). That unambiguity is the entire reason the function exists -- it is what stops a pair of fields being concatenated into something a different pair could also produce. The order matters too, so the rows can be reordered. An empty element is legitimate and changes the digest; so does an empty tuple. Because each update to a TupleHash appends one element rather than more of a message, this is the one algorithm here that cannot read the input panel or stream a file.',
    order: 5,
  },
  {
    id: OPTION_BLAKE_KEY,
    label: "Key",
    group: "transform",
    kind: "bytes",
    // BLAKE2b takes up to 64 bytes of key, BLAKE2s up to 32 and BLAKE3 exactly 32. The union is
    // accepted here and the specific limit is enforced where the message can name the algorithm --
    // the same pattern AES's per-mode nonce length uses.
    bytesLength: { min: 0, max: 64, generate: 32 },
    defaultBytesEncoding: "hex",
    secret: true,
    availableOn: [TAG_BLAKE_KEY],
    summary: "Turns the hash into a MAC. Never included in a share link.",
    detail:
      "BLAKE2 and BLAKE3 take a key directly, without the HMAC construction around the outside: the key goes into the initial state, which is why keyed BLAKE2b is a MAC in one pass rather than two and why HMAC-BLAKE2 is a thing nobody needs. RFC 7693 section 2.9 defines it for BLAKE2 (up to 64 bytes for 2b, 32 for 2s); BLAKE3's keyed_hash mode takes exactly 32. Leave it empty for a plain digest. A keyed digest is a different value from the unkeyed one over the same message, so this is not something to set by accident -- which is the other reason it is marked secret and stripped from links.",
    order: 25,
  },
  {
    id: OPTION_BLAKE_SALT,
    label: "Salt",
    group: "transform",
    kind: "bytes",
    // RFC 7693: 16 bytes for BLAKE2b, 8 for BLAKE2s. Exact, not a range -- the parameter block has
    // a fixed field, and noble rejects anything else.
    bytesLength: { exact: [8, 16], generate: 16 },
    defaultBytesEncoding: "utf-8",
    availableOn: [TAG_BLAKE_SALT],
    summary: "Randomises the function itself. 16 bytes for BLAKE2b, 8 for BLAKE2s.",
    detail:
      "Mixed into the initial state rather than into the message, which makes it a different hash function rather than a different input -- the point being that an attacker cannot precompute against a function they have not seen. Not a secret and not a key: it is stored alongside whatever it protects, exactly like a password-hashing salt. Argon2 uses BLAKE2b this way internally.",
    order: 26,
  },
  {
    id: OPTION_BLAKE_PERSONAL,
    label: "Personalisation",
    group: "transform",
    kind: "bytes",
    bytesLength: { exact: [8, 16] },
    defaultBytesEncoding: "utf-8",
    availableOn: [TAG_BLAKE_SALT],
    summary: "Domain separation, the way BLAKE2 does it. Same sizes as the salt.",
    detail:
      "BLAKE2's answer to cSHAKE's customisation string: a fixed-width application identifier in the parameter block, so two protocols using BLAKE2b cannot produce the same digest for the same message. Public, like the salt, and fixed-width unlike a customisation string -- 16 bytes for BLAKE2b and 8 for BLAKE2s, no more and no less.",
    order: 27,
  },
  {
    id: OPTION_BLAKE_CONTEXT,
    label: "Derive-key context",
    group: "transform",
    kind: "bytes",
    bytesLength: { min: 0, max: 4096 },
    defaultBytesEncoding: "utf-8",
    availableOn: [TAG_BLAKE_CONTEXT],
    summary: "BLAKE3's derive_key mode. Use instead of a key, never with one.",
    detail:
      'BLAKE3 has three modes and this is the third: hash, keyed_hash, and derive_key. The context is a hardcoded, application-specific string -- the specification asks for something globally unique like "example.com 2019 auth key" -- and the input becomes the key material. It is a KDF, so what comes out is unrelated to both the plain and the keyed digest of the same bytes. Exclusive with the key: BLAKE3 defines no mode that takes both, and setting both is refused rather than silently resolved.',
    order: 28,
  },
  {
    id: OPTION_CUSTOMIZATION,
    label: "Customisation string",
    group: "transform",
    kind: "bytes",
    bytesLength: { min: 0, max: 4096 },
    defaultBytesEncoding: "utf-8",
    availableOn: [TAG_CUSTOMIZATION],
    summary: "Domain separation. Different strings give unrelated outputs.",
    detail:
      "SP 800-185's S parameter. Two applications that pick different customisation strings get functions that cannot collide with each other even on identical input, which is what lets one primitive be reused across a protocol safely. Empty is the default and is what a bare SHAKE would give. It is not a key: it is not secret, it is often published in the protocol spec, and it provides no authentication.",
    order: 30,
  },
  {
    id: OPTION_FUNCTION_NAME,
    label: "Function name",
    group: "transform",
    kind: "bytes",
    bytesLength: { min: 0, max: 4096 },
    defaultBytesEncoding: "utf-8",
    availableOn: [TAG_FUNCTION_NAME],
    summary: "cSHAKE's N parameter. Reserved for NIST-defined functions.",
    detail:
      "SP 800-185 reserves this for functions NIST itself defines -- KMAC, TupleHash and ParallelHash are all cSHAKE with a particular N -- and tells everyone else to leave it empty and use the customisation string instead. It is exposed here because reproducing those constructions by hand, or a third-party function that used it anyway, requires setting it. With both N and S empty, cSHAKE is defined to be exactly SHAKE.",
    order: 40,
  },
  {
    id: OPTION_BLOCK_SIZE,
    label: "Block size",
    group: "transform",
    kind: "number",
    arg: {
      placeholder: String(DEFAULT_PARALLEL_BLOCK_SIZE),
      unit: "bytes",
      min: 1,
      max: MAX_PARALLEL_BLOCK_SIZE,
      step: 1,
    },
    availableOn: [TAG_BLOCK_SIZE],
    summary: "ParallelHash's B. Part of the digest, not a tuning knob.",
    detail:
      "ParallelHash splits the input into blocks of this size, hashes each independently, then hashes the concatenated results. The size therefore changes the output: the same bytes with B=8 and B=16 give unrelated digests, so it has to match whatever produced the value you are comparing against. There is no interoperable default -- SP 800-185's own examples use 8, which is what this starts at.",
    order: 50,
  },
  {
    id: OPTION_DOMAIN,
    label: "Domain byte",
    group: "transform",
    kind: "number",
    arg: {
      placeholder: String(DEFAULT_TURBOSHAKE_DOMAIN),
      min: 1,
      max: 127,
      step: 1,
    },
    availableOn: [TAG_DOMAIN],
    summary: "TurboSHAKE's D. Leave at 31 (0x1F) unless a spec says otherwise.",
    detail:
      "A single byte between 0x01 and 0x7F that separates one use of TurboSHAKE from another, the same idea as cSHAKE's customisation string but cheaper. 0x1F is the value the specification uses for the bare XOF and the only one anything interoperates on by default; KangarooTwelve uses others internally. A different byte gives a completely unrelated output rather than a variation, so changing it is a deliberate interop decision.",
    order: 60,
  },
];

/**
 * The shared catalogue: every option whose definition is the same for all 103 algorithms.
 *
 * Still the answer for almost all of them. `hashCatalogueFor` below adds per-algorithm controls on
 * top for the two axes whose *choices* differ -- a select's options cannot be shared when HAVAL
 * offers five lengths and Tiger three.
 */
export const CATALOGUE = createOptionCatalogue<HashOptionGroup>(OPTIONS);

export const getOption = CATALOGUE.get;
export const requireOption = CATALOGUE.require;
export const optionsInGroup = CATALOGUE.inGroup;

/** Bytes to a label a reader recognises: HAVAL is named in bits everywhere it appears. */
function bitsLabel(bytes: number): string {
  return `${bytes * 8} bits`;
}

function outputChoiceOption(meta: HashAlgorithmMeta): OptionDef<HashOptionGroup> {
  return {
    id: OPTION_OUTPUT_LENGTH,
    label: "Digest length",
    group: "output",
    kind: "enum",
    choices: meta.outputLengths!.map((bytes) => ({
      value: String(bytes),
      label: bitsLabel(bytes),
      summary: `${bytes} bytes`,
    })),
    availableOn: [TAG_OUTPUT_CHOICE],
    summary: "Which of this algorithm's digest sizes to produce.",
    detail: meta.truncation
      ? "A select rather than a free number, because only these lengths are defined. For this algorithm the shorter forms are genuine truncations -- the 128-bit digest is the first 16 bytes of the 192-bit one -- so a value truncated by hand elsewhere will still agree with this."
      : "A select rather than a free number, because only these lengths are defined and nothing in between exists. Note that these are NOT truncations of one another -- the requested length changes the computation rather than trimming its result, so the 128-bit digest is unrelated to the first 16 bytes of the 256-bit one. HAVAL folds the length into a tailoring step at the end; MD6 puts it in the control word every node reads and derives its round count from it, so a shorter MD6 does fewer rounds. Either way, truncating by hand gives a wrong answer with no error.",
    order: 10,
  };
}

/**
 * The variant select, built from the algorithm's own list.
 *
 * Same arrangement as `outputChoiceOption` and `passesOption`: one shared option id whose choices come
 * from the metadata, so a new algorithm with variants needs no code here.
 */
function variantOption(meta: HashAlgorithmMeta): OptionDef<HashOptionGroup> {
  return {
    id: OPTION_HASH_VARIANT,
    label: "Variant",
    group: "transform",
    kind: "enum",
    choices: meta.variants!.map((v) => ({ value: v.id, label: v.label })),
    availableOn: [TAG_HASH_VARIANT],
    summary: "Which named variant of this algorithm to compute.",
    detail:
      "Not an output length and not a round count: these are separate functions published under one name. MetroHash's two variants have the same width, the same structure and the same round count, and differ only in four constants and a handful of rotation counts -- so their outputs are unrelated and there is nothing in either to say which produced it. t1ha's two versions differ more substantially than that. Reproducing a stored value means matching whichever variant produced it.",
    order: 12,
  };
}

function passesOption(meta: HashAlgorithmMeta): OptionDef<HashOptionGroup> {
  const broken = meta.brokenBelowPasses;
  return {
    id: OPTION_PASSES,
    label: "Passes",
    group: "transform",
    kind: "enum",
    choices: meta.passes!.map((count) => ({
      value: String(count),
      label: String(count),
      summary:
        broken !== undefined && count < broken
          ? "Collision attacks are practical at this pass count"
          : "More passes, more mixing",
    })),
    availableOn: [TAG_PASSES],
    summary: "How many passes the round function makes.",
    detail:
      "The pass count is an argument to one function rather than a choice between separate algorithms -- but it changes the output completely, and for HAVAL it also changes the round function's permutation, so a digest at three passes has nothing to do with the same message at five. Reproducing a stored value means matching whatever produced it. Where a lower count is known to be breakable, the Checks panel says so for the count actually selected.",
    order: 15,
  };
}

const CACHE = new Map<string, OptionCatalogue<HashOptionGroup>>();

/**
 * The catalogue for one algorithm.
 *
 * Returns the shared one unless the algorithm declares a choice set, in which case the generic
 * option is swapped for a select carrying that algorithm's own values. Cached per id, because
 * `ToolDefinition.catalogue` is resolved once per tool and rebuilding it per render would be waste.
 */
export function hashCatalogueFor(meta: HashAlgorithmMeta): OptionCatalogue<HashOptionGroup> {
  if (!meta.outputLengths && !meta.passes && !meta.variants) return CATALOGUE;

  const cached = CACHE.get(meta.id);
  if (cached) return cached;

  const extras: OptionDef<HashOptionGroup>[] = [];
  if (meta.outputLengths) extras.push(outputChoiceOption(meta));
  if (meta.passes) extras.push(passesOption(meta));
  if (meta.variants) extras.push(variantOption(meta));

  // The generic numeric output-length control is dropped where a select replaces it, so the two
  // can never both render -- they write the same option id and would fight over it.
  const base = meta.outputLengths ? OPTIONS.filter((o) => o.id !== OPTION_OUTPUT_LENGTH) : OPTIONS;
  const catalogue = createOptionCatalogue<HashOptionGroup>([...base, ...extras]);
  CACHE.set(meta.id, catalogue);
  return catalogue;
}
