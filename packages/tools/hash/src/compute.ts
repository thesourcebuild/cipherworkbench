import {
  decodeBytesOption,
  decodeListOption,
  type ToolResult,
  type ToolStream,
  type ToolVariantTable,
} from "@ocs/engine";
import { createSpec } from "./create-spec";
import {
  hasVariableOutput,
  HASH_ALGORITHMS,
  requireHashAlgorithm,
  usesInputPanel,
  resolveOutputLen,
  resolvePasses,
  type HashAlgorithmMeta,
} from "./catalogue/algorithm-meta";
import { hashCatalogueFor } from "./catalogue/options";
import { requireHashBinding, type HashBinding, type HashParams } from "./bindings";
import {
  OPTION_BLAKE_CONTEXT,
  OPTION_BLAKE_KEY,
  OPTION_BLAKE_PERSONAL,
  OPTION_BLAKE_SALT,
  OPTION_CUSTOMIZATION,
  OPTION_FUNCTION_NAME,
  OPTION_SEED_64,
  OPTION_TUPLE,
  readBlockSize,
  readDomain,
  readIterations,
  readPasses,
  readRequestedOutputLength,
  readHashVariant,
  readSeed,
} from "./pure";
import type { HashSpec } from "./spec";

interface ResolvedSpec {
  meta: HashAlgorithmMeta;
  binding: HashBinding;
  params: HashParams;
  iterations: number;
  /** TupleHash's elements. Empty for every other algorithm. */
  tuple: Uint8Array[];
  /** Set when an option could not be decoded -- reported as a result, not thrown. */
  problem?: string;
}

function resolve(spec: HashSpec): ResolvedSpec {
  const meta = requireHashAlgorithm(spec.algorithm);
  const binding = requireHashBinding(spec.algorithm);
  // A fixed-output algorithm ignores the option entirely rather than being clamped
  // by it: leaving a stale `outputLength` in the spec after switching from SHAKE256
  // to SHA-256 must not change SHA-256's answer.
  const requested = hasVariableOutput(meta)
    ? readRequestedOutputLength(spec.options)
    : undefined;
  /**
   * Each parameter is read only when the algorithm declares it.
   *
   * The guard is the point rather than an optimisation: a `customization` left in the spec after
   * switching from cSHAKE128 to SHA-256 must not change SHA-256's answer. Options persist across
   * tool switches by design -- that is what makes the workbench pleasant -- so every consumer has
   * to be deliberate about which of them it reads.
   */
  const catalogue = hashCatalogueFor(meta);
  /**
   * The variant is resolved before the length, because for Quark the variant *decides* the length --
   * see `variantOutputLen`. Resolved against the algorithm's own list, so a variant left in the spec
   * after a tool switch cannot reach a binding that has never heard of it.
   */
  let variant: string | undefined;
  if (meta.variants) {
    const requestedVariant = readHashVariant(spec.options);
    const known = meta.variants.some((v) => v.id === requestedVariant);
    variant = known ? requestedVariant : (meta.defaultVariant ?? meta.variants[0]!.id);
  }
  const params: HashParams = { outputLen: resolveOutputLen(meta, requested, variant) };
  if (variant !== undefined) params.variant = variant;
  // Guarded like every other parameter: a `passes` left in the spec after switching away from
  // HAVAL must not reach Tiger, which has no fifth pass.
  if (meta.passes) params.passes = resolvePasses(meta, readPasses(spec.options));
  if (meta.seeded) params.seed = readSeed(spec.options);
  if (meta.blockSized) params.blockLen = readBlockSize(spec.options);
  if (meta.domainSeparated) params.domain = readDomain(spec.options);

  let problem: string | undefined;

  if (meta.seeded64) {
    // Always through `decodeBytesOption`, never by reading the companion encoding key by hand.
    const decoded = decodeBytesOption(catalogue, spec.options, OPTION_SEED_64);
    if (!decoded.ok) problem = `Seed: ${decoded.error}`;
    else if (decoded.bytes.length > 0) {
      /**
       * An *empty* field is left undefined rather than read as zero, so a binding can fall back to its
       * algorithm's own default seed.
       *
       * For SpookyHash and t1ha that default is zero and nothing changes. rapidhash v1.0's is
       * `0xbdd89aa982704029`, so reading empty as zero would make the reference's own no-seed answer
       * unreachable from the form -- while showing an empty box, which is the worst pairing available.
       *
       * Fewer than eight bytes are the low end of the value, so `01` is 1 rather than 1 << 56.
       */
      let seed = 0n;
      for (const byte of decoded.bytes) seed = (seed << 8n) | BigInt(byte);
      params.seed64 = seed;
    }
  }

  if (meta.customizable) {
    const decoded = decodeBytesOption(catalogue, spec.options, OPTION_CUSTOMIZATION);
    if (decoded.ok) params.customization = decoded.bytes;
    else problem = `Customisation string: ${decoded.error}`;
  }
  if (meta.namedFunction) {
    const decoded = decodeBytesOption(catalogue, spec.options, OPTION_FUNCTION_NAME);
    if (decoded.ok) params.functionName = decoded.bytes;
    else problem ??= `Function name: ${decoded.error}`;
  }

  /**
   * BLAKE2's and BLAKE3's own parameters, with the length limits enforced here.
   *
   * The catalogue accepts the union of what the three algorithms allow -- a 64-byte key is legal for
   * BLAKE2b and not for BLAKE2s or BLAKE3 -- because `bytesLength` describes one control shared by
   * all three. The specific limit belongs where the message can name the algorithm, which is the same
   * reasoning AES's per-mode nonce length follows.
   */
  if (meta.keyed) {
    const decoded = decodeBytesOption(catalogue, spec.options, OPTION_BLAKE_KEY);
    if (!decoded.ok) problem ??= `Key: ${decoded.error}`;
    else if (decoded.bytes.length > 0) {
      const max = meta.id === "blake2b" ? 64 : 32;
      const exact = meta.id === "blake3";
      if (exact && decoded.bytes.length !== 32) {
        problem ??= `BLAKE3's keyed mode takes exactly 32 bytes of key; this one is ${decoded.bytes.length}.`;
      } else if (decoded.bytes.length > max) {
        problem ??= `${meta.label} accepts at most ${max} bytes of key; this one is ${decoded.bytes.length}.`;
      } else {
        params.key = decoded.bytes;
      }
    }
  }
  if (meta.saltedPersonalised) {
    const want = meta.id === "blake2b" ? 16 : 8;
    for (const [id, label, assign] of [
      [OPTION_BLAKE_SALT, "Salt", (b: Uint8Array) => (params.salt = b)],
      [
        OPTION_BLAKE_PERSONAL,
        "Personalisation",
        (b: Uint8Array) => (params.personalization = b),
      ],
    ] as const) {
      const decoded = decodeBytesOption(catalogue, spec.options, id);
      if (!decoded.ok) problem ??= `${label}: ${decoded.error}`;
      else if (decoded.bytes.length === 0) continue;
      else if (decoded.bytes.length !== want) {
        problem ??= `${meta.label}'s ${label.toLowerCase()} is exactly ${want} bytes; this one is ${decoded.bytes.length}.`;
      } else assign(decoded.bytes);
    }
  }
  if (meta.contextual) {
    const decoded = decodeBytesOption(catalogue, spec.options, OPTION_BLAKE_CONTEXT);
    if (!decoded.ok) problem ??= `Derive-key context: ${decoded.error}`;
    else if (decoded.bytes.length > 0) {
      if (params.key) {
        // BLAKE3 defines no mode taking both, so this is refused rather than resolved: silently
        // preferring one would produce a digest the user did not ask for.
        problem ??=
          "BLAKE3 takes either a key or a derive-key context, not both. Clear one of them.";
      } else params.context = decoded.bytes;
    }
  }

  let tuple: Uint8Array[] = [];
  if (meta.tupleInput) {
    const decoded = decodeListOption(catalogue, spec.options, OPTION_TUPLE);
    if (decoded.ok) tuple = decoded.items;
    else problem ??= decoded.error;
  }

  return {
    meta,
    binding,
    params,
    iterations: readIterations(spec.options),
    tuple,
    ...(problem === undefined ? {} : { problem }),
  };
}

/**
 * Applies iterations 2..n to an already-computed digest.
 *
 * Each pass hashes the previous digest's *raw bytes*. That is what
 * double-SHA256 means in Bitcoin and everywhere else the construction appears —
 * as opposed to re-hashing the hex spelling of the digest, which some older
 * home-grown password schemes did and which produces entirely different values.
 * The `iterations` option's own help text calls that distinction out, because it
 * is the reason two tools can disagree on "double SHA-256".
 */
function iterate(digest: Uint8Array, resolved: ResolvedSpec): Uint8Array {
  let current = digest;
  for (let pass = 1; pass < resolved.iterations; pass++) {
    const hasher = resolved.binding.create(resolved.params);
    hasher.update(current);
    current = hasher.digest();
  }
  return current;
}

export async function computeHash(spec: HashSpec, input: Uint8Array): Promise<ToolResult> {
  const resolved = resolve(spec);
  if (resolved.problem) return { error: resolved.problem };

  const hasher = resolved.binding.create(resolved.params);

  /**
   * TupleHash is fed element by element, and the input panel is not involved.
   *
   * `update()` on a TupleHash *is* "append one tuple element" -- verified against noble, where
   * `update("ab"); update("c")` equals `tuplehash([ab, c])` and differs from `tuplehash([abc])`.
   * That is the construction working as specified, and it is also why this algorithm cannot
   * stream a file: 64 KiB chunks would hash a tuple of chunks. The manifest says so with
   * `supportsFile: false`.
   */
  if (resolved.meta.tupleInput) {
    for (const element of resolved.tuple) hasher.update(element);
    return { bytes: iterate(hasher.digest(), resolved), fields: tupleFields(resolved) };
  }

  hasher.update(input);
  return { bytes: iterate(hasher.digest(), resolved) };
}

/**
 * The element count and their sizes, shown alongside a TupleHash result.
 *
 * Worth the space because the whole point of TupleHash is that the boundaries are data: someone
 * comparing against another implementation needs to see that this run hashed three elements of
 * 2, 1 and 0 bytes rather than one of three.
 */
function tupleFields(resolved: ResolvedSpec) {
  const sizes = resolved.tuple.map((element) => element.length);
  return [
    {
      label: "Tuple",
      value:
        sizes.length === 0
          ? "empty"
          : `${sizes.length} element${sizes.length === 1 ? "" : "s"} of ${sizes.join(", ")} byte${
              sizes.length === 1 && sizes[0] === 1 ? "" : "s"
            }`,
      hint: "Element boundaries are part of the input: (ab, c) and (abc) hash to different values.",
    },
  ];
}

/**
 * The streaming half. `update` feeds straight through to the underlying hasher —
 * no buffering, no block alignment, because every `noble` hasher already handles
 * arbitrary chunk boundaries internally.
 *
 * Iterations are applied in `finish`, on the digest, which is exactly where
 * `computeHash` applies them — that shared `iterate` call is what makes the
 * stream-equals-one-shot invariant hold for iterated digests too, not just plain
 * ones.
 */
/**
 * The algorithm's own family over the same input, each member at its own defaults.
 *
 * `category` is the axis, which is the same grouping the sidebar uses: MD is MD2, MD4 and MD5; SHA-1
 * is on its own; SHA-2 is the six widths; SHA-3, Keccak, SHAKE and TurboSHAKE are four separate
 * families rather than one Keccak-shaped heap. That is the comparison people actually want -- "which
 * of the SHA-2 widths produced this" -- and it is the one they can read.
 *
 * It was briefly all 102 algorithms at once. That answers a different and rarer question, and it
 * answers it badly: a hundred rows of hex is a haystack, and MD5 next to Groestl-512 next to
 * MurmurHash3 invites a comparison between things that have nothing to do with each other.
 *
 * `Output` first, because it is the column that does the work: a 32-byte digest can only have come
 * from a 32-byte row, which across SHA-2's six widths settles it immediately. No `Category` column --
 * every row now shares one, so it would be the same word repeated down the table.
 *
 * A family of one returns nothing rather than a single row restating the Result panel. SHA-1,
 * Whirlpool, Snefru, SM3 and BelT have no siblings, and the panel says so.
 *
 * At each member's *own* defaults: the passes, output length and customisation string in the form
 * belong to the algorithm selected above. A row is "SHAKE256 as it comes", not "SHAKE256 with your
 * SHAKE128 settings".
 *
 * TupleHash is left out entirely -- its input is a *tuple* of elements rather than a byte string, so
 * there is nothing to feed it from a stream. `createHashStream` refuses outright, and
 * `usesInputPanel` is the flag that already records the distinction.
 */
export function hashVariants(spec: HashSpec): ToolVariantTable {
  const meta = requireHashAlgorithm(spec.algorithm);
  /**
   * Algorithms needing async setup are excluded, and the reason is structural rather than a policy.
   *
   * A variant row hands back a `stream()` that must be constructible *synchronously* -- the panel builds
   * one per row on render. FSB's matrix table is a dynamic import awaited by `loadTool()`, so a *sibling*
   * FSB stream created from another tool's page would have no table and would throw.
   *
   * Today FSB is alone in its category, so this filter changes nothing; it is here so that adding a
   * second syndrome-based hash does not silently break the panel on the day it lands.
   */
  const family = HASH_ALGORITHMS.filter(
    (other) =>
      other.category === meta.category &&
      /*
       * Not filtered on whether the implementation is loaded, which it used to be.
       *
       * The old predicate excluded anything declaring `prepare` -- FSB alone, which cost FSB its
       * rows. Now that every algorithm implemented in `@ocs/algos` is a dynamic import, that
       * predicate would have emptied the table for eight of the 51 categories rather than trimming
       * them: MD spans four modules and xxHash three, and a category down to one member renders no
       * panel at all. Each row carries its own `prepare` instead, awaited by the panel on Run --
       * which also gives FSB the rows it never had.
       */
      usesInputPanel(other),
  );

  if (family.length < 2) return { columns: [], rows: [] };

  return {
    noun: "algorithm",
    columns: ["Output", "Block"],
    rows: family.map((other) => ({
      id: other.id,
      label: other.label,
      // Through the binding rather than `prepareHashAlgorithm`, which lives in `definition.ts` and
      // imports this file -- taking it from there would be a cycle.
      ...(requireHashBinding(other.id).prepare
        ? { prepare: () => requireHashBinding(other.id).prepare!() }
        : {}),
      stream: () => createHashStream(createSpec({ algorithm: other.id })),
      selected: other.id === spec.algorithm,
      cells: [`${other.outputLen} bytes`, `${other.blockLen} bytes`],
    })),
  };
}

export function createHashStream(spec: HashSpec): ToolStream {
  const resolved = resolve(spec);
  if (resolved.meta.tupleInput) {
    // Unreachable through the app: the manifest sets `streaming: false` for TupleHash, so nothing
    // asks for a stream. Explicit rather than silently hashing a tuple of file chunks.
    throw new Error(`${resolved.meta.label} takes a tuple of elements and cannot stream.`);
  }
  // The whole params object, not just the length. Passing `outputLen` alone is what previously
  // dropped the xxHash seed on the streaming path -- see the note on `HashParams`.
  const hasher = resolved.binding.create(resolved.params);
  let finished = false;

  return {
    update(chunk: Uint8Array) {
      if (finished) throw new Error("Cannot update a hash stream after finish().");
      hasher.update(chunk);
    },
    finish(): ToolResult {
      if (finished) throw new Error("finish() called twice on the same hash stream.");
      finished = true;
      return { bytes: iterate(hasher.digest(), resolved) };
    },
  };
}
