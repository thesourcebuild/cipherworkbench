/**
 * MD6, Rivest's SHA-3 round-1 submission, and the only *tree* hash in this repo.
 *
 * Everything else here is Merkle-Damgard or a sponge: a single chain of state, one block at a time.
 * MD6 is a Merkle tree. Data goes into 512-byte leaves, each leaf compresses to a 128-byte chaining
 * value, four of those fill a parent, and the tree grows upward until one node is left -- which makes
 * it the only algorithm in the app whose *shape* depends on how much input there is. An 8 KB message
 * builds three levels; nine bytes builds one.
 *
 * The submission also defines a sequential mode, chosen by the parameter `L`: a node at level `L + 1`
 * chains instead of branching, so `L = 0` is a pure sequential hash and `L = 64` -- the default, and
 * what every implementation and every published value uses -- is a tree for any input that fits in
 * sixty-four levels, which is all of them. Only the default is implemented, and that is stated rather
 * than hidden: an `L` nobody has published a value for would be a control with nothing behind it.
 *
 * **Everything here was derived from Rivest's own C**, fetched from a mirror of the reference
 * implementation (`md6_compress.c` and `md6_mode.c`) and read rather than recalled. What that gives is
 * the parts no paper summary carries: the exact node layout, the bit fields of the control word, and
 * the fact that the digest is the **tail** of the chaining value rather than its head.
 *
 * Five things to preserve.
 *
 * **The compression function has no S-boxes and no key schedule -- it is one recurrence.** 89 input
 * words, then `r * 16` more computed from six taps back into the array, and the answer is the last 16.
 * `x = S ^ A[i-89] ^ A[i-17] ^ (A[i-18] & A[i-21]) ^ (A[i-31] & A[i-67])`, then two shifts. So there
 * is nothing to mistype except the six tap offsets and the sixteen shift pairs, and getting any of
 * them wrong gives a hash that is perfectly self-consistent and matches nothing.
 *
 * **The round count depends on the digest size.** `r = 40 + d/4`, so MD6-512 runs 168 rounds where
 * MD6-128 runs 72 -- which means the *number of rounds is part of the answer*, not a speed knob, and
 * two implementations disagreeing about it produce unrelated output at the same length.
 *
 * **The digest is the tail of the 1024-bit chaining value**, not the head. `trim_hashval` in the
 * reference copies the *last* `d/8` bytes. Reading from the front is right for nothing and looks
 * right for everything, which is the same trap Shabal's tail-of-B has.
 *
 * **Only the leaves are byte-reversed.** A level-1 node's 64 words are big-endian reads of the message
 * bytes; a node above it holds chaining values that are already words and must not be touched. The
 * reference expresses this as a conditional `md6_reverse_little_endian` inside `md6_compress_block`,
 * which is easy to read as unconditional.
 *
 * **`z` marks the very last compression, and nothing else does.** It is a bit in the control word, so
 * the root of the tree hashes differently from every node below it -- which is what stops a subtree's
 * chaining value from being a valid whole-message digest. A node that is the *only* node at the top
 * level and already holds exactly one child passes through uncompressed instead.
 *
 * `tests/algos-md6.test.ts` checks all three registered sizes against values from the reference
 * implementation, at lengths that build one, two and three levels of tree -- plus a vector from an
 * unrelated third-party port, which is the corroboration that matters most here: NIST's KAT files for
 * the round-1 submissions are not mirrored anywhere reachable, so agreement between independent
 * implementations is what stands in for them.
 */

const MASK = (1n << 64n) - 1n;

/** The first 960 bits of the fractional part of sqrt(6). Fifteen words, from the reference. */
const Q: readonly bigint[] = [
  0x7311c2812425cfa0n,
  0x6432286434aac8e7n,
  0xb60450e9ef68b7c1n,
  0xe8fb23908d9f06f1n,
  0xdd2e76cba691e5bfn,
  0x0cd0d63b2c30bc41n,
  0x1f8ccf6823058f8an,
  0x54e5ed5b88e3775dn,
  0x4ad12aae0a6d6031n,
  0x3e7f16bb88222e0dn,
  0x8af8671d3fb50c2cn,
  0x995ad1178bd25c31n,
  0xc878c1dd04c4b633n,
  0x3b72066c7a1552acn,
  0x0d6f3522631effcbn,
];

/** The round constant's seed and the mask its recurrence uses. */
const S0 = 0x0123456789abcdefn;
const S_MASK = 0x7311c2812425cfa0n;

/**
 * The sixteen (right, left) shift pairs, one per step of a round.
 *
 * The reference writes these as sixteen `loop_body(rs, ls, step)` macros so the compiler can unroll
 * them; here they are the table that arrangement is hiding. One transposed pair gives a hash that
 * inverts against itself and reproduces nothing.
 */
const SHIFTS: readonly (readonly [number, number])[] = [
  [10, 11],
  [5, 24],
  [13, 9],
  [10, 16],
  [11, 15],
  [12, 9],
  [2, 27],
  [7, 15],
  [14, 6],
  [15, 2],
  [7, 29],
  [13, 8],
  [11, 15],
  [7, 5],
  [6, 31],
  [12, 9],
];

/** Tap offsets: linear feedback, two quadratic pairs, and the end-around at the full width. */
const T0 = 17;
const T1 = 18;
const T2 = 21;
const T3 = 31;
const T4 = 67;
const T5 = 89;

/** Words in a compression input (89), in its output (16), of message per block (64), of key (8). */
const N_WORDS = 89;
const C_WORDS = 16;
const B_WORDS = 64;
const K_WORDS = 8;
const Q_WORDS = 15;

/** Bytes of message in one leaf, and bytes in one chaining value. */
export const MD6_LEAF_BYTES = B_WORDS * 8;
const CHAIN_BYTES = C_WORDS * 8;
/** Chaining values that fit in one parent node. */
const FAN_OUT = B_WORDS / C_WORDS;

/** The mode parameter. 64 is the default and the only value with published values behind it. */
const L = 64;

/** Digest sizes this repo offers, in bytes. MD6 accepts any `d` from 1 to 512 bits. */
export const MD6_OUTPUT_LENS: readonly number[] = [16, 32, 64];

/** `r = 40 + d/4`, so the round count is part of the answer rather than a tuning knob. */
export function md6Rounds(digestBits: number): number {
  return 40 + Math.floor(digestBits / 4);
}

/**
 * The compression function: 89 words in, 16 out, via `r * 16` computed words.
 *
 * Written as the loop the reference's sixteen macros expand to. `A` is allocated at full size rather
 * than kept as a sliding window, because every step reaches 89 words back and the reference indexes it
 * exactly that way -- a window would work and would make the tap arithmetic something to re-derive.
 */
function compress(input: readonly bigint[], rounds: number): bigint[] {
  const total = N_WORDS + rounds * C_WORDS;
  const a = new Array<bigint>(total).fill(0n);
  for (let i = 0; i < N_WORDS; i++) a[i] = input[i]!;

  let s = S0;
  let i = N_WORDS;
  for (let j = 0; j < rounds * C_WORDS; j += C_WORDS) {
    for (let step = 0; step < C_WORDS; step++) {
      const [right, left] = SHIFTS[step]!;
      const at = i + step;
      let x = s;
      x ^= a[at - T5]!;
      x ^= a[at - T0]!;
      x ^= a[at - T1]! & a[at - T2]!;
      x ^= a[at - T3]! & a[at - T4]!;
      x = (x ^ (x >> BigInt(right))) & MASK;
      a[at] = (x ^ ((x << BigInt(left)) & MASK)) & MASK;
    }
    // The round constant's own recurrence: a rotate-by-one with a masked feedback term.
    s = (((s << 1n) & MASK) ^ (s >> 63n) ^ (s & S_MASK)) & MASK;
    i += C_WORDS;
  }

  return a.slice(total - C_WORDS, total);
}

/**
 * One node: the standard 89-word input assembled around a 64-word payload.
 *
 * Layout, and the order is the specification's: Q in words 0-14, the key in 15-22 (all zero here,
 * since no keyed mode is offered), the unique node id in 23, the control word in 24, and the payload
 * in 25-88.
 */
function compressNode(
  payload: readonly bigint[],
  level: number,
  index: number,
  rounds: number,
  isRoot: boolean,
  padBits: number,
  digestBits: number,
): bigint[] {
  const input = new Array<bigint>(N_WORDS);
  let at = 0;
  for (let j = 0; j < Q_WORDS; j++) input[at++] = Q[j]!;
  // The key. Eight zero words, because only the unkeyed mode is offered -- see the header.
  for (let j = 0; j < K_WORDS; j++) input[at++] = 0n;
  // The unique node id: the level in the top byte, the index within the level below it.
  input[at++] = ((BigInt(level) << 56n) | BigInt(index)) & MASK;
  /**
   * The control word, six bit fields in one word.
   *
   * `z` is the one that matters most: it is set only for the very last compression, so the root of
   * the tree hashes differently from every node below it. Without it a subtree's chaining value would
   * be a valid digest of its own prefix.
   */
  input[at++] =
    ((BigInt(rounds) << 48n) |
      (BigInt(L) << 40n) |
      (BigInt(isRoot ? 1 : 0) << 36n) |
      (BigInt(padBits) << 20n) |
      // The key length, zero throughout: bits 12-19.
      (BigInt(0) << 12n) |
      BigInt(digestBits)) &
    MASK;
  for (let j = 0; j < B_WORDS; j++) input[at++] = payload[j]!;
  return compress(input, rounds);
}

/** Big-endian words of a byte buffer, zero-padded to a full payload. */
function payloadFromBytes(bytes: Uint8Array, length: number): bigint[] {
  const out = new Array<bigint>(B_WORDS).fill(0n);
  for (let w = 0; w < B_WORDS; w++) {
    let value = 0n;
    for (let i = 0; i < 8; i++) {
      const at = w * 8 + i;
      value = (value << 8n) | BigInt(at < length ? bytes[at]! : 0);
    }
    out[w] = value;
  }
  return out;
}

export interface Md6Hasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

/**
 * MD6 at a given digest size, incremental.
 *
 * The tree is kept as a stack of partially filled levels, exactly as the reference's `md6_state` does,
 * which is what makes this streamable at all: a leaf is compressed as soon as its 512 bytes are full
 * *and* more input is known to be coming, and its chaining value goes into the level above. Only the
 * levels currently on the stack are held, so hashing a hundred gigabytes needs a few kilobytes of
 * state rather than a tree in memory.
 *
 * The "and more input is coming" half is not an optimisation. A full leaf that turns out to be the end
 * of the message must be compressed with `z = 1` if it is also the only node, so it cannot be
 * compressed until the next chunk arrives to prove it is not the last.
 */
export function createMd6(digestBits: number): Md6Hasher {
  if (!Number.isInteger(digestBits) || digestBits < 1 || digestBits > 512) {
    throw new Error(`MD6's digest size is 1 to 512 bits; this one is ${digestBits}.`);
  }
  const rounds = md6Rounds(digestBits);

  /** Level 1 holds message bytes; every level above holds whole chaining values. */
  const leaf = new Uint8Array(MD6_LEAF_BYTES);
  let leafBytes = 0;
  /** `above[i]` is the payload being filled at level `i + 2`, as chaining values. */
  const above: bigint[][] = [];
  const counts: number[] = [];
  let done = false;
  let result: Uint8Array | undefined;

  /** Push a finished chaining value up the tree, compressing any level it fills. */
  const pushUp = (value: bigint[], fromLevel: number, final: boolean): bigint[] | undefined => {
    let level = fromLevel + 1;
    let carried = value;
    for (;;) {
      const slot = level - 2;
      while (above.length <= slot) {
        above.push([]);
        counts.push(0);
      }
      above[slot]!.push(...carried);
      counts[slot]!++;

      if (!final && counts[slot]! < FAN_OUT) return undefined;
      if (final) {
        /**
         * A level holding exactly one child is not compressed -- it is passed through.
         *
         * The reference's `md6_process` returns early when `ell == top` and the level holds one
         * chaining value, which is what stops a one-child parent from being an extra round of
         * compression the published values do not have. It is also why `z` cannot simply be "the last
         * compression at the top level": the top level may not compress at all.
         */
        const isTop = slot === above.length - 1;
        if (isTop && counts[slot] === 1) return carried;
      }

      const padWords = B_WORDS - above[slot]!.length;
      const payload = [...above[slot]!, ...new Array<bigint>(padWords).fill(0n)];
      const isTop = slot === above.length - 1;
      const out = compressNode(
        payload,
        level,
        // Index within the level: how many nodes it has already produced.
        indexAt(level),
        rounds,
        final && isTop,
        padWords * 64,
        digestBits,
      );
      bumpIndex(level);
      above[slot] = [];
      counts[slot] = 0;
      if (final && isTop) return out;
      carried = out;
      level++;
    }
  };

  /** How many nodes each level has already emitted, which is its next node's index. */
  const indices = new Map<number, number>();
  function indexAt(level: number): number {
    return indices.get(level) ?? 0;
  }
  function bumpIndex(level: number): void {
    indices.set(level, indexAt(level) + 1);
  }

  return {
    update(chunk) {
      if (done) throw new Error("MD6: update after digest.");
      let at = 0;
      while (at < chunk.length) {
        // Compress a full leaf only once the next byte proves it is not the last.
        if (leafBytes === MD6_LEAF_BYTES) {
          const out = compressNode(
            payloadFromBytes(leaf, leafBytes),
            1,
            indexAt(1),
            rounds,
            false,
            0,
            digestBits,
          );
          bumpIndex(1);
          pushUp(out, 1, false);
          leafBytes = 0;
        }
        const take = Math.min(MD6_LEAF_BYTES - leafBytes, chunk.length - at);
        leaf.set(chunk.subarray(at, at + take), leafBytes);
        leafBytes += take;
        at += take;
      }
    },

    digest() {
      if (result) return Uint8Array.from(result);
      done = true;

      /**
       * The root, and the two cases it splits into.
       *
       * A message that fits in one leaf never builds a tree at all: that leaf *is* the root, so it is
       * compressed with `z = 1` and nothing goes upward. Otherwise the last leaf is compressed as an
       * ordinary node and `pushUp` walks the stack, compressing each level and marking only the
       * topmost one as the root.
       */
      const aloneAtTheTop = above.length === 0;
      const leafOut = compressNode(
        payloadFromBytes(leaf, leafBytes),
        1,
        indexAt(1),
        rounds,
        aloneAtTheTop,
        (MD6_LEAF_BYTES - leafBytes) * 8,
        digestBits,
      );
      bumpIndex(1);
      const root = aloneAtTheTop ? leafOut : pushUp(leafOut, 1, true)!;

      // The chaining value as bytes, big-endian words.
      const all = new Uint8Array(CHAIN_BYTES);
      for (let w = 0; w < C_WORDS; w++) {
        for (let i = 0; i < 8; i++) {
          all[w * 8 + i] = Number((root[w]! >> BigInt(56 - 8 * i)) & 0xffn);
        }
      }

      /**
       * The digest is the **tail**, not the head.
       *
       * `trim_hashval` in the reference copies the last `ceil(d/8)` bytes of the 128 and, for a `d`
       * that is not a whole number of bytes, shifts the whole thing left so the digest is
       * left-aligned. Taking the first bytes instead is wrong for every size and looks right for all
       * of them, which is the same trap Shabal's tail-of-B has.
       */
      const full = Math.ceil(digestBits / 8);
      const out = all.slice(CHAIN_BYTES - full);
      const spare = digestBits % 8;
      if (spare > 0) {
        for (let i = 0; i < full; i++) {
          out[i] = ((out[i]! << (8 - spare)) | (i + 1 < full ? out[i + 1]! >> spare : 0)) & 0xff;
        }
        out[full - 1] = (out[full - 1]! & ((0xff << (8 - spare)) & 0xff)) & 0xff;
      }
      result = out;
      return Uint8Array.from(result);
    },
  };
}

/** One-shot, for the tests and the vectors. */
export function md6(data: Uint8Array, digestBits: number): Uint8Array {
  const h = createMd6(digestBits);
  h.update(data);
  return h.digest();
}
