/**
 * XXH3-64 and XXH3-128, from the xxHash specification (`doc/xxhash_spec.md`, Cyan4973/xxHash).
 *
 * The two remaining algorithms the reference this app follows offers and no *pure-JavaScript*
 * library provides. `hash-wasm` has both -- as WebAssembly, which is what emn178's online-tools
 * uses -- and it is a devDependency here serving as the differential oracle these need rather than
 * a runtime dependency: instantiating WebAssembly costs a `'wasm-unsafe-eval'` CSP relaxation, and
 * the desktop CSP allows only `'self'` plus per-script hashes.
 *
 * XXH3 is four algorithms wearing one name, selected by input length -- 0-16, 17-128, 129-240 and
 * 241+ bytes -- and each has its own secret offsets and finalisation. That is why the tests walk
 * *every* length from 0 to 1200 rather than sampling: a boundary is where this can be wrong, and
 * there are four of them.
 *
 * **On BigInt.** Every 64-bit value here is a `bigint`, and that is a deliberate first-version
 * choice rather than an oversight. XXH3 is dense 64-bit arithmetic with a 64x64->128 multiply in
 * four places, and a hand-rolled 32-bit-limb version is perhaps five times faster and very much
 * more than five times easier to get subtly wrong. This repo already reaches for BigInt where
 * correctness dominates -- the wide CRC engine, RSA's modular exponentiation. The cost is stated
 * honestly in `WHY-NOT-A-LIBRARY.md`: this is the slowest hash here, and if that becomes a problem
 * the accumulate/scramble loop is the only part worth converting, because it is the only part that
 * scales with input size.
 */

const MASK = (1n << 64n) - 1n;
const M32 = 0xffffffffn;

const PRIME32_1 = 0x9e3779b1n;
const PRIME32_2 = 0x85ebca77n;
const PRIME32_3 = 0xc2b2ae3dn;
const PRIME64_1 = 0x9e3779b185ebca87n;
const PRIME64_2 = 0xc2b2ae3d27d4eb4fn;
const PRIME64_3 = 0x165667b19e3779f9n;
const PRIME64_4 = 0x85ebca77c2b2ae63n;
const PRIME64_5 = 0x27d4eb2f165667c5n;
const PRIME_MX1 = 0x165667919e3779f9n;
const PRIME_MX2 = 0x9fb21c651e98df25n;

/** The 192-byte default secret, verbatim from the specification. */
const SECRET = /* @__PURE__ */ Uint8Array.from([
  0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad,
  0x1c, 0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3,
  0x67, 0x1f, 0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc,
  0xff, 0x72, 0x21, 0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6,
  0x81, 0x3a, 0x26, 0x4c, 0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65,
  0x8b, 0x1b, 0x53, 0x2e, 0xa3, 0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19,
  0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8, 0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9,
  0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d, 0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31,
  0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64, 0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb,
  0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb, 0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0,
  0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e, 0x2b, 0x16, 0xbe, 0x58, 0x7d,
  0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce, 0x45, 0xcb, 0x3a, 0x8f,
  0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
]);

const STRIPE_LEN = 64;
/** The reference's internal buffer size. Its digest path depends on this exact value -- see below. */
const INTERNAL_BUFFER = 256;

const u64 = (x: bigint): bigint => x & MASK;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const sub = (a: bigint, b: bigint): bigint => (a - b) & MASK;
const mul = (a: bigint, b: bigint): bigint => (a * b) & MASK;
const lo32 = (x: bigint): bigint => x & M32;
const hi32 = (x: bigint): bigint => (x >> 32n) & M32;

function rotl64(x: bigint, bits: bigint): bigint {
  return ((x << bits) | (x >> (64n - bits))) & MASK;
}

function bswap64(x: bigint): bigint {
  let out = 0n;
  for (let i = 0n; i < 8n; i++) out = (out << 8n) | ((x >> (i * 8n)) & 0xffn);
  return out;
}

function bswap32(x: bigint): bigint {
  return (
    (((x & 0xffn) << 24n) |
      ((x & 0xff00n) << 8n) |
      ((x >> 8n) & 0xff00n) |
      ((x >> 24n) & 0xffn)) &
    M32
  );
}

/** The full 128-bit product, folded to 64 bits by XOR. Four places need it; none is hot. */
function mul128Fold64(a: bigint, b: bigint): bigint {
  const product = a * b;
  return u64(product ^ (product >> 64n));
}

function readU64(bytes: Uint8Array, offset: number): bigint {
  let out = 0n;
  for (let i = 7; i >= 0; i--) out = (out << 8n) | BigInt(bytes[offset + i]!);
  return out;
}

function readU32(bytes: Uint8Array, offset: number): bigint {
  return BigInt(
    (bytes[offset]! |
      (bytes[offset + 1]! << 8) |
      (bytes[offset + 2]! << 16) |
      (bytes[offset + 3]! << 24)) >>>
      0,
  );
}

function avalanche(x: bigint): bigint {
  let v = x ^ (x >> 37n);
  v = mul(v, PRIME_MX1);
  return u64(v ^ (v >> 32n));
}

function avalanche64(x: bigint): bigint {
  let v = x ^ (x >> 33n);
  v = mul(v, PRIME64_2);
  v ^= v >> 29n;
  v = mul(v, PRIME64_3);
  return u64(v ^ (v >> 32n));
}

/**
 * The secret a seeded long-input hash uses.
 *
 * Only the 241+ byte path derives a secret from the seed; the shorter paths take the seed directly
 * and keep the default secret. Getting that split wrong gives correct short hashes and wrong long
 * ones, which is exactly the kind of thing the per-length tests exist to find.
 */
function deriveSecret(seed: bigint): Uint8Array {
  if (seed === 0n) return SECRET;
  const out = new Uint8Array(SECRET.length);
  for (let i = 0; i < 12; i++) {
    const a = add(readU64(SECRET, i * 16), seed);
    const b = sub(readU64(SECRET, i * 16 + 8), seed);
    writeU64(out, i * 16, a);
    writeU64(out, i * 16 + 8, b);
  }
  return out;
}

function writeU64(bytes: Uint8Array, offset: number, value: bigint): void {
  for (let i = 0; i < 8; i++) bytes[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
}

/** One 16-byte chunk against 16 bytes of secret. The building block of the medium paths. */
function mixStep(
  input: Uint8Array,
  inputOffset: number,
  secret: Uint8Array,
  secretOffset: number,
  seed: bigint,
): bigint {
  const d0 = readU64(input, inputOffset);
  const d1 = readU64(input, inputOffset + 8);
  const s0 = readU64(secret, secretOffset);
  const s1 = readU64(secret, secretOffset + 8);
  return mul128Fold64(d0 ^ add(s0, seed), d1 ^ sub(s1, seed));
}

// ── 0 to 16 bytes ───────────────────────────────────────────────────────────

function len1to3(input: Uint8Array, seed: bigint, secret: Uint8Array, wide: boolean) {
  const length = input.length;
  // The four bytes are deliberately not in input order: last, length, first, middle.
  const combined = BigInt(
    ((input[length - 1]! | (length << 8) | (input[0]! << 16) | (input[length >> 1]! << 24)) >>>
      0) >>>
      0,
  );
  const s0 = readU32(secret, 0);
  const s1 = readU32(secret, 4);
  const low = avalanche64(u64(add(u64(s0 ^ s1), seed) ^ combined));
  if (!wide) return { low, high: 0n };
  const s2 = readU32(secret, 8);
  const s3 = readU32(secret, 12);
  const flipped = u64(rotl32(bswap32(combined), 13n));
  const high = avalanche64(u64(sub(u64(s2 ^ s3), seed) ^ flipped));
  return { low, high };
}

/** A 32-bit rotate, which the 1-to-3 path needs and nothing else here does. */
function rotl32(x: bigint, bits: bigint): bigint {
  return ((x << bits) | (x >> (32n - bits))) & M32;
}

function len4to8(input: Uint8Array, seed: bigint, secret: Uint8Array, wide: boolean) {
  const length = input.length;
  const first = readU32(input, 0);
  const last = readU32(input, length - 4);
  // The seed's low half is byte-swapped into its high half before use.
  const modified = u64(seed ^ (bswap32(lo32(seed)) << 32n));

  if (!wide) {
    const s0 = readU64(secret, 8);
    const s1 = readU64(secret, 16);
    const combined = u64(last | (first << 32n));
    let value = u64(sub(u64(s0 ^ s1), modified) ^ combined);
    value = u64(value ^ rotl64(value, 49n) ^ rotl64(value, 24n));
    value = mul(value, PRIME_MX2);
    value = u64(value ^ ((value >> 35n) + BigInt(length)));
    value = mul(value, PRIME_MX2);
    return { low: u64(value ^ (value >> 28n)), high: 0n };
  }

  const s0 = readU64(secret, 16);
  const s1 = readU64(secret, 24);
  const combined = u64(first | (last << 32n));
  const value = u64(add(u64(s0 ^ s1), modified) ^ combined);
  const product = value * u64(add(PRIME64_1, BigInt(length) << 2n));
  let high = u64(product >> 64n);
  let low = u64(product);
  high = add(high, u64(low << 1n));
  low = u64(low ^ (high >> 3n));
  low = u64(low ^ (low >> 35n));
  low = mul(low, PRIME_MX2);
  low = u64(low ^ (low >> 28n));
  return { low, high: avalanche(high) };
}

function len9to16(input: Uint8Array, seed: bigint, secret: Uint8Array, wide: boolean) {
  const length = input.length;
  const first = readU64(input, 0);
  const last = readU64(input, length - 8);

  if (!wide) {
    const lowMix = u64(add(u64(readU64(secret, 24) ^ readU64(secret, 32)), seed) ^ first);
    const highMix = u64(sub(u64(readU64(secret, 40) ^ readU64(secret, 48)), seed) ^ last);
    const product = lowMix * highMix;
    const value = add(
      add(add(BigInt(length), bswap64(lowMix)), highMix),
      u64(u64(product) ^ u64(product >> 64n)),
    );
    return { low: avalanche(value), high: 0n };
  }

  const val1 = u64(sub(u64(readU64(secret, 32) ^ readU64(secret, 40)), seed) ^ first ^ last);
  const val2 = u64(add(u64(readU64(secret, 48) ^ readU64(secret, 56)), seed) ^ last);
  const product = val1 * PRIME64_1;
  let low = add(u64(product), u64(BigInt(length - 1) << 54n));
  let high = add(add(u64(product >> 64n), hi32(val2) << 32n), mul(lo32(val2), PRIME32_2));
  low = u64(low ^ bswap64(high));
  const product2 = low * PRIME64_2;
  low = u64(product2);
  high = add(u64(product2 >> 64n), mul(high, PRIME64_2));
  return { low: avalanche(low), high: avalanche(high) };
}

function len0to16(input: Uint8Array, seed: bigint, secret: Uint8Array, wide: boolean) {
  const length = input.length;
  if (length > 8) return len9to16(input, seed, secret, wide);
  if (length >= 4) return len4to8(input, seed, secret, wide);
  if (length > 0) return len1to3(input, seed, secret, wide);

  if (!wide) {
    return {
      low: avalanche64(u64(seed ^ readU64(secret, 56) ^ readU64(secret, 64))),
      high: 0n,
    };
  }
  return {
    low: avalanche64(u64(seed ^ readU64(secret, 64) ^ readU64(secret, 72))),
    high: avalanche64(u64(seed ^ readU64(secret, 80) ^ readU64(secret, 88))),
  };
}

// ── 17 to 240 bytes ─────────────────────────────────────────────────────────

/** XXH3-128 mixes two chunks at a time and cross-feeds the raw words into the other accumulator. */
function mixTwoChunks(
  acc: bigint[],
  input: Uint8Array,
  offset1: number,
  offset2: number,
  secret: Uint8Array,
  secretOffset: number,
  seed: bigint,
): void {
  const a0 = readU64(input, offset2);
  const a1 = readU64(input, offset2 + 8);
  const b0 = readU64(input, offset1);
  const b1 = readU64(input, offset1 + 8);
  acc[0] = add(acc[0]!, mixStep(input, offset1, secret, secretOffset, seed));
  acc[1] = add(acc[1]!, mixStep(input, offset2, secret, secretOffset + 16, seed));
  acc[0] = u64(acc[0]! ^ add(a0, a1));
  acc[1] = u64(acc[1]! ^ add(b0, b1));
}

function len17to240(input: Uint8Array, seed: bigint, secret: Uint8Array, wide: boolean) {
  const length = input.length;
  const acc = [mul(BigInt(length), PRIME64_1), 0n];

  if (length <= 128) {
    // N chunks from the front and N from the back, whichever N covers the input; the pairs are
    // walked from the outside in, which is why the loop counts down.
    const rounds = ((length - 1) >> 5) + 1;
    for (let i = rounds - 1; i >= 0; i--) {
      const start = i * 16;
      const end = length - i * 16 - 16;
      if (wide) {
        mixTwoChunks(acc, input, start, end, secret, i * 32, seed);
      } else {
        acc[0] = add(acc[0]!, mixStep(input, start, secret, i * 32, seed));
        acc[0] = add(acc[0]!, mixStep(input, end, secret, i * 32 + 16, seed));
      }
    }
  } else if (!wide) {
    const chunks = length >> 4;
    for (let i = 0; i < 8; i++) {
      acc[0] = add(acc[0]!, mixStep(input, i * 16, secret, i * 16, seed));
    }
    acc[0] = avalanche(acc[0]!);
    for (let i = 8; i < chunks; i++) {
      // The `+ 3` secret offset is not a typo: past the first 128 bytes the secret is read from an
      // unaligned position, which is part of the specification.
      acc[0] = add(acc[0]!, mixStep(input, i * 16, secret, (i - 8) * 16 + 3, seed));
    }
    acc[0] = add(acc[0]!, mixStep(input, length - 16, secret, 119, seed));
  } else {
    const chunks = length >> 5;
    for (let i = 0; i < 4; i++) {
      mixTwoChunks(acc, input, i * 32, i * 32 + 16, secret, i * 32, seed);
    }
    acc[0] = avalanche(acc[0]!);
    acc[1] = avalanche(acc[1]!);
    for (let i = 4; i < chunks; i++) {
      mixTwoChunks(acc, input, i * 32, i * 32 + 16, secret, (i - 4) * 32 + 3, seed);
    }
    // The final pair reverses the half order *and* negates the seed. Both are deliberate.
    mixTwoChunks(acc, input, length - 16, length - 32, secret, 103, u64(0n - seed));
  }

  if (!wide) return { low: avalanche(acc[0]!), high: 0n };
  const low = add(acc[0]!, acc[1]!);
  const high = add(
    add(mul(acc[0]!, PRIME64_1), mul(acc[1]!, PRIME64_4)),
    mul(sub(BigInt(length), seed), PRIME64_2),
  );
  return { low: avalanche(low), high: u64(0n - avalanche(high)) };
}

// ── 241+ bytes ──────────────────────────────────────────────────────────────

const INIT_ACC: readonly bigint[] = [
  PRIME32_3,
  PRIME64_1,
  PRIME64_2,
  PRIME64_3,
  PRIME64_4,
  PRIME32_2,
  PRIME64_5,
  PRIME32_1,
];

/**
 * One 64-byte stripe into the eight accumulators.
 *
 * The only loop whose cost scales with input size, and therefore the only candidate if this ever
 * needs to be faster. Note the `i ^ 1` lane crossing on the plain addition -- each accumulator gets
 * the *other* lane of its pair, which is what stops the eight lanes being eight independent hashes.
 */
function accumulate(
  acc: bigint[],
  input: Uint8Array,
  offset: number,
  secret: Uint8Array,
  secretOffset: number,
): void {
  for (let i = 0; i < 8; i++) {
    const data = readU64(input, offset + i * 8);
    const value = u64(data ^ readU64(secret, secretOffset + i * 8));
    acc[i ^ 1] = add(acc[i ^ 1]!, data);
    acc[i] = add(acc[i]!, lo32(value) * hi32(value));
  }
}

function scramble(acc: bigint[], secret: Uint8Array): void {
  const offset = secret.length - STRIPE_LEN;
  for (let i = 0; i < 8; i++) {
    let v = u64(acc[i]! ^ (acc[i]! >> 47n));
    v = u64(v ^ readU64(secret, offset + i * 8));
    acc[i] = mul(v, PRIME32_1);
  }
}

function finalMerge(
  acc: readonly bigint[],
  init: bigint,
  secret: Uint8Array,
  secretOffset: number,
): bigint {
  let result = init;
  for (let i = 0; i < 4; i++) {
    const a = u64(acc[i * 2]! ^ readU64(secret, secretOffset + i * 16));
    const b = u64(acc[i * 2 + 1]! ^ readU64(secret, secretOffset + i * 16 + 8));
    result = add(result, mul128Fold64(a, b));
  }
  return avalanche(result);
}

function stripesPerBlock(secret: Uint8Array): number {
  return (secret.length - STRIPE_LEN) >> 3;
}

function hashLong(input: Uint8Array, secret: Uint8Array, wide: boolean) {
  const acc = [...INIT_ACC];
  const perBlock = stripesPerBlock(secret);
  const blockSize = STRIPE_LEN * perBlock;
  const length = input.length;

  // Every block but the last, whether or not the last one happens to be full.
  const blocks = Math.floor((length - 1) / blockSize);
  for (let block = 0; block < blocks; block++) {
    for (let stripe = 0; stripe < perBlock; stripe++) {
      accumulate(acc, input, block * blockSize + stripe * STRIPE_LEN, secret, stripe * 8);
    }
    scramble(acc, secret);
  }

  // The last block: every whole stripe except the final one, then the last 64 bytes as a stripe.
  // Those last 64 bytes may overlap the stripe before them, which is intended.
  const consumed = blocks * blockSize;
  const remaining = length - consumed;
  const fullStripes = Math.floor((remaining - 1) / STRIPE_LEN);
  for (let stripe = 0; stripe < fullStripes; stripe++) {
    accumulate(acc, input, consumed + stripe * STRIPE_LEN, secret, stripe * 8);
  }
  accumulate(acc, input, length - STRIPE_LEN, secret, secret.length - 71);

  const low = finalMerge(acc, mul(BigInt(length), PRIME64_1), secret, 11);
  if (!wide) return { low, high: 0n };
  const high = finalMerge(
    acc,
    u64(~mul(BigInt(length), PRIME64_2)),
    secret,
    secret.length - 75,
  );
  return { low, high };
}

function xxh3(input: Uint8Array, seed: bigint, wide: boolean) {
  const length = input.length;
  if (length <= 16) return len0to16(input, seed, SECRET, wide);
  if (length <= 240) return len17to240(input, seed, SECRET, wide);
  // Only the long path derives a secret from the seed; the shorter ones use the seed directly.
  return hashLong(input, deriveSecret(seed), wide);
}

/** XXH3-64. Returns the digest as a bigint; `xxh3_64Bytes` gives the canonical big-endian bytes. */
export function xxh3_64(input: Uint8Array, seed = 0n): bigint {
  return xxh3(input, u64(seed), false).low;
}

/** XXH3-128. `low` and `high` as the specification names them; the canonical output is high‖low. */
export function xxh3_128(input: Uint8Array, seed = 0n): { low: bigint; high: bigint } {
  return xxh3(input, u64(seed), true);
}

function toBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[length - 1 - i] = Number((value >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

/**
 * The canonical byte form: **big-endian**, so the hex reads the same as the decimal value.
 *
 * XXH3-128's canonical form is the high half followed by the low half -- which is why
 * `XXH128("abc")` prints as `06b05ab6733a6185` `78af5f94892f3950` and its second half is exactly
 * `XXH3-64("abc")`. That relationship is asserted in the tests, because it is the cheapest possible
 * check that the two are wired to the same computation.
 */
export const xxh3_64Bytes = (input: Uint8Array, seed = 0n): Uint8Array =>
  toBytes(xxh3_64(input, seed), 8);

export const xxh3_128Bytes = (input: Uint8Array, seed = 0n): Uint8Array => {
  const { low, high } = xxh3_128(input, seed);
  const out = new Uint8Array(16);
  out.set(toBytes(high, 8), 0);
  out.set(toBytes(low, 8), 8);
  return out;
};

// ── incremental ─────────────────────────────────────────────────────────────

/** Stripes in the reference's internal buffer: 256 / 64. Its digest path depends on this. */
const BUFFER_STRIPES = INTERNAL_BUFFER / STRIPE_LEN;
/** Where `finalMerge` reads its secret for the low half. */
const MERGE_START = 11;
/** Backed off from the secret's scramble segment to place the final stripe's secret. */
const LAST_ACC_START = 7;

/**
 * Incremental XXH3, following the reference state machine rather than a simpler equivalent.
 *
 * The obvious implementation -- buffer everything and hash at the end -- is correct and useless: it
 * would hold an entire file in memory, which is the one thing the streaming path exists to avoid.
 * So this reproduces `XXH3_update`/`XXH3_digest` structurally, including two details that look like
 * accidents and are not:
 *
 *  - **The 256-byte buffer is never cleared.** When fewer than 64 bytes are buffered at digest
 *    time, the final stripe is assembled from the *tail* of the buffer followed by those bytes --
 *    the tail still holding the end of the previous 256-byte fill. That only works because the
 *    buffer is exactly 256 bytes and is always written from index 0.
 *  - **`digest()` works on a copy of the accumulators.** Digesting must not consume the state, and
 *    the last-stripe accumulation would otherwise do exactly that. `tests/algos-xxh3.test.ts`
 *    digests twice and requires the same answer.
 */
class Xxh3Stream {
  private readonly acc = [...INIT_ACC];
  private readonly buffer = new Uint8Array(INTERNAL_BUFFER);
  private buffered = 0;
  private stripesSoFar = 0;
  private total = 0;
  private readonly secret: Uint8Array;
  private readonly perBlock: number;

  constructor(
    private readonly seed: bigint,
    private readonly wide: boolean,
  ) {
    this.secret = deriveSecret(u64(seed));
    this.perBlock = stripesPerBlock(this.secret);
  }

  /**
   * `nbStripes` stripes from `offset`, scrambling whenever a block completes.
   *
   * Loops over block boundaries rather than handling one, because `update` can hand it a whole
   * chunk's worth of stripes -- a 100 KB chunk is over 1500 stripes and crosses many blocks.
   */
  private consumeStripes(
    acc: bigint[],
    stripesSoFar: number,
    input: Uint8Array,
    offset: number,
    nbStripes: number,
  ): number {
    let soFar = stripesSoFar;
    let done = 0;
    while (done < nbStripes) {
      const room = this.perBlock - soFar;
      const take = Math.min(room, nbStripes - done);
      for (let i = 0; i < take; i++) {
        accumulate(acc, input, offset + (done + i) * STRIPE_LEN, this.secret, (soFar + i) * 8);
      }
      done += take;
      soFar += take;
      if (soFar === this.perBlock) {
        scramble(acc, this.secret);
        soFar = 0;
      }
    }
    return soFar;
  }

  update(chunk: Uint8Array): void {
    this.total += chunk.length;
    let offset = 0;
    let remaining = chunk.length;

    if (remaining <= INTERNAL_BUFFER - this.buffered) {
      this.buffer.set(chunk, this.buffered);
      this.buffered += remaining;
      return;
    }

    if (this.buffered > 0) {
      const load = INTERNAL_BUFFER - this.buffered;
      this.buffer.set(chunk.subarray(0, load), this.buffered);
      offset += load;
      remaining -= load;
      this.stripesSoFar = this.consumeStripes(
        this.acc,
        this.stripesSoFar,
        this.buffer,
        0,
        BUFFER_STRIPES,
      );
      this.buffered = 0;
    }

    /**
     * Strictly greater, and a stripe count that deliberately leaves a remainder.
     *
     * `(remaining - 1) / 64` guarantees at least one byte stays unconsumed -- the reference asserts
     * that invariant twice -- and it is what stops the final stripe being accumulated a second time
     * at digest. Consuming in whole 256-byte buffers instead looks equivalent and is not: for an
     * input whose length is an exact multiple of 256 it leaves nothing buffered, `digest` then folds
     * the retained tail stripe in again, and the answer is wrong for exactly those lengths. Twelve
     * of them showed up in the chunked-versus-one-shot test.
     */
    if (remaining > INTERNAL_BUFFER) {
      const nbStripes = Math.floor((remaining - 1) / STRIPE_LEN);
      this.stripesSoFar = this.consumeStripes(
        this.acc,
        this.stripesSoFar,
        chunk,
        offset,
        nbStripes,
      );
      offset += nbStripes * STRIPE_LEN;
      remaining -= nbStripes * STRIPE_LEN;
      // Retain the last consumed stripe at the buffer's tail; `digest` reaches back for it when
      // fewer than 64 bytes end up buffered. See the class comment.
      this.buffer.set(
        chunk.subarray(offset - STRIPE_LEN, offset),
        INTERNAL_BUFFER - STRIPE_LEN,
      );
    }

    this.buffer.set(chunk.subarray(offset), 0);
    this.buffered = remaining;
  }

  digest(): { low: bigint; high: bigint } {
    if (this.total <= 240) {
      // Everything still fits in the buffer, so the short and medium paths apply unchanged.
      return xxh3(this.buffer.subarray(0, this.total), u64(this.seed), this.wide);
    }

    // A copy: the last stripe must not be folded into the live state.
    const acc = [...this.acc];
    if (this.buffered >= STRIPE_LEN) {
      const nbStripes = Math.floor((this.buffered - 1) / STRIPE_LEN);
      this.consumeStripes(acc, this.stripesSoFar, this.buffer, 0, nbStripes);
      accumulate(
        acc,
        this.buffer,
        this.buffered - STRIPE_LEN,
        this.secret,
        this.secret.length - STRIPE_LEN - LAST_ACC_START,
      );
    } else {
      const lastStripe = new Uint8Array(STRIPE_LEN);
      const catchup = STRIPE_LEN - this.buffered;
      lastStripe.set(this.buffer.subarray(INTERNAL_BUFFER - catchup), 0);
      lastStripe.set(this.buffer.subarray(0, this.buffered), catchup);
      accumulate(
        acc,
        lastStripe,
        0,
        this.secret,
        this.secret.length - STRIPE_LEN - LAST_ACC_START,
      );
    }

    const low = finalMerge(acc, mul(BigInt(this.total), PRIME64_1), this.secret, MERGE_START);
    if (!this.wide) return { low, high: 0n };
    const high = finalMerge(
      acc,
      u64(~mul(BigInt(this.total), PRIME64_2)),
      this.secret,
      this.secret.length - 75,
    );
    return { low, high };
  }
}

/** Incremental XXH3-64, shaped like every other hasher here: `update` then `digest`. */
export function createXxh3_64(seed = 0n): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
  digestBytes(): Uint8Array;
} {
  const stream = new Xxh3Stream(seed, false);
  const finish = () => toBytes(stream.digest().low, 8);
  return { update: (chunk) => stream.update(chunk), digest: finish, digestBytes: finish };
}

/** Incremental XXH3-128. The canonical byte order is high‖low -- see `xxh3_128Bytes`. */
export function createXxh3_128(seed = 0n): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
  digestBytes(): Uint8Array;
} {
  const stream = new Xxh3Stream(seed, true);
  const finish = () => {
    const { low, high } = stream.digest();
    const out = new Uint8Array(16);
    out.set(toBytes(high, 8), 0);
    out.set(toBytes(low, 8), 8);
    return out;
  };
  return { update: (chunk) => stream.update(chunk), digest: finish, digestBytes: finish };
}
