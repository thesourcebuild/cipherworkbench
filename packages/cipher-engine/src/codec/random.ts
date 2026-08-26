/**
 * The one place random bytes come from.
 *
 * `crypto.getRandomValues` is present in all three hosts this code runs in —
 * a browser tab, an Electron renderer, and Node 20+ under vitest — which is why
 * nothing here needs a per-host branch or a `node:crypto` import. The eslint
 * config bans `Math.random` across `packages/algos`, `packages/tools` and this
 * package so there is no second, weaker source to reach for by accident.
 */

/** `getRandomValues` refuses requests over 65536 bytes, so fill in chunks. */
const MAX_CHUNK = 65536;

export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new Error(`randomBytes needs a non-negative integer length, got ${length}`);
  }
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += MAX_CHUNK) {
    crypto.getRandomValues(out.subarray(offset, Math.min(offset + MAX_CHUNK, length)));
  }
  return out;
}

/**
 * A fresh nonce/IV, as the hex string the `bytes` option control stores. The
 * "Generate" button next to every key/IV field calls this — which is the whole
 * reason `C003` (nonce reuse) can offer a one-click fix instead of just telling
 * the user off.
 */
export function randomHex(length: number): string {
  let out = "";
  for (const byte of randomBytes(length)) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * An unbiased integer in `[0, bound)`, for any bound up to `Number.MAX_SAFE_INTEGER`.
 *
 * **Rejection, not a modulo, and that is the whole substance of this file beyond `randomBytes`.**
 * `randomBytes(1)[0] % bound` is biased whenever 256 is not a multiple of `bound`: at `bound = 70`
 * the first 46 values come up about 1.4% more often than the rest. The bias is invisible in any
 * output you look at, survives every round-trip test, and makes an entropy figure a claim the code
 * cannot support -- which is why the password generator went to the trouble first, and why this is
 * now one implementation rather than one per caller.
 *
 * `bigint` rather than 32-bit arithmetic, deliberately. A range can legitimately exceed 2^32 -- a
 * random integer between 1 and 10^15 is an ordinary thing to ask for -- and building the value in a
 * `number` from seven bytes crosses 2^53, where the low bits stop existing. That is the same hazard
 * `xxhash3.ts` and `simon-speck.ts` use `bigint` for, and the cost here is nothing: this draws at most
 * a couple of times per value.
 *
 * The loop terminates with probability 1 and expected iterations below 2, because `limit` is at least
 * half of `span`: `span % bound < bound <= span / 2` for every bound that needs more than one byte.
 */
export function randomBelow(bound: number): number {
  if (!Number.isSafeInteger(bound) || bound < 1) {
    throw new Error(`randomBelow needs a safe positive integer bound, got ${bound}`);
  }
  if (bound === 1) return 0;
  const big = BigInt(bound);
  // `toString(2).length` is exactly ceil(log2(bound + 1)), which is the bit width to draw at.
  const byteCount = Math.ceil(big.toString(2).length / 8);
  const span = 1n << BigInt(byteCount * 8);
  // The largest multiple of `bound` that fits; anything at or above it is redrawn.
  const limit = span - (span % big);
  for (;;) {
    let value = 0n;
    for (const byte of randomBytes(byteCount)) value = (value << 8n) | BigInt(byte);
    if (value < limit) return Number(value % big);
  }
}

/**
 * An unbiased integer in the **inclusive** range `[min, max]`.
 *
 * Inclusive because that is what people mean by "between 1 and 6", and an off-by-one here is the kind
 * of thing that never shows up in a sample of a hundred: a die that never rolls a 6 looks like luck.
 * `tests/algos-random.test.ts` asserts both endpoints are actually produced.
 */
export function randomInt(min: number, max: number): number {
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max)) {
    throw new Error(`randomInt needs safe integer bounds, got ${min} and ${max}`);
  }
  if (max < min) throw new Error(`randomInt needs max >= min, got ${min} and ${max}`);
  const span = max - min + 1;
  if (!Number.isSafeInteger(span)) {
    throw new Error(
      `randomInt cannot span ${min} to ${max}: that is more than ${Number.MAX_SAFE_INTEGER} values.`,
    );
  }
  return min + randomBelow(span);
}

/**
 * A uniform double in `[0, 1)` with all 53 bits of the mantissa random.
 *
 * The obvious constructions are both wrong, and wrong in ways nothing visible catches. `byte / 256`
 * gives 256 distinct values. `randomBelow(2 ** 53) / 2 ** 53` is correct but draws seven bytes and a
 * `bigint` per value. And `Math.random()` is not a CSPRNG, which is why it is eslint-banned in the
 * packages that reach this one.
 *
 * So: 26 bits and 27 bits combined into the 53 the format has. That is the construction the reference
 * implementations of every serious PRNG use, and it is exact -- every representable double in the
 * interval is reachable with equal probability.
 */
export function randomFloat(): number {
  const bytes = randomBytes(7);
  // 26 bits from the first three and a half bytes, 27 from the rest.
  const high = ((bytes[0]! << 18) | (bytes[1]! << 10) | (bytes[2]! << 2) | (bytes[3]! >> 6)) >>> 0;
  const low = (((bytes[3]! & 0x3f) << 21) | (bytes[4]! << 13) | (bytes[5]! << 5) | (bytes[6]! >> 3)) >>> 0;
  return (high * 2 ** 27 + low) / 2 ** 53;
}

/**
 * Fisher-Yates over `randomBelow`, returning a new array.
 *
 * In here rather than in a caller because the two things that go wrong with a shuffle are both
 * arithmetic: drawing from `[0, length)` instead of `[0, i]` gives a distribution that is not uniform
 * over permutations, and iterating upwards rather than downwards gives the same. One implementation,
 * one test that walks the distribution of a three-element array over all six orders.
 */
export function shuffled<T>(items: readonly T[]): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomBelow(i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

/**
 * `count` distinct integers from the inclusive range, in draw order.
 *
 * Two branches, because one algorithm is degenerate at each end of the ratio. Rejecting duplicates is
 * the right thing when the range dwarfs the count -- the expected number of redraws is tiny -- and it
 * is a coupon-collector problem when they are close: asking for all 100 values in 1..100 that way
 * spends its last draws waiting for one specific number. A partial Fisher-Yates over the whole range
 * is exact and instant there, and impossible when the range is 10^15 wide.
 *
 * The threshold is `count * 4`, so the rejection branch never runs at worse than a 25% collision rate
 * and the array branch never allocates more than four times what was asked for.
 */
export function randomIntSample(min: number, max: number, count: number): number[] {
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new Error(`randomIntSample needs a non-negative integer count, got ${count}`);
  }
  const span = max - min + 1;
  if (!Number.isSafeInteger(span) || span < 1) {
    throw new Error(`randomIntSample needs max >= min, got ${min} and ${max}`);
  }
  if (count > span) {
    throw new Error(`Cannot draw ${count} distinct values from ${span}.`);
  }
  if (span <= count * 4) {
    const pool = Array.from({ length: span }, (_, index) => min + index);
    const out: number[] = [];
    for (let i = 0; i < count; i++) {
      const j = i + randomBelow(span - i);
      [pool[i], pool[j]] = [pool[j]!, pool[i]!];
      out.push(pool[i]!);
    }
    return out;
  }
  const seen = new Set<number>();
  const out: number[] = [];
  while (out.length < count) {
    const value = randomInt(min, max);
    if (seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}
