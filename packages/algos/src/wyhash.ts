/**
 * wyhash final 3.
 *
 * `not-a-mac`. The seed is not a key: recovering it from a handful of known outputs is
 * straightforward, and the design does not claim otherwise.
 *
 * Its successor rapidhash lives in `rapidhash.ts` -- separately, because that turned out to be four
 * distinct published versions rather than one. The two share the mixing primitive below and nothing
 * else.
 *
 * **Its whole diffusion is a 128-bit multiply.** `mum(A, B)` takes the full 128-bit product and keeps
 * both halves; `mix(A, B)` folds them together with XOR. That single operation is where all of it comes
 * from -- there is no S-box, no round constant table and no permutation anywhere. `bigint` is used
 * because JavaScript has no other way to get the high half of a 64x64 product: `Math.imul` reaches
 * 32x32, and a double loses the low bits above 2^53. That makes this among the slowest of the
 * non-cryptographic hashes here, which is a consequence of the platform rather than of the design.
 *
 * **The vectors are published and they cross every branch.** Seven of them, from Zig's standard
 * library, which states that it runs the reference's own `test_vector.cpp` at commit `77e50f2`. Their
 * lengths are 0, 1, 3, 14, 26, 62 and 80 -- which is not incidental: wyhash dispatches at 4, 16 and 48
 * bytes, so those seven reach all four of its paths. That matters more than count for a function whose
 * short paths are hand-written.
 *
 * **Final 3, not final 4.** The two differ in their secret quadruple and their mixing and produce
 * unrelated output. Final 3 ships because it is the version a reachable published vector exists for --
 * final 4's own test program only *prints* its values. Same judgement as GIMLI's two padding
 * conventions.
 *
 * **The 3-byte read double-counts a byte, and that is correct.** `read3(p, k)` is
 * `p[0] << 16 | p[k >> 1] << 8 | p[k - 1]`, so for a two-byte input `p[1]` is read twice. This repo has
 * a note elsewhere about exactly that gather being a *bug* when borrowed into SpookyHash's tail -- here
 * it is the reference's own definition and must stay.
 */

const MASK = (1n << 64n) - 1n;
const u64 = (x: bigint): bigint => x & MASK;

/** The full 128-bit product: low half first, high half second. */
function mum(a: bigint, b: bigint): [bigint, bigint] {
  const product = a * b;
  return [u64(product), u64(product >> 64n)];
}

const mix = (a: bigint, b: bigint): bigint => {
  const [low, high] = mum(a, b);
  return u64(low ^ high);
};

const read64 = (p: Uint8Array, at: number): bigint => {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(p[at + i]!);
  return value;
};

const read32 = (p: Uint8Array, at: number): bigint => {
  let value = 0n;
  for (let i = 3; i >= 0; i--) value = (value << 8n) | BigInt(p[at + i]!);
  return value;
};

/** wyhash's default secret, `_wyp`, at final 3. Final 4 uses a different quadruple. */
export const WYHASH_SECRET: readonly bigint[] = [
  0xa0761d6478bd642fn,
  0xe7037ed1a0b428dbn,
  0x8ebc6af09c88c6e3n,
  0x589965cc75374cc3n,
];

/** wyhash final 3. */
export function wyhash(message: Uint8Array, seed: bigint = 0n, secret: readonly bigint[] = WYHASH_SECRET): bigint {
  const len = message.length;
  let at = 0;
  let state = u64(seed ^ mix(u64(seed ^ secret[0]!), secret[1]!));
  let a: bigint;
  let b: bigint;

  if (len <= 16) {
    if (len >= 4) {
      a = u64((read32(message, at) << 32n) | read32(message, at + ((len >> 3) << 2)));
      b = u64((read32(message, at + len - 4) << 32n) | read32(message, at + len - 4 - ((len >> 3) << 2)));
    } else if (len > 0) {
      // Reads p[k >> 1] twice for a two-byte input. The reference's own definition; see the header.
      a = (BigInt(message[at]!) << 16n) | (BigInt(message[at + (len >> 1)]!) << 8n) | BigInt(message[at + len - 1]!);
      b = 0n;
    } else {
      a = 0n;
      b = 0n;
    }
  } else {
    let remaining = len;
    if (remaining > 48) {
      let see1 = state;
      let see2 = state;
      do {
        state = mix(u64(read64(message, at) ^ secret[1]!), u64(read64(message, at + 8) ^ state));
        see1 = mix(u64(read64(message, at + 16) ^ secret[2]!), u64(read64(message, at + 24) ^ see1));
        see2 = mix(u64(read64(message, at + 32) ^ secret[3]!), u64(read64(message, at + 40) ^ see2));
        at += 48;
        remaining -= 48;
      } while (remaining > 48);
      state = u64(state ^ see1 ^ see2);
    }
    while (remaining > 16) {
      state = mix(u64(read64(message, at) ^ secret[1]!), u64(read64(message, at + 8) ^ state));
      remaining -= 16;
      at += 16;
    }
    a = read64(message, at + remaining - 16);
    b = read64(message, at + remaining - 8);
  }

  a = u64(a ^ secret[1]!);
  b = u64(b ^ state);
  const [low, high] = mum(a, b);
  return mix(u64(low ^ secret[0]! ^ BigInt(len)), u64(high ^ secret[1]!));
}

/** Eight bytes, most significant first -- the spelling a digest is compared in. */
export function wyhashBytes(message: Uint8Array, seed: bigint = 0n): Uint8Array {
  const out = new Uint8Array(8);
  let value = wyhash(message, seed);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

