/**
 * RC5 and RC6: Rivest's parameterised pair, and neither has a table either.
 *
 * They share a key schedule -- the same magic constants derived from e and phi, the same three-pass
 * mixing over two arrays -- and they differ in the round. RC5 is a two-word Feistel whose rotation
 * amount is *data-dependent*, which was the new idea; RC6 is four words, adds a quadratic function
 * `B * (2B + 1)` to decorrelate the rotation amounts, and was an AES finalist.
 *
 * Three things worth knowing before touching either.
 *
 * **RC5 is three parameters, not one algorithm.** RC5-w/r/b is a word size, a round count and a key
 * length, and all three are genuinely free: 0 rounds is legal, a 1-byte key is legal, and RC5-32/12/16
 * is merely the common naming. Only the 32-bit word is offered here, because that is the one with
 * reachable vectors and the one every deployment used; `rounds` is a real option on the tool.
 *
 * **The words are little-endian**, unlike TEA's. RC5's own specification says so, and it is the sort
 * of thing that makes an implementation self-consistent and agree with nothing -- which is why the
 * vectors in `tests/algos-rc5.test.ts` include the asymmetric plaintext `1020304050607080` rather
 * than only the all-zero and all-ones blocks.
 *
 * **The rotation amount is masked to 5 bits, and that is load-bearing.** `rotl(x, y)` uses `y & 31`,
 * because the rotation is by a *data* value that can be anything. Writing the shift without the mask
 * happens to work in JavaScript, where `<<` masks its operand for you, and would break the moment
 * anyone reached for a 64-bit word size. It is written out.
 *
 * The security posture is different for the two and both are offered anyway. RC5 with 12 rounds is
 * broken by differential cryptanalysis given about 2^44 chosen plaintexts, which is why the designers
 * later recommended 16 or more; 12 is still what the deployments used. RC6 has no attack better than
 * exhaustive search and lost to Rijndael on performance and patent grounds rather than on strength.
 */

import type { BlockCipher } from "./blockmodes";

/** From e and phi: P = Odd((e - 2) * 2^32), Q = Odd((phi - 1) * 2^32). Shared by both ciphers. */
const P32 = 0xb7e15163;
const Q32 = 0x9e3779b9;

const u32 = (x: number): number => x >>> 0;
const rotl = (x: number, n: number): number => {
  const s = n & 31;
  return s === 0 ? u32(x) : u32((x << s) | (x >>> (32 - s)));
};
const rotr = (x: number, n: number): number => {
  const s = n & 31;
  return s === 0 ? u32(x) : u32((x >>> s) | (x << (32 - s)));
};

const loadLE = (src: Uint8Array, at: number): number =>
  u32(src[at]! | (src[at + 1]! << 8) | (src[at + 2]! << 16) | (src[at + 3]! << 24));

function storeLE(value: number, dst: Uint8Array, at: number): void {
  dst[at] = value & 0xff;
  dst[at + 1] = (value >>> 8) & 0xff;
  dst[at + 2] = (value >>> 16) & 0xff;
  dst[at + 3] = (value >>> 24) & 0xff;
}

/**
 * The shared key schedule, in the specification's three phases.
 *
 * Phase 1 loads the key bytes into little-endian words. Phase 2 fills S with an arithmetic
 * progression from P by Q. Phase 3 mixes the two arrays three times over the longer of them -- and
 * `3 * max(|S|, |L|)` rather than `3 * |S|` is the part implementations get wrong, because for a key
 * longer than the schedule the loop has to cover L instead.
 */
function expandKey(key: Uint8Array, words: number): number[] {
  // At least one word even for an empty key: the mixing loop indexes L unconditionally.
  const l = new Array<number>(Math.max(1, Math.ceil(key.length / 4))).fill(0);
  for (let i = key.length - 1; i >= 0; i--) {
    l[Math.floor(i / 4)] = u32((l[Math.floor(i / 4)]! << 8) + key[i]!);
  }

  const s = new Array<number>(words);
  s[0] = P32;
  for (let i = 1; i < words; i++) s[i] = u32(s[i - 1]! + Q32);

  let a = 0;
  let b = 0;
  let i = 0;
  let j = 0;
  const iterations = 3 * Math.max(s.length, l.length);
  for (let k = 0; k < iterations; k++) {
    a = s[i] = rotl(u32(s[i]! + a + b), 3);
    b = l[j] = rotl(u32(l[j]! + a + b), u32(a + b));
    i = (i + 1) % s.length;
    j = (j + 1) % l.length;
  }
  return s;
}

/**
 * RC5-32/r/b. `rounds` is 0 to 255; 12 is the classic naming and 16 the designers' later advice.
 *
 * Note that a 0-round RC5 is not a mistake to refuse: it is two additions of subkeys, it has a
 * published vector, and its existence is what makes the round count visibly a *parameter* rather than
 * a constant somebody could quietly change.
 */
export function createRc5(key: Uint8Array, rounds: number): BlockCipher {
  if (key.length > 255) throw new Error(`RC5's key is at most 255 bytes; this one is ${key.length}.`);
  if (!Number.isInteger(rounds) || rounds < 0 || rounds > 255) {
    throw new Error(`RC5's round count is 0 to 255; this one is ${rounds}.`);
  }
  const s = expandKey(key, 2 * (rounds + 1));

  return {
    blockSize: 8,
    encryptBlock(src, dst) {
      let a = u32(loadLE(src, 0) + s[0]!);
      let b = u32(loadLE(src, 4) + s[1]!);
      for (let i = 1; i <= rounds; i++) {
        a = u32(rotl(a ^ b, b) + s[2 * i]!);
        b = u32(rotl(b ^ a, a) + s[2 * i + 1]!);
      }
      storeLE(a, dst, 0);
      storeLE(b, dst, 4);
    },
    decryptBlock(src, dst) {
      let a = loadLE(src, 0);
      let b = loadLE(src, 4);
      for (let i = rounds; i >= 1; i--) {
        b = u32(rotr(u32(b - s[2 * i + 1]!), a) ^ a);
        a = u32(rotr(u32(a - s[2 * i]!), b) ^ b);
      }
      storeLE(u32(a - s[0]!), dst, 0);
      storeLE(u32(b - s[1]!), dst, 4);
    },
  };
}

const RC6_ROUNDS = 20;

/**
 * RC6-32/20/b, the AES submission. 128-bit block, key of 16, 24 or 32 bytes.
 *
 * `Math.imul` for the quadratic term, and not for speed: `B * (2B + 1)` overflows a double past 2^53,
 * so the ordinary `*` silently loses the low bits it is supposed to keep. That is the one place in
 * this file where JavaScript's number type is a hazard rather than a convenience, and it produces a
 * cipher that inverts perfectly and matches nothing.
 */
export function createRc6(key: Uint8Array): BlockCipher {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`RC6's key is 16, 24 or 32 bytes; this one is ${key.length}.`);
  }
  const s = expandKey(key, 2 * RC6_ROUNDS + 4);
  const quad = (x: number): number => rotl(Math.imul(x, u32(2 * x + 1)), 5);

  return {
    blockSize: 16,
    encryptBlock(src, dst) {
      let a = loadLE(src, 0);
      let b = u32(loadLE(src, 4) + s[0]!);
      let c = loadLE(src, 8);
      let d = u32(loadLE(src, 12) + s[1]!);

      for (let i = 1; i <= RC6_ROUNDS; i++) {
        const t = quad(b);
        const u = quad(d);
        a = u32(rotl(a ^ t, u) + s[2 * i]!);
        c = u32(rotl(c ^ u, t) + s[2 * i + 1]!);
        // The rotation of the four registers, written as a rotation rather than four assignments.
        [a, b, c, d] = [b, c, d, a];
      }

      storeLE(u32(a + s[2 * RC6_ROUNDS + 2]!), dst, 0);
      storeLE(b, dst, 4);
      storeLE(u32(c + s[2 * RC6_ROUNDS + 3]!), dst, 8);
      storeLE(d, dst, 12);
    },
    decryptBlock(src, dst) {
      let a = u32(loadLE(src, 0) - s[2 * RC6_ROUNDS + 2]!);
      let b = loadLE(src, 4);
      let c = u32(loadLE(src, 8) - s[2 * RC6_ROUNDS + 3]!);
      let d = loadLE(src, 12);

      for (let i = RC6_ROUNDS; i >= 1; i--) {
        [a, b, c, d] = [d, a, b, c];
        const t = quad(b);
        const u = quad(d);
        c = rotr(u32(c - s[2 * i + 1]!), t) ^ u;
        a = rotr(u32(a - s[2 * i]!), u) ^ t;
      }

      storeLE(a, dst, 0);
      storeLE(u32(b - s[0]!), dst, 4);
      storeLE(c, dst, 8);
      storeLE(u32(d - s[1]!), dst, 12);
    },
  };
}
