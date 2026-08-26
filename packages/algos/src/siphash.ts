/**
 * SipHash-2-4, from Aumasson and Bernstein's 2012 paper.
 *
 * A keyed pseudorandom function for short inputs, and the answer to a specific problem: hash-table
 * flooding. Perl, Python, Ruby, Rust, Haskell and both major BSD kernels key their hash tables with
 * this, because an unkeyed hash lets an attacker choose inputs that all land in one bucket and turn a
 * dictionary into a linked list. It is not a general-purpose MAC -- 64 bits of output is too short for
 * message authentication -- and the tool's security note says so.
 *
 * Three things to know.
 *
 * **The output is written little-endian, and the published vectors are printed the other way.** The
 * reference `vectors.h` lists the empty-message result as the byte string `31 0e 0e dd 47 db 6f 72`,
 * while the paper and most write-ups quote the same value as the integer `0x726fdb47dd0e0e31`. Both
 * are correct and they are reverses of each other. This returns the byte string, because that is what
 * a MAC is, and `tests/algos-siphash.test.ts` asserts both spellings so the confusion cannot creep
 * back in.
 *
 * **The last block carries the length, not padding.** The final 64-bit word is the remaining bytes in
 * the low positions with `len mod 256` in the top byte. There is no padding byte and no length block:
 * a 7-byte input and an 8-byte input differ in that top byte alone.
 *
 * **Only 2-4 is offered.** SipHash-1-3 is the same code with different round counts and is what Rust's
 * `SipHasher13` uses, but no published vector for it was reachable offline, and this repo does not
 * register a keyed construction it cannot check against something independent. The round counts are
 * parameters here rather than constants so that registering it later is a metadata entry -- the same
 * arrangement as Tiger2 before its vector turned up.
 *
 * `bigint`, as elsewhere for 64-bit word algorithms: the inputs SipHash is designed for are short
 * enough that the cost never shows.
 */

const MASK = (1n << 64n) - 1n;
const rotl = (x: bigint, n: number): bigint => ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK;

/** Eight bytes at `at`, little-endian, zero-extended past the end. */
function readLe(bytes: Uint8Array, at: number): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(bytes[at + i] ?? 0);
  return value;
}

/**
 * SipHash with an explicit round count, returning the 8-byte digest.
 *
 * `compression` and `finalization` are the two numbers in the name: SipHash-2-4 is two compression
 * rounds per message word and four finalisation rounds.
 */
export function siphash(
  key: Uint8Array,
  message: Uint8Array,
  compression = 2,
  finalization = 4,
): Uint8Array {
  if (key.length !== 16) {
    throw new Error(`SipHash's key is 16 bytes; this one is ${key.length}.`);
  }

  const k0 = readLe(key, 0);
  const k1 = readLe(key, 8);
  // The four initialisation constants spell "somepseudorandomlygeneratedbytes" in ASCII.
  let v0 = 0x736f6d6570736575n ^ k0;
  let v1 = 0x646f72616e646f6dn ^ k1;
  let v2 = 0x6c7967656e657261n ^ k0;
  let v3 = 0x7465646279746573n ^ k1;

  const round = (): void => {
    v0 = (v0 + v1) & MASK;
    v1 = rotl(v1, 13) ^ v0;
    v0 = rotl(v0, 32);
    v2 = (v2 + v3) & MASK;
    v3 = rotl(v3, 16) ^ v2;
    v0 = (v0 + v3) & MASK;
    v3 = rotl(v3, 21) ^ v0;
    v2 = (v2 + v1) & MASK;
    v1 = rotl(v1, 17) ^ v2;
    v2 = rotl(v2, 32);
  };

  const absorb = (word: bigint): void => {
    v3 ^= word;
    for (let i = 0; i < compression; i++) round();
    v0 ^= word;
  };

  const whole = message.length - (message.length % 8);
  for (let at = 0; at < whole; at += 8) absorb(readLe(message, at));

  // The tail: the remaining bytes low, the length's low byte high. No padding.
  let last = BigInt(message.length & 0xff) << 56n;
  for (let i = whole; i < message.length; i++) {
    last |= BigInt(message[i]!) << BigInt(8 * (i - whole));
  }
  absorb(last);

  v2 ^= 0xffn;
  for (let i = 0; i < finalization; i++) round();

  const digest = (v0 ^ v1 ^ v2 ^ v3) & MASK;
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) out[i] = Number((digest >> BigInt(8 * i)) & 0xffn);
  return out;
}

/** SipHash-2-4, the variant every deployment means when it says "SipHash". */
export function siphash24(key: Uint8Array, message: Uint8Array): Uint8Array {
  return siphash(key, message, 2, 4);
}
