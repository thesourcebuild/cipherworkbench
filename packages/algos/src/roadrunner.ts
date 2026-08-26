/**
 * RoadRunneR, a bitslice-friendly Feistel cipher for 8-bit microcontrollers (Baysal and Sahin,
 * LightSec 2015). 64-bit block, 80- or 128-bit key.
 *
 * `legacy`. No attack on the full cipher, but it is an unstandardised competition-era design that
 * nothing deploys, so it is here to reproduce values rather than to encrypt with.
 *
 * The interesting thing structurally is that **its round function is itself a small SPN**: where a
 * classical Feistel round applies one mixing function to half the block, RoadRunneR runs three
 * substitute-then-linear-then-key layers over the left half, with a round counter injected between
 * the second and the third. So a "round" here is closer to three rounds of a 32-bit cipher, which
 * is why twelve of them suffice at 128 bits.
 *
 * Four things to preserve.
 *
 * **The S-box is not an involution**, unlike PRIDE's and the LS-designs' -- it is a seven-gate
 * bitsliced sequence over four bytes, and applying it twice is not the identity. That is asserted at
 * load, because it is the natural wrong assumption to make in this neighbourhood and it would leave
 * encryption correct and decryption silently wrong.
 *
 * **L is a single expression, `x ^= rotl(rotl(x) ^ x)`, and it is its own inverse.** So the
 * decryption path reuses it; only the S-box and the key ordering have to be undone.
 *
 * **The two key sizes take their key material differently, and this is the one real branch.** At 128
 * bits the four bytes of each SLK layer come from a *fixed* position determined by a counter stepping
 * by 4 modulo 16 -- so the key is read as four independent 32-bit words. At 80 bits the key is ten
 * bytes, which four does not divide, so the counter steps *one byte at a time modulo 10* and a
 * layer's four bytes straddle the wrap. An implementation that treats 80 bits as "the same thing with
 * a shorter key" is right for the first two layers and wrong from the third.
 *
 * **Decryption walks the key backwards, and the two sizes rewind differently.** At 80 bits the
 * counter is advanced by 6 modulo 10 after each round -- three layers of four bytes is twelve, and
 * twelve minus ten is two, so recovering the previous round's starting position means moving forward
 * six rather than back twelve. At 128 bits it is 12 modulo 16. Both are stated as additions because a
 * negative modulo in JavaScript is not the residue.
 *
 * Verified against the designers' own four test vectors -- two per key size -- in both directions.
 * `tests/algos-lightweight-block4.test.ts` decrypts the published ciphertext rather than
 * re-encrypting ours, which is what catches an inverse that is self-consistent and wrong.
 */

import type { BlockCipher } from "./blockmodes";

export type RoadRunneRVariant = "64-80" | "64-128";

const BLOCK = 8;

const rotl8 = (x: number): number => ((x << 1) | (x >>> 7)) & 0xff;

/**
 * The 4-bit S-box, applied bitsliced across four bytes of the state.
 *
 * Seven gates, and the order matters: `t` holds the original byte 3 because byte 3 is overwritten
 * before bytes 0 and 2 need it.
 */
function substitute(d: number[], at: number): void {
  const t = d[at + 3]!;
  d[at + 3] = d[at + 3]! & d[at + 2]!;
  d[at + 3] = d[at + 3]! ^ d[at + 1]!;
  d[at + 1] = d[at + 1]! | d[at + 2]!;
  d[at + 1] = d[at + 1]! ^ d[at + 0]!;
  d[at + 0] = d[at + 0]! & d[at + 3]!;
  d[at + 0] = d[at + 0]! ^ t;
  d[at + 2] = d[at + 2]! ^ (t & d[at + 1]!);
  for (let i = 0; i < 4; i++) d[at + i] = d[at + i]! & 0xff;
}

/** The linear layer, one byte at a time. Its own inverse. */
function linear(d: number[], i: number): void {
  let t = rotl8(d[i]!);
  t ^= d[i]!;
  t = rotl8(t);
  d[i] = (d[i]! ^ t) & 0xff;
}

// The S-box is deliberately not an involution; assuming otherwise breaks only decryption.
{
  const probe = [0x12, 0x34, 0x56, 0x78];
  const twice = probe.slice();
  substitute(twice, 0);
  substitute(twice, 0);
  if (twice.join(",") === probe.join(",")) {
    throw new Error("RoadRunneR: the S-box must not be an involution");
  }
}

const KEY_BYTES: Record<RoadRunneRVariant, number> = { "64-80": 10, "64-128": 16 };
const ROUNDS: Record<RoadRunneRVariant, number> = { "64-80": 10, "64-128": 12 };

/** The byte the key counter starts at when decrypting, which is where encryption left off. */
const REWIND_START: Record<RoadRunneRVariant, number> = { "64-80": 2, "64-128": 8 };

function crypt(key: Uint8Array, block: Uint8Array, variant: RoadRunneRVariant, decrypt: boolean): Uint8Array {
  const keyBytes = KEY_BYTES[variant];
  const rounds = ROUNDS[variant];
  const b = Array.from(block);
  let counter = decrypt ? REWIND_START[variant] : 4;

  /**
   * One substitute-linear-key layer.
   *
   * At 80 bits the four key bytes are consumed one at a time from a counter modulo 10, so a layer
   * can straddle the end of the key; at 128 bits they are a 4-byte-aligned word.
   */
  const slk = (): void => {
    substitute(b, 0);
    if (keyBytes === 10) {
      for (let i = 0; i < 4; i++) linear(b, i);
      for (let i = 0; i < 4; i++) {
        b[i] = (b[i]! ^ key[counter]!) & 0xff;
        counter = (counter + 1) % 10;
      }
    } else {
      for (let i = 0; i < 4; i++) {
        linear(b, i);
        b[i] = (b[i]! ^ key[counter + i]!) & 0xff;
      }
    }
  };

  const firstKey = decrypt ? 4 : 0;
  const lastKey = decrypt ? 0 : 4;
  for (let i = 0; i < 4; i++) b[i] = (b[i]! ^ key[firstKey + i]!) & 0xff;

  for (let step = 0; step < rounds; step++) {
    const round = decrypt ? step + 1 : rounds - step;
    const carried = [b[0]!, b[1]!, b[2]!, b[3]!];
    if (keyBytes === 10) {
      slk();
      slk();
      b[3] = b[3]! ^ round;
      slk();
      // Three layers consumed twelve bytes of a ten-byte key, so rewinding is +6 rather than -12.
      if (decrypt) counter = (counter + 6) % 10;
    } else {
      slk();
      counter = (counter + 4) & 15;
      slk();
      counter = (counter + 4) & 15;
      b[3] = b[3]! ^ round;
      slk();
      counter = (counter + (decrypt ? 12 : 4)) & 15;
    }
    substitute(b, 0);
    for (let i = 0; i < 4; i++) b[i] = (b[i]! ^ b[i + 4]!) & 0xff;
    for (let i = 0; i < 4; i++) b[i + 4] = carried[i]!;
  }

  const carried = [b[0]!, b[1]!, b[2]!, b[3]!];
  for (let i = 0; i < 4; i++) b[i] = (b[i + 4]! ^ key[lastKey + i]!) & 0xff;
  for (let i = 0; i < 4; i++) b[i + 4] = carried[i]!;
  return Uint8Array.from(b);
}

export function roadrunnerKeyLength(variant: RoadRunneRVariant): number {
  return KEY_BYTES[variant];
}

export function createRoadRunneR(key: Uint8Array, variant: RoadRunneRVariant): BlockCipher {
  const expected = KEY_BYTES[variant];
  if (key.length !== expected) {
    throw new Error(`RoadRunneR-${variant} needs a key of exactly ${expected} bytes; this one is ${key.length}.`);
  }
  const material = Uint8Array.from(key);
  return {
    blockSize: BLOCK,
    encryptBlock(src, dst) {
      dst.set(crypt(material, src.subarray(0, BLOCK), variant, false));
    },
    decryptBlock(src, dst) {
      dst.set(crypt(material, src.subarray(0, BLOCK), variant, true));
    },
  };
}
