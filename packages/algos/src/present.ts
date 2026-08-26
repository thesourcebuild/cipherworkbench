/**
 * PRESENT-80, from CHES 2007 and ISO/IEC 29192-2, over the shared `BlockCipher` interface.
 *
 * The reference lightweight block cipher: a 64-bit block, an 80-bit key, and a design target of about
 * 1570 gate equivalents -- roughly a quarter of the smallest AES. It exists because RFID tags and
 * similar hardware could not afford AES, and it is the thing every later lightweight design is
 * compared against. There is no software reason to choose it; it is here to read and reproduce output
 * from hardware that does.
 *
 * Three things to know.
 *
 * **It is bit-sliced, so the permutation is the whole cipher.** Each round is an XOR with the round
 * key, one 4-bit S-box applied to all sixteen nibbles, and then a bit permutation that moves bit `i`
 * to position `16i mod 63`. That permutation is what gives the cipher its diffusion, and it is
 * expressed as a loop over 64 bits rather than as a table on purpose -- `16i mod 63` is the
 * specification, and a 64-entry table would be one more thing to mistype.
 *
 * **The round counter goes in at bits 19 to 15.** The 80-bit key register is rotated left 61 bits, the
 * top nibble is passed through the S-box, and the round number -- counting from 1 -- is XORed into
 * bits 19..15. Off-by-one on that counter gives a cipher that round-trips and matches nothing.
 *
 * **Thirty-one rounds, then a final key XOR.** The thirty-second subkey is used as a post-whitening
 * key with no S-box or permutation after it, which is the usual Feistel-adjacent off-by-one.
 *
 * Both key sizes are implemented. The 80-bit variant carries four of the paper's own vectors in
 * `tests/algos-lightweight.test.ts` -- all four combinations of an all-zero and an all-ones key and
 * plaintext, which between them exercise every branch of the schedule.
 *
 * **PRESENT-128 has no published vector, and that is a fact about the paper rather than about
 * searching.** Appendix I tabulates four vectors and all four are 80-bit; Appendix II describes the
 * 128-bit key schedule in prose -- rotate the register left 61, S-box the top *two* nibbles rather than
 * one, XOR the counter into bits 66 to 62 -- and gives no values, prefacing it with "we do not expect
 * it to be used". Bouncy Castle, Crypto++, Botan and FELICS implement PRESENT-80 only. So the 128-bit
 * variant rests on the paper's prose plus the fact that it shares the S-box, the permutation and the
 * round structure with the 80-bit variant, which four published vectors do pin. What is *not* checked
 * by anything external is its schedule. `tests/algos-lightweight.test.ts` says so rather than implying
 * otherwise, and pins the properties that can be checked: 31 distinct round keys, dependence on every
 * key bit, and a working inverse.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const KEY_LEN = 10;
const KEY_LEN_128 = 16;

export type PresentVariant = "80" | "128";

/** The 4-bit S-box, as the paper tabulates it. */
/**
 * PRESENT's 4-bit S-box.
 *
 * Exported because **LED uses the same one** -- Guo, Peyrin, Poschmann and Robshaw reused it deliberately
 * -- so `led.ts` imports it rather than storing a second copy, and PRESENT's own published vectors already
 * pin it for both ciphers.
 */
export const PRESENT_SBOX: readonly number[] = [
  0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2,
];
/** The private alias the rest of this file was written against. */
const SBOX = PRESENT_SBOX;

const SBOX_INV: readonly number[] = (() => {
  // Derived rather than listed, and the load-time check is the point: a non-permutation would make
  // decryption silently wrong for some inputs and right for others.
  const inverse = new Array<number>(16).fill(-1);
  for (let i = 0; i < 16; i++) inverse[SBOX[i]!] = i;
  if (inverse.some((v) => v < 0)) throw new Error("PRESENT's S-box is not a permutation.");
  return inverse;
})();

const MASK64 = (1n << 64n) - 1n;
const MASK80 = (1n << 80n) - 1n;

function substitute(state: bigint, box: readonly number[]): bigint {
  let out = 0n;
  for (let i = 0; i < 16; i++) {
    const nibble = Number((state >> BigInt(4 * i)) & 0xfn);
    out |= BigInt(box[nibble]!) << BigInt(4 * i);
  }
  return out;
}

/** Bit `i` moves to `16i mod 63`; bit 63 stays put. Its own inverse is the reverse mapping. */
function permute(state: bigint, forward: boolean): bigint {
  let out = 0n;
  for (let i = 0; i < 64; i++) {
    const to = i === 63 ? 63 : (16 * i) % 63;
    const [from, dest] = forward ? [i, to] : [to, i];
    out |= ((state >> BigInt(from)) & 1n) << BigInt(dest);
  }
  return out;
}

/** The 32 round keys: the top 64 bits of the register, rotated and S-boxed between rounds. */
const MASK128 = (1n << 128n) - 1n;

function schedule(key: Uint8Array): bigint[] {
  if (key.length !== KEY_LEN) {
    throw new Error(`PRESENT-80's key is 10 bytes; this one is ${key.length}.`);
  }
  let register = 0n;
  for (const byte of key) register = (register << 8n) | BigInt(byte);
  register &= MASK80;

  const keys: bigint[] = [];
  for (let round = 1; round <= 32; round++) {
    keys.push((register >> 16n) & MASK64);
    if (round === 32) break;
    register = ((register << 61n) | (register >> 19n)) & MASK80;
    const top = Number((register >> 76n) & 0xfn);
    register = (register & ~(0xfn << 76n)) | (BigInt(SBOX[top]!) << 76n);
    register ^= BigInt(round) << 15n;
  }
  return keys;
}

/**
 * PRESENT-128's schedule, from the paper's Appendix II.
 *
 * Three differences from the 80-bit one, and the middle is the easy one to miss: the round key is the
 * top *64* bits of a 128-bit register rather than the top 64 of an 80-bit one; **two** nibbles go
 * through the S-box rather than one; and the counter lands at bit 62 rather than bit 15. The rotation
 * is 61 in both.
 */
function schedule128(key: Uint8Array): bigint[] {
  if (key.length !== KEY_LEN_128) {
    throw new Error(`PRESENT-128's key is 16 bytes; this one is ${key.length}.`);
  }
  let register = 0n;
  for (const byte of key) register = (register << 8n) | BigInt(byte);
  register &= MASK128;

  const keys: bigint[] = [];
  for (let round = 1; round <= 32; round++) {
    keys.push((register >> 64n) & MASK64);
    if (round === 32) break;
    register = ((register << 61n) | (register >> 67n)) & MASK128;
    const top = Number((register >> 124n) & 0xfn);
    const next = Number((register >> 120n) & 0xfn);
    register = (register & ~(0xfn << 124n)) | (BigInt(SBOX[top]!) << 124n);
    register = (register & ~(0xfn << 120n)) | (BigInt(SBOX[next]!) << 120n);
    // Bits k66..k62, least significant bit of the counter at k62.
    register ^= BigInt(round) << 62n;
  }
  return keys;
}

function toBig(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value & MASK64;
}

function fromBig(value: bigint, dst: Uint8Array): void {
  for (let i = 0; i < BLOCK; i++) {
    dst[i] = Number((value >> BigInt(8 * (BLOCK - 1 - i))) & 0xffn);
  }
}

/** PRESENT at either key size. */
export function createPresent(key: Uint8Array, variant: PresentVariant = "80"): BlockCipher {
  const keys = variant === "128" ? schedule128(key) : schedule(key);

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      let state = toBig(src);
      for (let round = 0; round < 31; round++) {
        state ^= keys[round]!;
        state = permute(substitute(state, SBOX), true);
      }
      fromBig(state ^ keys[31]!, dst);
    },
    decryptBlock: (src, dst) => {
      let state = toBig(src);
      state ^= keys[31]!;
      for (let round = 30; round >= 0; round--) {
        state = substitute(permute(state, false), SBOX_INV);
        state ^= keys[round]!;
      }
      fromBig(state, dst);
    },
  };
}
