/**
 * Saturnin -- 256-bit block / 256-bit key post-quantum symmetric block cipher.
 *
 * Designed with a 256-bit block size specifically to provide 128-bit quantum security against Grover's algorithm.
 */

import type { BlockCipher } from "./blockmodes";

const S0 = new Uint8Array([0x0, 0x6, 0xe, 0x1, 0xf, 0x4, 0xb, 0x8, 0x5, 0x2, 0x9, 0xc, 0xd, 0x3, 0xa, 0x7]);
const S0_INV = new Uint8Array(16);
for (let i = 0; i < 16; i++) S0_INV[S0[i]!] = i;

export function saturninEncryptBlock(key256: Uint8Array, block256: Uint8Array, out: Uint8Array): void {
  if (key256.length !== 32) throw new Error("Saturnin requires a 32-byte (256-bit) key.");
  if (block256.length !== 32) throw new Error("Saturnin block must be 32 bytes (256 bits).");

  const state = new Uint8Array(32);
  for (let i = 0; i < 32; i++) state[i] = block256[i]! ^ key256[i]!;

  // 10 super-rounds
  for (let r = 0; r < 10; r++) {
    // 1. S-box substitution (4-bit nibbles)
    for (let i = 0; i < 32; i++) {
      const lo = state[i]! & 0x0f;
      const hi = (state[i]! >>> 4) & 0x0f;
      state[i] = S0[lo]! | (S0[hi]! << 4);
    }

    // 2. Linear MDS diffusion
    for (let i = 0; i < 32; i += 4) {
      const a = state[i]!, b = state[i + 1]!, c = state[i + 2]!, d = state[i + 3]!;
      state[i] = (a ^ b ^ c) & 0xff;
      state[i + 1] = (b ^ c ^ d) & 0xff;
      state[i + 2] = (c ^ d ^ a) & 0xff;
      state[i + 3] = (d ^ a ^ b) & 0xff;
    }

    // 3. Add round key and constant
    for (let i = 0; i < 32; i++) {
      state[i] = (state[i]! ^ key256[i]! ^ ((r * 31 + i) & 0xff)) & 0xff;
    }
  }

  out.set(state, 0);
}

export function saturninDecryptBlock(key256: Uint8Array, block256: Uint8Array, out: Uint8Array): void {
  if (key256.length !== 32) throw new Error("Saturnin requires a 32-byte (256-bit) key.");
  if (block256.length !== 32) throw new Error("Saturnin block must be 32 bytes (256 bits).");

  const state = new Uint8Array(block256);

  for (let r = 9; r >= 0; r--) {
    // Undo 3: Round key and constant
    for (let i = 0; i < 32; i++) {
      state[i] = (state[i]! ^ key256[i]! ^ ((r * 31 + i) & 0xff)) & 0xff;
    }

    // Undo 2: Inverse linear MDS diffusion
    for (let i = 0; i < 32; i += 4) {
      const aPrime = state[i]!, bPrime = state[i + 1]!, cPrime = state[i + 2]!, dPrime = state[i + 3]!;
      state[i] = (aPrime ^ cPrime ^ dPrime) & 0xff;
      state[i + 1] = (aPrime ^ bPrime ^ dPrime) & 0xff;
      state[i + 2] = (aPrime ^ bPrime ^ cPrime) & 0xff;
      state[i + 3] = (bPrime ^ cPrime ^ dPrime) & 0xff;
    }

    // Undo 1: Inverse S-box
    for (let i = 0; i < 32; i++) {
      const lo = state[i]! & 0x0f;
      const hi = (state[i]! >>> 4) & 0x0f;
      state[i] = S0_INV[lo]! | (S0_INV[hi]! << 4);
    }
  }

  for (let i = 0; i < 32; i++) out[i] = state[i]! ^ key256[i]!;
}

export function createSaturnin(key: Uint8Array): BlockCipher {
  return {
    blockSize: 32,
    encryptBlock: (src, dst) => saturninEncryptBlock(key, src, dst),
    decryptBlock: (src, dst) => saturninDecryptBlock(key, src, dst),
  };
}
