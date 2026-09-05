/**
 * LightMAC (ISO/IEC 29192-6):
 * Lightweight Block-Counter Message Authentication Code for constrained devices.
 */

import { aes128BlockEncrypt, aes256BlockEncrypt } from "./aes-round";

function aesBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  if (key.length === 32) {
    return aes256BlockEncrypt(block, key);
  }
  const k16 = new Uint8Array(16);
  k16.set(key.subarray(0, Math.min(16, key.length)));
  return aes128BlockEncrypt(block, k16);
}

export interface LightMacOptions {
  counterBits?: 8 | 16 | 32 | 64; // default 64
  tagLength?: number; // default 16
}

export function lightMac(key: Uint8Array, data: Uint8Array, options: LightMacOptions = {}): Uint8Array {
  const counterBits = options.counterBits ?? 64;
  const counterBytes = counterBits / 8;
  const blockSize = 16;
  const msgBlockSize = blockSize - counterBytes;
  const tagLen = options.tagLength ?? 16;

  // Split key into K1 and K2 (if 16 bytes, derive K2 = AES_K1(0x01^16))
  const k1 = key.subarray(0, 16);
  let k2: Uint8Array;
  if (key.length >= 32) {
    k2 = key.subarray(16, 32);
  } else {
    const c = new Uint8Array(16);
    c.fill(1);
    k2 = aesBlock(k1, c);
  }

  // Split data into blocks of msgBlockSize, with 10* padding on last block if needed
  const numBlocks = Math.max(1, Math.ceil(data.length / msgBlockSize));
  const V = new Uint8Array(16);

  for (let i = 0; i < numBlocks; i++) {
    const block = new Uint8Array(16);
    // Write counter in big-endian in first counterBytes
    let ctr = BigInt(i + 1);
    for (let b = counterBytes - 1; b >= 0; b--) {
      block[b] = Number(ctr & 0xffn);
      ctr >>= 8n;
    }
    // Copy data chunk
    const chunk = data.subarray(i * msgBlockSize, Math.min((i + 1) * msgBlockSize, data.length));
    block.set(chunk, counterBytes);
    if (chunk.length < msgBlockSize) {
      block[counterBytes + chunk.length] = 0x80; // 10* padding
    }

    const encrypted = aesBlock(k1, block);
    for (let b = 0; b < 16; b++) {
      V[b]! ^= encrypted[b]!;
    }
  }

  // Final tag: T = AES_K2(V)
  const tag = aesBlock(k2, V);
  return new Uint8Array(tag.slice(0, tagLen));
}
