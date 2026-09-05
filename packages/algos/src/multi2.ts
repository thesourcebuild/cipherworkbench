/**
 * MULTI2 Block Cipher:
 * Hitachi 64-bit Feistel cipher designed for ISDB / ARIB digital broadcasting scrambling.
 * Uses 32 rounds of nonlinear Feistel mixing with 8 round keys derived from a 256-bit or 320-bit system key.
 */

import type { BlockCipher } from "./blockmodes";

const rotl32 = (x: number, n: number) => (((x << n) | (x >>> (32 - n))) >>> 0);

export class Multi2Cipher {
  private k = new Uint32Array(8);

  constructor(systemKey: Uint8Array, _rounds = 32) {
    if (systemKey.length < 32) throw new Error("MULTI2 requires at least a 32-byte (256-bit) system key.");
    this.keySchedule(systemKey);
  }

  private keySchedule(sk: Uint8Array): void {
    const view = new DataView(sk.buffer, sk.byteOffset, sk.length);
    for (let i = 0; i < 8; i++) {
      this.k[i] = view.getUint32(i * 4, false); // big-endian
    }
  }

  private roundFunction(l: number, r: number, kIndex: number): [number, number] {
    const k1 = this.k[kIndex % 8]!;
    const k2 = this.k[(kIndex + 1) % 8]!;

    // Feistel nonlinear round components
    let t = (l + k1) >>> 0;
    t = (rotl32(t, 1) + t - 1) >>> 0;
    t = (rotl32(t, 4) ^ t) >>> 0;

    const newR = (r ^ t) >>> 0;
    let newL = (newR + k2) >>> 0;
    newL = (rotl32(newL, 2) + newL + 1) >>> 0;
    newL = (rotl32(newL, 8) ^ newL) >>> 0;
    newL = (l ^ newL) >>> 0;

    return [newL, newR];
  }

  encryptBlock(block: Uint8Array): Uint8Array {
    const view = new DataView(block.buffer, block.byteOffset, 8);
    let l = view.getUint32(0, false);
    let r = view.getUint32(4, false);

    for (let round = 0; round < 32; round += 2) {
      [l, r] = this.roundFunction(l, r, round);
    }

    const out = new Uint8Array(8);
    const outView = new DataView(out.buffer);
    outView.setUint32(0, l, false);
    outView.setUint32(4, r, false);
    return out;
  }

  decryptBlock(block: Uint8Array): Uint8Array {
    const view = new DataView(block.buffer, block.byteOffset, 8);
    let l = view.getUint32(0, false);
    let r = view.getUint32(4, false);

    for (let round = 30; round >= 0; round -= 2) {
      const k1 = this.k[round % 8]!;
      const k2 = this.k[(round + 1) % 8]!;

      let newL = (r + k2) >>> 0;
      newL = (rotl32(newL, 2) + newL + 1) >>> 0;
      newL = (rotl32(newL, 8) ^ newL) >>> 0;
      const origL = (l ^ newL) >>> 0;

      let t = (origL + k1) >>> 0;
      t = (rotl32(t, 1) + t - 1) >>> 0;
      t = (rotl32(t, 4) ^ t) >>> 0;
      const origR = (r ^ t) >>> 0;

      l = origL;
      r = origR;
    }

    const out = new Uint8Array(8);
    const outView = new DataView(out.buffer);
    outView.setUint32(0, l, false);
    outView.setUint32(4, r, false);
    return out;
  }
}

export function createMulti2(key: Uint8Array): BlockCipher {
  const cipher = new Multi2Cipher(key);
  return {
    blockSize: 8,
    encryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const block = src.subarray(0, 8);
      const enc = cipher.encryptBlock(block);
      dst.set(enc);
    },
    decryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const block = src.subarray(0, 8);
      const dec = cipher.decryptBlock(block);
      dst.set(dec);
    },
  };
}

export function multi2EncryptEcb(key: Uint8Array, data: Uint8Array): Uint8Array {
  const cipher = new Multi2Cipher(key);
  const padLen = 8 - (data.length % 8);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(padLen, data.length);

  const out = new Uint8Array(padded.length);
  for (let i = 0; i < padded.length; i += 8) {
    out.set(cipher.encryptBlock(padded.subarray(i, i + 8)), i);
  }
  return out;
}

export function multi2DecryptEcb(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (data.length % 8 !== 0) throw new Error("Invalid MULTI2 ciphertext length.");
  const cipher = new Multi2Cipher(key);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 8) {
    out.set(cipher.decryptBlock(data.subarray(i, i + 8)), i);
  }
  const padLen = out[out.length - 1]!;
  if (padLen > 0 && padLen <= 8) {
    return out.slice(0, out.length - padLen);
  }
  return out;
}
