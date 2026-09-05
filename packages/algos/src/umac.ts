/**
 * UMAC (RFC 4418):
 * Universal Message Authentication Code using NH and AES.
 */

import { aes128BlockEncrypt } from "./aes-round";

function nhHash(k: Uint32Array, m: Uint8Array, outWordCount = 2): Uint8Array {
  const mWords = new Uint32Array(m.length >>> 2);
  const view = new DataView(m.buffer, m.byteOffset, m.length);
  for (let i = 0; i < mWords.length; i++) {
    mWords[i] = view.getUint32(i * 4, true); // little-endian
  }

  const out = new Uint8Array(outWordCount * 8);
  const outView = new DataView(out.buffer);

  for (let t = 0; t < outWordCount; t++) {
    let acc = 0n;
    const keyOffset = t * 4;
    for (let i = 0; i < mWords.length - 1; i += 2) {
      const a = BigInt((mWords[i]! + k[i + keyOffset]!) >>> 0);
      const b = BigInt((mWords[i + 1]! + k[i + 1 + keyOffset]!) >>> 0);
      acc = (acc + a * b) & 0xffffffffffffffffn;
    }
    outView.setBigUint64(t * 8, acc, true);
  }
  return out;
}

export interface UmacOptions {
  nonce?: Uint8Array;
  tagLength?: number; // 8 (64-bit) or 16 (128-bit), default 8
}

export function umac(key: Uint8Array, data: Uint8Array, options: UmacOptions = {}): Uint8Array {
  const tagLen = options.tagLength ?? 8;
  const numIterations = tagLen === 16 ? 4 : 2;

  const k16 = new Uint8Array(16);
  k16.set(key.subarray(0, Math.min(16, key.length)));

  // Generate subkeys K_NH via AES key expansion
  const nhKeyWords = new Uint32Array(256 + 16);
  const blockBuf = new Uint8Array(16);
  const blockView = new DataView(blockBuf.buffer);
  for (let i = 0; i < Math.ceil((nhKeyWords.length * 4) / 16); i++) {
    blockView.setUint32(12, i, false);
    const enc = aes128BlockEncrypt(blockBuf, k16);
    const encView = new DataView(enc.buffer, enc.byteOffset, 16);
    for (let w = 0; w < 4 && (i * 4 + w) < nhKeyWords.length; w++) {
      nhKeyWords[i * 4 + w] = encView.getUint32(w * 4, true);
    }
  }

  // Pad data to 32-byte boundary
  const padLen = data.length === 0 ? 32 : (32 - (data.length % 32)) % 32;
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);

  // Hash with NH
  const nhOut = nhHash(nhKeyWords, padded, numIterations);

  // Pad with AES(nonce)
  const nonce = options.nonce ?? new Uint8Array(8);
  const nonceBlock = new Uint8Array(16);
  nonceBlock.set(nonce.subarray(0, Math.min(16, nonce.length)));
  const padMask = aes128BlockEncrypt(nonceBlock, k16);

  const tag = new Uint8Array(tagLen);
  for (let i = 0; i < tagLen; i++) {
    tag[i] = nhOut[i]! ^ padMask[i]!;
  }
  return tag;
}
