/**
 * Poly1305-AES -- D. J. Bernstein's original 2005 specification.
 *
 * Keys:
 *  - 16-byte Poly1305 key r (clamped)
 *  - 16-byte AES-128 key k
 *  - 16-byte nonce n
 *
 * Formula:
 *  Tag = (Poly1305(r, message) + AES_k(n)) mod 2^128
 */

import { aes128EncryptBlock, aes128KeySchedule } from "./aes-round";

const P = (1n << 130n) - 5n;

function clamp(r: Uint8Array): bigint {
  const c = new Uint8Array(r);
  c[3] = c[3]! & 15;
  c[7] = c[7]! & 15;
  c[11] = c[11]! & 15;
  c[15] = c[15]! & 15;
  c[4] = c[4]! & 252;
  c[8] = c[8]! & 252;
  c[12] = c[12]! & 252;

  let val = 0n;
  for (let i = 0; i < 16; i++) {
    val |= BigInt(c[i]!) << BigInt(8 * i);
  }
  return val;
}

export function poly1305AesMac(
  keyR: Uint8Array,
  keyK: Uint8Array,
  nonce: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  if (keyR.length !== 16) throw new Error("Poly1305-AES key r must be 16 bytes.");
  if (keyK.length !== 16) throw new Error("Poly1305-AES AES key k must be 16 bytes.");
  if (nonce.length !== 16) throw new Error("Poly1305-AES nonce must be 16 bytes.");

  const r = clamp(keyR);
  let acc = 0n;

  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.subarray(offset, Math.min(offset + 16, message.length));
    let chunkNum = 0n;
    for (let i = 0; i < chunk.length; i++) {
      chunkNum |= BigInt(chunk[i]!) << BigInt(8 * i);
    }
    chunkNum |= 1n << BigInt(8 * chunk.length); // 0x01 append

    acc = ((acc + chunkNum) * r) % P;
  }

  // Encrypt nonce with AES-128: s = AES_k(n)
  const sched = aes128KeySchedule(keyK);
  const sBytes = new Uint8Array(16);
  aes128EncryptBlock(sched, nonce, sBytes);

  let s = 0n;
  for (let i = 0; i < 16; i++) {
    s |= BigInt(sBytes[i]!) << BigInt(8 * i);
  }

  // Tag = (acc + s) mod 2^128
  const tagNum = (acc + s) & ((1n << 128n) - 1n);
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tag[i] = Number((tagNum >> BigInt(8 * i)) & 0xffn);
  }

  return tag;
}
