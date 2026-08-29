/**
 * HCTR2 -- Length-preserving wide-block disk encryption mode (Linux Kernel 6.0+).
 */

import { aes256DecryptBlock, aes256EncryptBlock, aes256KeySchedule } from "./aes-round";

function polyval(key: Uint8Array, message: Uint8Array): Uint8Array {
  let h = 0n;
  for (let i = 0; i < 16; i++) h |= BigInt(key[i]!) << BigInt(8 * i);

  let acc = 0n;
  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.subarray(offset, Math.min(offset + 16, message.length));
    let chunkNum = 0n;
    for (let i = 0; i < chunk.length; i++) {
      chunkNum |= BigInt(chunk[i]!) << BigInt(8 * i);
    }
    acc = (acc ^ chunkNum) * h;
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number((acc >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}

export function hctr2Encrypt(key256: Uint8Array, tweak: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (plaintext.length < 16) throw new Error("HCTR2 requires plaintext >= 16 bytes.");

  const p0 = plaintext.subarray(0, 16);
  const pRest = plaintext.subarray(16);

  const hash1 = polyval(key256.subarray(0, 16), concat(tweak, pRest));
  const u = new Uint8Array(16);
  for (let i = 0; i < 16; i++) u[i] = p0[i]! ^ hash1[i]!;

  const sched = aes256KeySchedule(key256);
  const v = new Uint8Array(16);
  aes256EncryptBlock(sched, u, v);

  const cRest = new Uint8Array(pRest.length);
  for (let i = 0; i < pRest.length; i++) {
    cRest[i] = pRest[i]! ^ v[i % 16]! ^ ((i * 37) & 0xff);
  }

  const hash2 = polyval(key256.subarray(0, 16), concat(tweak, cRest));
  const c0 = new Uint8Array(16);
  for (let i = 0; i < 16; i++) c0[i] = v[i]! ^ hash2[i]!;

  const ciphertext = new Uint8Array(plaintext.length);
  ciphertext.set(c0, 0);
  ciphertext.set(cRest, 16);
  return ciphertext;
}

export function hctr2Decrypt(key256: Uint8Array, tweak: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length < 16) throw new Error("HCTR2 requires ciphertext >= 16 bytes.");

  const c0 = ciphertext.subarray(0, 16);
  const cRest = ciphertext.subarray(16);

  const hash2 = polyval(key256.subarray(0, 16), concat(tweak, cRest));
  const v = new Uint8Array(16);
  for (let i = 0; i < 16; i++) v[i] = c0[i]! ^ hash2[i]!;

  const pRest = new Uint8Array(cRest.length);
  for (let i = 0; i < cRest.length; i++) {
    pRest[i] = cRest[i]! ^ v[i % 16]! ^ ((i * 37) & 0xff);
  }

  const sched = aes256KeySchedule(key256);
  const u = new Uint8Array(16);
  aes256DecryptBlock(sched, v, u);

  const hash1 = polyval(key256.subarray(0, 16), concat(tweak, pRest));
  const p0 = new Uint8Array(16);
  for (let i = 0; i < 16; i++) p0[i] = u[i]! ^ hash1[i]!;

  const plaintext = new Uint8Array(ciphertext.length);
  plaintext.set(p0, 0);
  plaintext.set(pRest, 16);
  return plaintext;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
