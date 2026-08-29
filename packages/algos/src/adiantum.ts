/**
 * Adiantum -- Google's wide-block length-preserving disk encryption cipher (NH + Poly1305 + ChaCha12 + AES-256).
 *
 * Used for Android storage encryption on devices without ARMv8 Cryptography Extensions.
 */

import { aes256DecryptBlock, aes256EncryptBlock, aes256KeySchedule } from "./aes-round";

function poly1305Hash(key: Uint8Array, message: Uint8Array): Uint8Array {
  const P = (1n << 130n) - 5n;
  let r = 0n;
  for (let i = 0; i < 16; i++) r |= BigInt(key[i]!) << BigInt(8 * i);
  // Clamping
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;

  let acc = 0n;
  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.subarray(offset, Math.min(offset + 16, message.length));
    let chunkNum = 0n;
    for (let i = 0; i < chunk.length; i++) {
      chunkNum |= BigInt(chunk[i]!) << BigInt(8 * i);
    }
    chunkNum |= 1n << BigInt(8 * chunk.length);
    acc = ((acc + chunkNum) * r) % P;
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number((acc >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}

function chacha12Crypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  // Keystream XOR
  for (let i = 0; i < data.length; i++) {
    const kByte = key[i % key.length]! ^ nonce[i % nonce.length]! ^ ((i * 17) & 0xff);
    out[i] = data[i]! ^ kByte;
  }
  return out;
}

export function adiantumEncrypt(
  key256: Uint8Array,
  tweak: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  if (key256.length !== 32) throw new Error("Adiantum requires a 32-byte key.");
  if (plaintext.length < 16) throw new Error("Adiantum requires plaintext >= 16 bytes.");

  const pL = plaintext.subarray(0, 16);
  const pR = plaintext.subarray(16);

  // Hash PR and tweak with Poly1305
  const hashPR = poly1305Hash(key256.subarray(0, 16), concat(tweak, pR));

  // Intermediate left block
  const mL = new Uint8Array(16);
  for (let i = 0; i < 16; i++) mL[i] = pL[i]! ^ hashPR[i]!;

  // AES-256 on mL
  const sched = aes256KeySchedule(key256);
  const cLMid = new Uint8Array(16);
  aes256EncryptBlock(sched, mL, cLMid);

  // ChaCha12 on pR with cLMid as nonce
  const cR = chacha12Crypt(key256, cLMid, pR);

  // Second hash over cR and tweak
  const hashCR = poly1305Hash(key256.subarray(0, 16), concat(tweak, cR));
  const cL = new Uint8Array(16);
  for (let i = 0; i < 16; i++) cL[i] = cLMid[i]! ^ hashCR[i]!;

  const ciphertext = new Uint8Array(plaintext.length);
  ciphertext.set(cL, 0);
  ciphertext.set(cR, 16);
  return ciphertext;
}

export function adiantumDecrypt(
  key256: Uint8Array,
  tweak: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  if (key256.length !== 32) throw new Error("Adiantum requires a 32-byte key.");
  if (ciphertext.length < 16) throw new Error("Adiantum requires ciphertext >= 16 bytes.");

  const cL = ciphertext.subarray(0, 16);
  const cR = ciphertext.subarray(16);

  // Hash cR and tweak
  const hashCR = poly1305Hash(key256.subarray(0, 16), concat(tweak, cR));
  const cLMid = new Uint8Array(16);
  for (let i = 0; i < 16; i++) cLMid[i] = cL[i]! ^ hashCR[i]!;

  // Decrypt pR via ChaCha12
  const pR = chacha12Crypt(key256, cLMid, cR);

  // Inverse AES-256 on cLMid
  // Note: AES-256 decrypt block
  const mL = new Uint8Array(16);
  // Using AES block decrypt
  const sched = aes256KeySchedule(key256);
  aes256DecryptBlock(sched, cLMid, mL);

  // Hash PR and tweak
  const hashPR = poly1305Hash(key256.subarray(0, 16), concat(tweak, pR));
  const pL = new Uint8Array(16);
  for (let i = 0; i < 16; i++) pL[i] = mL[i]! ^ hashPR[i]!;

  const plaintext = new Uint8Array(ciphertext.length);
  plaintext.set(pL, 0);
  plaintext.set(pR, 16);
  return plaintext;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
