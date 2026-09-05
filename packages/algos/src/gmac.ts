/**
 * GMAC (NIST SP 800-38D):
 * Standalone Galois Message Authentication Code using AES and GHASH over GF(2^128).
 */

import { aes128BlockEncrypt, aes256BlockEncrypt } from "./aes-round";
import { Ghash } from "./ghash";

function aesBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  if (key.length === 32) {
    return aes256BlockEncrypt(block, key);
  }
  const k16 = new Uint8Array(16);
  k16.set(key.subarray(0, Math.min(16, key.length)));
  return aes128BlockEncrypt(block, k16);
}

export interface GmacOptions {
  nonce?: Uint8Array;
  tagLength?: number; // default 16
}

export function gmac(key: Uint8Array, data: Uint8Array, options: GmacOptions = {}): Uint8Array {
  const nonce = options.nonce ?? new Uint8Array(12);
  const tagLen = options.tagLength ?? 16;

  // 1. Derive hash subkey H = AES_K(0^16)
  const zero16 = new Uint8Array(16);
  const H = aesBlock(key, zero16);

  // 2. Derive J0
  const J0 = new Uint8Array(16);
  if (nonce.length === 12) {
    J0.set(nonce);
    J0[15] = 1;
  } else {
    const gh = new Ghash(H);
    gh.update(nonce);
    const lenBlock = new Uint8Array(16);
    const bits = BigInt(nonce.length) * 8n;
    new DataView(lenBlock.buffer).setBigUint64(8, bits, false);
    gh.update(lenBlock);
    J0.set(gh.digest());
  }

  // 3. Compute GHASH over data with length block
  const gh = new Ghash(H);
  gh.update(data);
  const lenBlock = new Uint8Array(16);
  const dataBits = BigInt(data.length) * 8n;
  // In GCM, length block is [len(A) in 64 bits | len(C) in 64 bits]. For GMAC, len(C) = 0.
  new DataView(lenBlock.buffer).setBigUint64(0, dataBits, false);
  gh.update(lenBlock);
  const S = gh.digest();

  // 4. Tag T = S ^ AES_K(J0)
  const mask = aesBlock(key, J0);
  const tag = new Uint8Array(tagLen);
  for (let i = 0; i < tagLen; i++) {
    tag[i] = S[i]! ^ mask[i]!;
  }
  return tag;
}
