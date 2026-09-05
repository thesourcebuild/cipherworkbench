/**
 * CBC-MAC / DAA (ANSI X9.9 / FIPS PUB 113):
 * Data Authentication Algorithm using DES or AES in CBC mode.
 */

import { aes128BlockEncrypt, aes256BlockEncrypt } from "./aes-round";
import { createDes } from "./des";

function aesBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  if (key.length === 32) {
    return aes256BlockEncrypt(block, key);
  }
  const k16 = new Uint8Array(16);
  k16.set(key.subarray(0, Math.min(16, key.length)));
  return aes128BlockEncrypt(block, k16);
}

export interface CbcMacOptions {
  cipher?: "des" | "aes";
  padding?: "zeros" | "iso7816";
  tagLength?: number;
}

export function cbcMac(key: Uint8Array, data: Uint8Array, options: CbcMacOptions = {}): Uint8Array {
  const cipher = options.cipher ?? (key.length <= 8 ? "des" : "aes");
  const blockSize = cipher === "des" ? 8 : 16;
  const padding = options.padding ?? "zeros";

  let padded: Uint8Array;
  if (padding === "iso7816") {
    // ISO/IEC 7816-4: append 0x80 then 0x00 bytes to block boundary
    const padLen = blockSize - (data.length % blockSize);
    padded = new Uint8Array(data.length + padLen);
    padded.set(data);
    padded[data.length] = 0x80;
  } else {
    // zeros: pad with 0x00 to block boundary (min 1 block)
    const total = Math.max(blockSize, Math.ceil(data.length / blockSize) * blockSize);
    padded = new Uint8Array(total);
    padded.set(data);
  }

  const tagLen = options.tagLength ?? (cipher === "des" ? 8 : 16);

  if (cipher === "des") {
    const desKey = key.length >= 8 ? key.subarray(0, 8) : new Uint8Array(8);
    const des = createDes(desKey);
    const block = new Uint8Array(8);
    const scratch = new Uint8Array(8);
    for (let i = 0; i < padded.length; i += 8) {
      for (let b = 0; b < 8; b++) {
        block[b]! ^= padded[i + b] ?? 0;
      }
      des.encryptBlock(block, scratch);
      block.set(scratch);
    }
    return new Uint8Array(block.slice(0, tagLen));
  } else {
    const aesKey = key.length >= 16 ? key : new Uint8Array(16);
    let block = new Uint8Array(16);
    for (let i = 0; i < padded.length; i += 16) {
      for (let b = 0; b < 16; b++) {
        block[b]! ^= padded[i + b] ?? 0;
      }
      block = new Uint8Array(aesBlock(aesKey, block));
    }
    return new Uint8Array(block.slice(0, tagLen));
  }
}
