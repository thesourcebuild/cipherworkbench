/**
 * Standard Unix DES crypt(3):
 * Historical 25-round DES password hashing algorithm with 12-bit salt.
 */

import { createDes } from "./des";

const B64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function encode64(v: number, count: number): string {
  let s = "";
  for (let i = 0; i < count; i++) {
    s += B64_CHARS[v & 0x3f]!;
    v >>>= 6;
  }
  return s;
}

export function unixCrypt(password: string, salt: string): string {
  const cleanSalt = (salt.slice(0, 2).replace(/[^./0-9A-Za-z]/g, "") + "..").slice(0, 2);
  const saltVal =
    B64_CHARS.indexOf(cleanSalt[0]!) |
    (B64_CHARS.indexOf(cleanSalt[1]!) << 6);

  // Take first 8 chars of password, 7 bits each into 8 bytes (DES key format)
  const keyBytes = new Uint8Array(8);
  for (let i = 0; i < Math.min(8, password.length); i++) {
    keyBytes[i] = (password.charCodeAt(i) << 1) & 0xff;
  }

  // Modified DES setup: standard DES key schedule
  const des = createDes(keyBytes);

  // 25 iterations of DES encryption
  const block = new Uint8Array(8);
  const scratch = new Uint8Array(8);
  for (let r = 0; r < 25; r++) {
    block[0]! ^= (saltVal & 0xff);
    des.encryptBlock(block, scratch);
    block.set(scratch);
  }

  // Convert 64-bit result to 11 base64 characters
  let resStr = "";
  const v0 = (block[0]! << 16) | (block[1]! << 8) | block[2]!;
  const v1 = (block[3]! << 16) | (block[4]! << 8) | block[5]!;
  const v2 = (block[6]! << 8) | block[7]!;

  resStr += encode64(v0, 4);
  resStr += encode64(v1, 4);
  resStr += encode64(v2, 3);

  return cleanSalt + resStr;
}

export const unixDesCrypt = unixCrypt;
