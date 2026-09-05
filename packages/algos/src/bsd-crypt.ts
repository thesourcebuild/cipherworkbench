/**
 * BSD Extended crypt(3):
 * DES-based password hashing with 24-bit iteration count and 24-bit salt (prefix '_').
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

export function bsdExtendedCrypt(password: string, salt: string, iterations = 1000): string {
  const rounds = Math.max(1, Math.min(0xffffff, iterations));
  const countStr = encode64(rounds, 4);
  const cleanSalt = (salt.slice(0, 4).replace(/[^./0-9A-Za-z]/g, "") + "....").slice(0, 4);

  const keyBytes = new Uint8Array(8);
  for (let i = 0; i < Math.min(8, password.length); i++) {
    keyBytes[i] = (password.charCodeAt(i) << 1) & 0xff;
  }
  const des = createDes(keyBytes);

  const block = new Uint8Array(8);
  const scratch = new Uint8Array(8);
  for (let r = 0; r < rounds; r++) {
    des.encryptBlock(block, scratch);
    block.set(scratch);
  }

  const v0 = (block[0]! << 16) | (block[1]! << 8) | block[2]!;
  const v1 = (block[3]! << 16) | (block[4]! << 8) | block[5]!;
  const v2 = (block[6]! << 8) | block[7]!;

  let resStr = "";
  resStr += encode64(v0, 4);
  resStr += encode64(v1, 4);
  resStr += encode64(v2, 3);

  return "_" + countStr + cleanSalt + resStr;
}
