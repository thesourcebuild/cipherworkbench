/**
 * Standard Unix DES crypt(3):
 * Historical 25-round DES password hashing algorithm with 12-bit salt.
 */

import { createDesCrypt } from "./des";

const B64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

export function encodeDesCrypt64(v: number, count: number): string {
  let s = "";
  for (let i = 0; i < count; i++) {
    s += B64_CHARS[v & 0x3f]!;
    v >>>= 6;
  }
  return s;
}

export function cleanDesCryptSalt(salt: string, length: number): string {
  return (salt.slice(0, length).replace(/[^./0-9A-Za-z]/g, "") + ".".repeat(length)).slice(
    0,
    length,
  );
}

export function decodeDesCrypt64(value: string): number {
  let decoded = 0;
  for (let i = 0; i < value.length; i++) decoded |= B64_CHARS.indexOf(value[i]!) << (6 * i);
  return decoded;
}

export function desCryptKey(password: Uint8Array, previous = new Uint8Array(8)): Uint8Array {
  const key = new Uint8Array(8);
  for (let i = 0; i < 8; i++) key[i] = previous[i]! ^ ((password[i] ?? 0) << 1);
  return key;
}

export function desCryptHash(key: Uint8Array, salt: number, rounds: number): string {
  const des = createDesCrypt(key, salt);
  const block = new Uint8Array(8);
  const scratch = new Uint8Array(8);
  for (let i = 0; i < rounds; i++) {
    des.encryptBlock(block, scratch);
    block.set(scratch);
  }

  let encoded = "";
  for (let i = 0; i < block.length; i += 3) {
    const a = block[i]!;
    const hasB = i + 1 < block.length;
    const hasC = i + 2 < block.length;
    const b = hasB ? block[i + 1]! : 0;
    const c = hasC ? block[i + 2]! : 0;
    encoded += B64_CHARS[a >>> 2]!;
    encoded += B64_CHARS[((a & 3) << 4) | (b >>> 4)]!;
    if (hasB) encoded += B64_CHARS[((b & 15) << 2) | (c >>> 6)]!;
    if (hasC) encoded += B64_CHARS[c & 63]!;
  }
  return encoded;
}

export function unixCrypt(password: string | Uint8Array, salt: string): string {
  const cleanSalt = cleanDesCryptSalt(salt, 2);
  const saltValue = decodeDesCrypt64(cleanSalt);
  const passwordBytes =
    typeof password === "string"
      ? new TextEncoder().encode(password).subarray(0, 8)
      : password.subarray(0, 8);
  return cleanSalt + desCryptHash(desCryptKey(passwordBytes), saltValue, 25);
}

export const unixDesCrypt = unixCrypt;
