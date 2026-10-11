/**
 * BSD Extended crypt(3):
 * DES-based password hashing with 24-bit iteration count and 24-bit salt (prefix '_').
 */

import { createDesCrypt } from "./des";
import {
  cleanDesCryptSalt,
  decodeDesCrypt64,
  desCryptHash,
  desCryptKey,
  encodeDesCrypt64,
} from "./descrypt";

export function bsdExtendedCrypt(
  password: string | Uint8Array,
  salt: string,
  iterations = 1000,
): string {
  const rounds = Math.max(1, Math.min(0xffffff, iterations));
  const countStr = encodeDesCrypt64(rounds, 4);
  const cleanSalt = cleanDesCryptSalt(salt, 4);
  const passwordBytes =
    typeof password === "string" ? new TextEncoder().encode(password) : password;

  let offset = 0;
  let previous = new Uint8Array(8);
  let key: Uint8Array;
  for (;;) {
    key = desCryptKey(passwordBytes.subarray(offset, offset + 8), previous);
    offset += Math.min(8, passwordBytes.length - offset);
    if (offset >= passwordBytes.length) break;
    const des = createDesCrypt(key, 0);
    previous = new Uint8Array(8);
    des.encryptBlock(key, previous);
  }

  return `_${countStr}${cleanSalt}${desCryptHash(key, decodeDesCrypt64(cleanSalt), rounds)}`;
}
