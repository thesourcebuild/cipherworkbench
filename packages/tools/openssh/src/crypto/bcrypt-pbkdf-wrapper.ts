// @ts-expect-error bcrypt-pbkdf lacks official TypeScript declarations
import bcryptPbkdfModule from "bcrypt-pbkdf";

const pbkdf = (bcryptPbkdfModule.pbkdf || bcryptPbkdfModule) as (
  pass: Uint8Array,
  passlen: number,
  salt: Uint8Array,
  saltlen: number,
  key: Uint8Array,
  keylen: number,
  rounds: number,
) => number;

/**
 * Derives a key using OpenSSH's native bcrypt-PBKDF algorithm.
 */
export function deriveBcryptPbkdf(
  passphrase: string,
  salt: Uint8Array,
  keyLen: number,
  rounds: number,
): Uint8Array {
  const enc = new TextEncoder();
  const passBytes = enc.encode(passphrase);
  const outKey = new Uint8Array(keyLen);
  pbkdf(passBytes, passBytes.length, salt, salt.length, outKey, keyLen, rounds);
  return outKey;
}
