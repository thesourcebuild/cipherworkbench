import { md5, sha1 } from "@noble/hashes/legacy.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export type BcryptPrehash = "md5" | "sha1" | "sha256" | "sha512";

/** Hashcat modes 25600/25800/30600/28400 feed lowercase hex, not digest bytes, to bcrypt. */
export function bcryptPrehash(password: string | Uint8Array, algorithm: BcryptPrehash): string {
  const bytes = typeof password === "string" ? new TextEncoder().encode(password) : password;
  switch (algorithm) {
    case "md5":
      return bytesToHex(md5(bytes));
    case "sha1":
      return bytesToHex(sha1(bytes));
    case "sha256":
      return bytesToHex(sha256(bytes));
    case "sha512":
      // The returned 128-byte lowercase hex string is intentionally not truncated here.
      // bcrypt itself consumes only its first 72 UTF-8 bytes, exactly as Hashcat mode 28400 does.
      return bytesToHex(sha512(bytes));
  }
}

const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** RFC 4648 base64 with padding, kept here so these pure formats need no platform globals. */
export function standardBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const hasB = i + 1 < bytes.length;
    const hasC = i + 2 < bytes.length;
    const b = hasB ? bytes[i + 1]! : 0;
    const c = hasC ? bytes[i + 2]! : 0;
    const word = (a << 16) | (b << 8) | c;
    out += BASE64[(word >>> 18) & 63]!;
    out += BASE64[(word >>> 12) & 63]!;
    out += hasB ? BASE64[(word >>> 6) & 63]! : "=";
    out += hasC ? BASE64[word & 63]! : "=";
  }
  return out;
}

/** Constant-time for equal-length serialized password artifacts. */
export function passwordArtifactEqual(actual: string, expected: string): boolean {
  const actualBytes = new TextEncoder().encode(actual);
  const expectedBytes = new TextEncoder().encode(expected);
  let different = actualBytes.length ^ expectedBytes.length;
  const length = Math.max(actualBytes.length, expectedBytes.length);
  for (let i = 0; i < length; i++) {
    different |= (actualBytes[i] ?? 0) ^ (expectedBytes[i] ?? 0);
  }
  return different === 0;
}

/** Apache/Netscape's unsalted SHA-1 password format. */
export function apacheSha(password: string | Uint8Array): string {
  const bytes = typeof password === "string" ? new TextEncoder().encode(password) : password;
  return `{SHA}${standardBase64(sha1(bytes))}`;
}

export function apacheShaVerify(password: string | Uint8Array, stored: string): boolean {
  return (
    /^\{SHA\}[A-Za-z0-9+/]{27}=$/.test(stored) &&
    passwordArtifactEqual(apacheSha(password), stored)
  );
}

export const HTPASSWD_MAX_USERNAME_BYTES = 255;

export function validateHtpasswdUsername(username: string): string | undefined {
  if (username.length === 0) return "Enter a username.";
  if (username.includes(":")) return "The username cannot contain a colon.";
  if (/[\r\n]/.test(username)) return "The username cannot contain a newline.";
  const length = new TextEncoder().encode(username).length;
  if (length > HTPASSWD_MAX_USERNAME_BYTES) {
    return `The username is ${length} bytes; Apache limits it to ${HTPASSWD_MAX_USERNAME_BYTES}.`;
  }
  return undefined;
}

/** Serializes exactly one Apache password-file record, without a trailing newline. */
export function formatHtpasswdRecord(username: string, hash: string): string {
  const problem = validateHtpasswdUsername(username);
  if (problem) throw new Error(problem);
  if (/[\r\n]/.test(hash)) throw new Error("The password hash cannot contain a newline.");
  return `${username}:${hash}`;
}

export function parseHtpasswdRecord(
  record: string,
): { username: string; hash: string } | undefined {
  if (/[\r\n]/.test(record)) return undefined;
  const colon = record.indexOf(":");
  if (colon < 1 || colon === record.length - 1) return undefined;
  const username = record.slice(0, colon);
  if (validateHtpasswdUsername(username)) return undefined;
  return { username, hash: record.slice(colon + 1) };
}
