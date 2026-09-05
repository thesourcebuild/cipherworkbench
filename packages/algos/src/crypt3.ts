/**
 * Unix crypt(3) Shadow Password Hashes:
 * 1. MD5-Crypt ($1$) - Poul-Henning Kamp (FreeBSD / Linux)
 * 2. SHA-256-Crypt ($5$) - Ulrich Drepper (glibc standard)
 * 3. SHA-512-Crypt ($6$) - Ulrich Drepper (glibc standard)
 *
 * Uses standard shadow file format and custom 64-character alphabet:
 * "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
 */

import { md5 } from "@noble/hashes/legacy.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

const B64T = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function b64From24Bit(b2: number, b1: number, b0: number, n: number): string {
  let w = ((b2 << 16) | (b1 << 8) | b0) >>> 0;
  let out = "";
  while (n-- > 0) {
    out += B64T[w & 0x3f]!;
    w >>>= 6;
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. MD5-Crypt ($1$)
// ─────────────────────────────────────────────────────────────────────────────

export interface CryptOptions {
  salt?: string;
  rounds?: number; // For SHA-256 and SHA-512 (default 5000)
}

/**
 * Computes MD5-Crypt ($1$).
 */
export function md5Crypt(password: string | Uint8Array, salt: string): string {
  const pw = typeof password === "string" ? new TextEncoder().encode(password) : password;

  // Extract salt: up to 8 chars, strip "$1$" if present
  let cleanSalt = salt;
  if (cleanSalt.startsWith("$1$")) cleanSalt = cleanSalt.slice(3);
  const dollarIdx = cleanSalt.indexOf("$");
  if (dollarIdx !== -1) cleanSalt = cleanSalt.slice(0, dollarIdx);
  cleanSalt = cleanSalt.slice(0, 8);
  const saltBytes = new TextEncoder().encode(cleanSalt);

  // Initial alternate digest B = MD5(pw || salt || pw)
  const bData = new Uint8Array(pw.length * 2 + saltBytes.length);
  bData.set(pw, 0);
  bData.set(saltBytes, pw.length);
  bData.set(pw, pw.length + saltBytes.length);
  const altB = md5(bData);

  // Digest A = MD5(pw || "$1$" || salt || altB chunks || bits)
  const prefix = new TextEncoder().encode("$1$");
  const chunks: Uint8Array[] = [pw, prefix, saltBytes];

  for (let i = pw.length; i > 0; i -= 16) {
    chunks.push(altB.subarray(0, Math.min(i, 16)));
  }

  for (let i = pw.length; i > 0; i >>= 1) {
    chunks.push(new Uint8Array([(i & 1) ? 0 : pw[0]!]));
  }

  const totalLen = chunks.reduce((acc, c) => acc + c.length, 0);
  const aData = new Uint8Array(totalLen);
  let off = 0;
  for (const c of chunks) {
    aData.set(c, off);
    off += c.length;
  }

  let finalDigest = md5(aData);

  // 1000 loop iterations
  for (let i = 0; i < 1000; i++) {
    const parts: Uint8Array[] = [];
    if (i & 1) parts.push(pw);
    else parts.push(finalDigest);

    if (i % 3 !== 0) parts.push(saltBytes);
    if (i % 7 !== 0) parts.push(pw);

    if (i & 1) parts.push(finalDigest);
    else parts.push(pw);

    const roundLen = parts.reduce((acc, p) => acc + p.length, 0);
    const roundBuf = new Uint8Array(roundLen);
    let rOff = 0;
    for (const p of parts) {
      roundBuf.set(p, rOff);
      rOff += p.length;
    }
    finalDigest = md5(roundBuf);
  }

  // PHK 6-bit transposition
  const d = finalDigest;
  let hashStr = "";
  hashStr += b64From24Bit(d[0]!, d[6]!, d[12]!, 4);
  hashStr += b64From24Bit(d[1]!, d[7]!, d[13]!, 4);
  hashStr += b64From24Bit(d[2]!, d[8]!, d[14]!, 4);
  hashStr += b64From24Bit(d[3]!, d[9]!, d[15]!, 4);
  hashStr += b64From24Bit(d[4]!, d[10]!, d[5]!, 4);
  hashStr += b64From24Bit(0, 0, d[11]!, 2);

  return `$1$${cleanSalt}$${hashStr}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SHA-256-Crypt ($5$) & SHA-512-Crypt ($6$)
// ─────────────────────────────────────────────────────────────────────────────

function shaCryptGeneric(
  isSha512: boolean,
  password: string | Uint8Array,
  salt: string,
  optionsRounds?: number
): string {
  const hashFn = isSha512 ? sha512 : sha256;
  const hashSize = isSha512 ? 64 : 32;
  const magic = isSha512 ? "$6$" : "$5$";

  const pw = typeof password === "string" ? new TextEncoder().encode(password) : password;

  let cleanSalt = salt;
  if (cleanSalt.startsWith(magic)) cleanSalt = cleanSalt.slice(3);

  let rounds = optionsRounds ?? 5000;
  let roundsSpecified = optionsRounds !== undefined;

  if (cleanSalt.startsWith("rounds=")) {
    const dollar = cleanSalt.indexOf("$");
    if (dollar !== -1) {
      const parsed = parseInt(cleanSalt.slice(7, dollar), 10);
      if (!isNaN(parsed)) {
        rounds = parsed;
        roundsSpecified = true;
      }
      cleanSalt = cleanSalt.slice(dollar + 1);
    }
  }

  const dollarIdx = cleanSalt.indexOf("$");
  if (dollarIdx !== -1) cleanSalt = cleanSalt.slice(0, dollarIdx);
  cleanSalt = cleanSalt.slice(0, 16);
  const saltBytes = new TextEncoder().encode(cleanSalt);

  rounds = Math.max(1000, Math.min(999999999, rounds));

  // Step 1: Alternate B = H(pw || salt || pw)
  const bData = new Uint8Array(pw.length * 2 + saltBytes.length);
  bData.set(pw, 0);
  bData.set(saltBytes, pw.length);
  bData.set(pw, pw.length + saltBytes.length);
  const altB = hashFn(bData);

  // Step 2: Digest A = H(pw || salt || repeated B || bits)
  const aParts: Uint8Array[] = [pw, saltBytes];
  for (let i = pw.length; i > 0; i -= hashSize) {
    aParts.push(altB.subarray(0, Math.min(i, hashSize)));
  }

  for (let i = pw.length; i > 0; i >>= 1) {
    if (i & 1) aParts.push(altB);
    else aParts.push(pw);
  }

  const aLen = aParts.reduce((acc, p) => acc + p.length, 0);
  const aBuf = new Uint8Array(aLen);
  let aOff = 0;
  for (const p of aParts) {
    aBuf.set(p, aOff);
    aOff += p.length;
  }
  const altA = hashFn(aBuf);

  // Sequence P: H(pw repeated length times)
  const pBuf = new Uint8Array(pw.length * pw.length);
  for (let i = 0; i < pw.length; i++) {
    pBuf.set(pw, i * pw.length);
  }
  const dp = hashFn(pBuf);
  const pSeq = new Uint8Array(pw.length);
  for (let i = 0; i < pw.length; i += hashSize) {
    pSeq.set(dp.subarray(0, Math.min(pw.length - i, hashSize)), i);
  }

  // Sequence S: H(salt repeated length times)
  const sLen = 16 + altA[0]!;
  const sBuf = new Uint8Array(saltBytes.length * sLen);
  for (let i = 0; i < sLen; i++) {
    sBuf.set(saltBytes, i * saltBytes.length);
  }
  const ds = hashFn(sBuf);
  const sSeq = new Uint8Array(saltBytes.length);
  for (let i = 0; i < saltBytes.length; i += hashSize) {
    sSeq.set(ds.subarray(0, Math.min(saltBytes.length - i, hashSize)), i);
  }

  // Loop rounds
  let current = altA;
  for (let r = 0; r < rounds; r++) {
    const parts: Uint8Array[] = [];
    if (r & 1) parts.push(pSeq);
    else parts.push(current);

    if (r % 3 !== 0) parts.push(sSeq);
    if (r % 7 !== 0) parts.push(pSeq);

    if (r & 1) parts.push(current);
    else parts.push(pSeq);

    const rLen = parts.reduce((acc, p) => acc + p.length, 0);
    const rBuf = new Uint8Array(rLen);
    let rOff = 0;
    for (const p of parts) {
      rBuf.set(p, rOff);
      rOff += p.length;
    }
    current = hashFn(rBuf);
  }

  // Custom base64 permutation
  let hashStr = "";
  if (!isSha512) {
    // SHA-256 permutation
    const d = current;
    hashStr += b64From24Bit(d[0]!, d[10]!, d[20]!, 4);
    hashStr += b64From24Bit(d[21]!, d[1]!, d[11]!, 4);
    hashStr += b64From24Bit(d[12]!, d[22]!, d[2]!, 4);
    hashStr += b64From24Bit(d[3]!, d[13]!, d[23]!, 4);
    hashStr += b64From24Bit(d[24]!, d[4]!, d[14]!, 4);
    hashStr += b64From24Bit(d[15]!, d[25]!, d[5]!, 4);
    hashStr += b64From24Bit(d[6]!, d[16]!, d[26]!, 4);
    hashStr += b64From24Bit(d[27]!, d[7]!, d[17]!, 4);
    hashStr += b64From24Bit(d[18]!, d[28]!, d[8]!, 4);
    hashStr += b64From24Bit(d[9]!, d[19]!, d[29]!, 4);
    hashStr += b64From24Bit(0, d[31]!, d[30]!, 3);
  } else {
    // SHA-512 permutation
    const d = current;
    hashStr += b64From24Bit(d[0]!, d[21]!, d[42]!, 4);
    hashStr += b64From24Bit(d[22]!, d[43]!, d[1]!, 4);
    hashStr += b64From24Bit(d[44]!, d[2]!, d[23]!, 4);
    hashStr += b64From24Bit(d[3]!, d[24]!, d[45]!, 4);
    hashStr += b64From24Bit(d[25]!, d[46]!, d[4]!, 4);
    hashStr += b64From24Bit(d[47]!, d[5]!, d[26]!, 4);
    hashStr += b64From24Bit(d[6]!, d[27]!, d[48]!, 4);
    hashStr += b64From24Bit(d[28]!, d[49]!, d[7]!, 4);
    hashStr += b64From24Bit(d[50]!, d[8]!, d[29]!, 4);
    hashStr += b64From24Bit(d[9]!, d[30]!, d[51]!, 4);
    hashStr += b64From24Bit(d[31]!, d[52]!, d[10]!, 4);
    hashStr += b64From24Bit(d[53]!, d[11]!, d[32]!, 4);
    hashStr += b64From24Bit(d[12]!, d[33]!, d[54]!, 4);
    hashStr += b64From24Bit(d[34]!, d[55]!, d[13]!, 4);
    hashStr += b64From24Bit(d[56]!, d[14]!, d[35]!, 4);
    hashStr += b64From24Bit(d[15]!, d[36]!, d[57]!, 4);
    hashStr += b64From24Bit(d[37]!, d[58]!, d[16]!, 4);
    hashStr += b64From24Bit(d[59]!, d[17]!, d[38]!, 4);
    hashStr += b64From24Bit(d[18]!, d[39]!, d[60]!, 4);
    hashStr += b64From24Bit(d[40]!, d[61]!, d[19]!, 4);
    hashStr += b64From24Bit(d[62]!, d[20]!, d[41]!, 4);
    hashStr += b64From24Bit(0, 0, d[63]!, 2);
  }

  const roundsTag = roundsSpecified ? `rounds=${rounds}$` : "";
  return `${magic}${roundsTag}${cleanSalt}$${hashStr}`;
}

/**
 * Computes SHA-256-Crypt ($5$).
 */
export function sha256Crypt(password: string | Uint8Array, salt: string, rounds?: number): string {
  return shaCryptGeneric(false, password, salt, rounds);
}

/**
 * Computes SHA-512-Crypt ($6$).
 */
export function sha512Crypt(password: string | Uint8Array, salt: string, rounds?: number): string {
  return shaCryptGeneric(true, password, salt, rounds);
}

/**
 * Verifies a password against an MD5-Crypt, SHA-256-Crypt, or SHA-512-Crypt hash string.
 */
export function cryptVerify(password: string | Uint8Array, hash: string): boolean {
  if (hash.startsWith("$1$")) {
    const parts = hash.split("$");
    const salt = parts[2] ?? "";
    return md5Crypt(password, salt) === hash;
  }
  if (hash.startsWith("$5$")) {
    const parts = hash.split("$");
    let rounds: number | undefined;
    let salt = "";
    if (parts[2]?.startsWith("rounds=")) {
      rounds = parseInt(parts[2].slice(7), 10);
      salt = parts[3] ?? "";
    } else {
      salt = parts[2] ?? "";
    }
    return sha256Crypt(password, salt, rounds) === hash;
  }
  if (hash.startsWith("$6$")) {
    const parts = hash.split("$");
    let rounds: number | undefined;
    let salt = "";
    if (parts[2]?.startsWith("rounds=")) {
      rounds = parseInt(parts[2].slice(7), 10);
      salt = parts[3] ?? "";
    } else {
      salt = parts[2] ?? "";
    }
    return sha512Crypt(password, salt, rounds) === hash;
  }
  return false;
}
