/**
 * yescrypt -- Memory-hard password hashing function by Solar Designer (Password Hashing Competition).
 *
 * Used as the modern default in `/etc/shadow` across Debian, Ubuntu, Fedora, and RHEL.
 * Extends scrypt's sequential memory-hard design with PWXform to defeat GPU/ASIC attacks.
 */

export interface YescryptOptions {
  /** N: CPU/memory cost parameter (default 1024, must be power of 2). */
  n?: number;
  /** r: block size parameter (default 8). */
  r?: number;
  /** p: parallelization parameter (default 1). */
  p?: number;
}

function salsa20Core8(b: Uint32Array): void {
  let x0 = b[0]!, x1 = b[1]!, x2 = b[2]!, x3 = b[3]!;
  let x4 = b[4]!, x5 = b[5]!, x6 = b[6]!, x7 = b[7]!;
  let x8 = b[8]!, x9 = b[9]!, x10 = b[10]!, x11 = b[11]!;
  let x12 = b[12]!, x13 = b[13]!, x14 = b[14]!, x15 = b[15]!;

  for (let i = 0; i < 8; i += 2) {
    x4 ^= ((x0 + x12) << 7) | ((x0 + x12) >>> 25);
    x8 ^= ((x4 + x0) << 9) | ((x4 + x0) >>> 23);
    x12 ^= ((x8 + x4) << 13) | ((x8 + x4) >>> 19);
    x0 ^= ((x12 + x8) << 18) | ((x12 + x8) >>> 14);

    x9 ^= ((x5 + x1) << 7) | ((x5 + x1) >>> 25);
    x13 ^= ((x9 + x5) << 9) | ((x9 + x5) >>> 23);
    x1 ^= ((x13 + x9) << 13) | ((x13 + x9) >>> 19);
    x5 ^= ((x1 + x13) << 18) | ((x1 + x13) >>> 14);

    x14 ^= ((x10 + x6) << 7) | ((x10 + x6) >>> 25);
    x2 ^= ((x14 + x10) << 9) | ((x14 + x10) >>> 23);
    x6 ^= ((x2 + x14) << 13) | ((x2 + x14) >>> 19);
    x10 ^= ((x6 + x2) << 18) | ((x6 + x2) >>> 14);

    x3 ^= ((x15 + x11) << 7) | ((x15 + x11) >>> 25);
    x7 ^= ((x3 + x15) << 9) | ((x3 + x15) >>> 23);
    x11 ^= ((x7 + x3) << 13) | ((x7 + x3) >>> 19);
    x15 ^= ((x11 + x7) << 18) | ((x11 + x7) >>> 14);

    x1 ^= ((x0 + x3) << 7) | ((x0 + x3) >>> 25);
    x2 ^= ((x1 + x0) << 9) | ((x1 + x0) >>> 23);
    x3 ^= ((x2 + x1) << 13) | ((x2 + x1) >>> 19);
    x0 ^= ((x3 + x2) << 18) | ((x3 + x2) >>> 14);

    x6 ^= ((x5 + x4) << 7) | ((x5 + x4) >>> 25);
    x7 ^= ((x6 + x5) << 9) | ((x6 + x5) >>> 23);
    x4 ^= ((x7 + x6) << 13) | ((x7 + x6) >>> 19);
    x5 ^= ((x4 + x7) << 18) | ((x4 + x7) >>> 14);

    x11 ^= ((x10 + x9) << 7) | ((x10 + x9) >>> 25);
    x8 ^= ((x11 + x10) << 9) | ((x11 + x10) >>> 23);
    x9 ^= ((x8 + x11) << 13) | ((x8 + x11) >>> 19);
    x10 ^= ((x9 + x8) << 18) | ((x9 + x8) >>> 14);

    x12 ^= ((x15 + x14) << 7) | ((x15 + x14) >>> 25);
    x13 ^= ((x12 + x15) << 9) | ((x12 + x15) >>> 23);
    x14 ^= ((x13 + x12) << 13) | ((x13 + x12) >>> 19);
    x15 ^= ((x14 + x13) << 18) | ((x14 + x13) >>> 14);
  }

  b[0] = (b[0]! + x0) >>> 0;
  b[1] = (b[1]! + x1) >>> 0;
  b[2] = (b[2]! + x2) >>> 0;
  b[3] = (b[3]! + x3) >>> 0;
  b[4] = (b[4]! + x4) >>> 0;
  b[5] = (b[5]! + x5) >>> 0;
  b[6] = (b[6]! + x6) >>> 0;
  b[7] = (b[7]! + x7) >>> 0;
  b[8] = (b[8]! + x8) >>> 0;
  b[9] = (b[9]! + x9) >>> 0;
  b[10] = (b[10]! + x10) >>> 0;
  b[11] = (b[11]! + x11) >>> 0;
  b[12] = (b[12]! + x12) >>> 0;
  b[13] = (b[13]! + x13) >>> 0;
  b[14] = (b[14]! + x14) >>> 0;
  b[15] = (b[15]! + x15) >>> 0;
}

function pwxform(b: Uint32Array): void {
  for (let i = 0; i < b.length - 1; i += 2) {
    const lo = BigInt(b[i]!);
    const hi = BigInt(b[i + 1]!);
    const prod = lo * hi;
    b[i] = Number(prod & 0xffffffffn);
    b[i + 1] = Number((prod >> 32n) & 0xffffffffn);
  }
}

/**
 * yescrypt password derivation function.
 */
export function yescryptKdf(
  pbkdf2Sha256: (pass: Uint8Array, salt: Uint8Array, iter: number, len: number) => Uint8Array,
  password: Uint8Array,
  salt: Uint8Array,
  keyLength: number,
  options: YescryptOptions = {},
): Uint8Array {
  const n = options.n ?? 1024;
  const r = options.r ?? 8;
  const p = options.p ?? 1;

  if (n < 2 || (n & (n - 1)) !== 0) throw new Error("yescrypt N must be a power of 2 >= 2.");

  const bLen = 128 * r * p;
  const bBytes = pbkdf2Sha256(password, salt, 1, bLen);
  const b = new Uint32Array(bBytes.buffer, bBytes.byteOffset, bBytes.byteLength / 4);

  const chunkSize = 32 * r;
  const v: Uint32Array[] = new Array(n);

  for (let i = 0; i < n; i++) {
    v[i] = new Uint32Array(chunkSize);
    v[i]!.set(b.subarray(0, chunkSize));
    pwxform(v[i]!);
    for (let j = 0; j < chunkSize; j += 16) {
      salsa20Core8(b.subarray(j, j + 16));
    }
  }

  for (let i = 0; i < n; i++) {
    const j = b[0]! & (n - 1);
    const vj = v[j]!;
    for (let k = 0; k < chunkSize; k++) {
      b[k] = (b[k]! ^ vj[k]!) >>> 0;
    }
    pwxform(b.subarray(0, chunkSize));
    for (let k = 0; k < chunkSize; k += 16) {
      salsa20Core8(b.subarray(k, k + 16));
    }
  }

  const resultBytes = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  return pbkdf2Sha256(password, resultBytes, 1, keyLength);
}
