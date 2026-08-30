/**
 * A single AES round, key expansion, and block encryption/decryption routines.
 */

export const AES_SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

export const AES_INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  AES_INV_SBOX[AES_SBOX[i]!] = i;
}

const xtime = (x: number): number => ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff;

const mul = (a: number, b: number): number => {
  let res = 0;
  let temp = a;
  for (let i = 0; i < 8; i++) {
    if ((b & (1 << i)) !== 0) res ^= temp;
    temp = xtime(temp);
  }
  return res & 0xff;
};

export function aesRound(input: Uint8Array, rk: Uint8Array, out: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const a0 = AES_SBOX[input[4 * c + 0]!]!;
    const a1 = AES_SBOX[input[4 * ((c + 1) & 3) + 1]!]!;
    const a2 = AES_SBOX[input[4 * ((c + 2) & 3) + 2]!]!;
    const a3 = AES_SBOX[input[4 * ((c + 3) & 3) + 3]!]!;

    out[4 * c + 0] = (xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3 ^ rk[4 * c + 0]!) & 0xff;
    out[4 * c + 1] = (a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3 ^ rk[4 * c + 1]!) & 0xff;
    out[4 * c + 2] = (a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3 ^ rk[4 * c + 2]!) & 0xff;
    out[4 * c + 3] = (xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3) ^ rk[4 * c + 3]!) & 0xff;
  }
}

export function aesSubBytesShiftRows(input: Uint8Array, rk: Uint8Array, out: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    out[4 * c + 0] = (AES_SBOX[input[4 * c + 0]!]! ^ rk[4 * c + 0]!) & 0xff;
    out[4 * c + 1] = (AES_SBOX[input[4 * ((c + 1) & 3) + 1]!]! ^ rk[4 * c + 1]!) & 0xff;
    out[4 * c + 2] = (AES_SBOX[input[4 * ((c + 2) & 3) + 2]!]! ^ rk[4 * c + 2]!) & 0xff;
    out[4 * c + 3] = (AES_SBOX[input[4 * ((c + 3) & 3) + 3]!]! ^ rk[4 * c + 3]!) & 0xff;
  }
}

const RCON = new Uint8Array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

export function aes128KeySchedule(key: Uint8Array): Uint8Array[] {
  const rks: Uint8Array[] = new Array(11);
  const words = new Uint32Array(44);
  for (let i = 0; i < 4; i++) {
    words[i] = (key[4 * i]! | (key[4 * i + 1]! << 8) | (key[4 * i + 2]! << 16) | (key[4 * i + 3]! << 24)) >>> 0;
  }

  for (let i = 4; i < 44; i++) {
    let temp = words[i - 1]!;
    if (i % 4 === 0) {
      const rot = (temp >>> 8) | (temp << 24);
      const b0 = AES_SBOX[rot & 0xff]!;
      const b1 = AES_SBOX[(rot >>> 8) & 0xff]!;
      const b2 = AES_SBOX[(rot >>> 16) & 0xff]!;
      const b3 = AES_SBOX[(rot >>> 24) & 0xff]!;
      const sub = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
      const rconWord = RCON[(i / 4) - 1]!;
      temp = (sub ^ rconWord) >>> 0;
    }
    words[i] = (words[i - 4]! ^ temp) >>> 0;
  }

  for (let r = 0; r <= 10; r++) {
    const rk = new Uint8Array(16);
    for (let c = 0; c < 4; c++) {
      const w = words[r * 4 + c]!;
      rk[4 * c + 0] = w & 0xff;
      rk[4 * c + 1] = (w >>> 8) & 0xff;
      rk[4 * c + 2] = (w >>> 16) & 0xff;
      rk[4 * c + 3] = (w >>> 24) & 0xff;
    }
    rks[r] = rk;
  }
  return rks;
}

export function aes128EncryptBlock(rks: Uint8Array[], input: Uint8Array, out: Uint8Array): void {
  const state = new Uint8Array(16);
  for (let i = 0; i < 16; i++) state[i] = input[i]! ^ rks[0]![i]!;

  const next = new Uint8Array(16);
  for (let r = 1; r < 10; r++) {
    aesRound(state, rks[r]!, next);
    state.set(next, 0);
  }
  aesSubBytesShiftRows(state, rks[10]!, out);
}

export function aes256KeySchedule(key: Uint8Array): Uint8Array[] {
  const rks: Uint8Array[] = new Array(15);
  const words = new Uint32Array(60);
  for (let i = 0; i < 8; i++) {
    words[i] = (key[4 * i]! | (key[4 * i + 1]! << 8) | (key[4 * i + 2]! << 16) | (key[4 * i + 3]! << 24)) >>> 0;
  }

  for (let i = 8; i < 60; i++) {
    let temp = words[i - 1]!;
    if (i % 8 === 0) {
      const rot = (temp >>> 8) | (temp << 24);
      const b0 = AES_SBOX[rot & 0xff]!;
      const b1 = AES_SBOX[(rot >>> 8) & 0xff]!;
      const b2 = AES_SBOX[(rot >>> 16) & 0xff]!;
      const b3 = AES_SBOX[(rot >>> 24) & 0xff]!;
      const sub = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
      const rconWord = RCON[(i / 8) - 1]!;
      temp = (sub ^ rconWord) >>> 0;
    } else if (i % 8 === 4) {
      const b0 = AES_SBOX[temp & 0xff]!;
      const b1 = AES_SBOX[(temp >>> 8) & 0xff]!;
      const b2 = AES_SBOX[(temp >>> 16) & 0xff]!;
      const b3 = AES_SBOX[(temp >>> 24) & 0xff]!;
      temp = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
    }
    words[i] = (words[i - 8]! ^ temp) >>> 0;
  }

  for (let r = 0; r <= 14; r++) {
    const rk = new Uint8Array(16);
    for (let c = 0; c < 4; c++) {
      const w = words[r * 4 + c]!;
      rk[4 * c + 0] = w & 0xff;
      rk[4 * c + 1] = (w >>> 8) & 0xff;
      rk[4 * c + 2] = (w >>> 16) & 0xff;
      rk[4 * c + 3] = (w >>> 24) & 0xff;
    }
    rks[r] = rk;
  }
  return rks;
}

export function aes256EncryptBlock(rks: Uint8Array[], input: Uint8Array, out: Uint8Array): void {
  const state = new Uint8Array(16);
  for (let i = 0; i < 16; i++) state[i] = input[i]! ^ rks[0]![i]!;

  const next = new Uint8Array(16);
  for (let r = 1; r < 14; r++) {
    aesRound(state, rks[r]!, next);
    state.set(next, 0);
  }
  aesSubBytesShiftRows(state, rks[14]!, out);
}

function invShiftRowsSubBytes(state: Uint8Array): void {
  const tmp = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    tmp[4 * c + 0] = AES_INV_SBOX[state[4 * c + 0]!]!;
    tmp[4 * c + 1] = AES_INV_SBOX[state[4 * ((c + 3) & 3) + 1]!]!;
    tmp[4 * c + 2] = AES_INV_SBOX[state[4 * ((c + 2) & 3) + 2]!]!;
    tmp[4 * c + 3] = AES_INV_SBOX[state[4 * ((c + 1) & 3) + 3]!]!;
  }
  state.set(tmp, 0);
}

function invMixColumns(state: Uint8Array): void {
  const tmp = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    const s0 = state[4 * c + 0]!;
    const s1 = state[4 * c + 1]!;
    const s2 = state[4 * c + 2]!;
    const s3 = state[4 * c + 3]!;

    tmp[4 * c + 0] = mul(s0, 0x0e) ^ mul(s1, 0x0b) ^ mul(s2, 0x0d) ^ mul(s3, 0x09);
    tmp[4 * c + 1] = mul(s0, 0x09) ^ mul(s1, 0x0e) ^ mul(s2, 0x0b) ^ mul(s3, 0x0d);
    tmp[4 * c + 2] = mul(s0, 0x0d) ^ mul(s1, 0x09) ^ mul(s2, 0x0e) ^ mul(s3, 0x0b);
    tmp[4 * c + 3] = mul(s0, 0x0b) ^ mul(s1, 0x0d) ^ mul(s2, 0x09) ^ mul(s3, 0x0e);
  }
  state.set(tmp, 0);
}

export function aes256DecryptBlock(rks: Uint8Array[], input: Uint8Array, out: Uint8Array): void {
  const state = new Uint8Array(16);
  for (let i = 0; i < 16; i++) state[i] = input[i]! ^ rks[14]![i]!;

  for (let r = 13; r >= 1; r--) {
    invShiftRowsSubBytes(state);
    const rk = rks[r]!;
    for (let i = 0; i < 16; i++) state[i] = state[i]! ^ rk[i]!;
    invMixColumns(state);
  }

  invShiftRowsSubBytes(state);
  const rk0 = rks[0]!;
  for (let i = 0; i < 16; i++) {
    out[i] = state[i]! ^ rk0[i]!;
  }
}

export function aes128BlockEncrypt(key: Uint8Array, block: Uint8Array): Uint8Array {
  const rks = aes128KeySchedule(key);
  const out = new Uint8Array(16);
  aes128EncryptBlock(rks, block, out);
  return out;
}

export function aes256BlockEncrypt(key: Uint8Array, block: Uint8Array): Uint8Array {
  const rks = aes256KeySchedule(key);
  const out = new Uint8Array(16);
  aes256EncryptBlock(rks, block, out);
  return out;
}
