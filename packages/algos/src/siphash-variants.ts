/**
 * SipHash Variants & HalfSipHash.
 * SipHash-c-d parameterizations (e.g., SipHash-1-3, SipHash-4-8) and
 * 32-bit architecture HalfSipHash-c-d.
 */

function rotl64(n: bigint, b: bigint): bigint {
  return ((n << b) | (n >> (64n - b))) & 0xffffffffffffffffn;
}

function sipRound64(v: [bigint, bigint, bigint, bigint]): void {
  v[0] = (v[0] + v[1]) & 0xffffffffffffffffn;
  v[1] = rotl64(v[1], 13n) ^ v[0];
  v[0] = rotl64(v[0], 32n);

  v[2] = (v[2] + v[3]) & 0xffffffffffffffffn;
  v[3] = rotl64(v[3], 16n) ^ v[2];

  v[0] = (v[0] + v[3]) & 0xffffffffffffffffn;
  v[3] = rotl64(v[3], 21n) ^ v[0];

  v[2] = (v[2] + v[1]) & 0xffffffffffffffffn;
  v[1] = rotl64(v[1], 17n) ^ v[2];
  v[2] = rotl64(v[2], 32n);
}

export function siphashGeneric(key: Uint8Array, data: Uint8Array, cRounds: number, dRounds: number): Uint8Array {
  if (key.length !== 16) throw new Error("SipHash requires a 16-byte key.");

  let k0 = 0n;
  let k1 = 0n;
  for (let i = 0; i < 8; i++) k0 |= BigInt(key[i]!) << BigInt(8 * i);
  for (let i = 0; i < 8; i++) k1 |= BigInt(key[8 + i]!) << BigInt(8 * i);

  const v: [bigint, bigint, bigint, bigint] = [
    k0 ^ 0x736f6d6570736575n,
    k1 ^ 0x646f72616e646f6dn,
    k0 ^ 0x6c7967656e657261n,
    k1 ^ 0x7465646279746573n,
  ];

  const fullWords = Math.floor(data.length / 8);
  for (let i = 0; i < fullWords; i++) {
    let m = 0n;
    for (let b = 0; b < 8; b++) m |= BigInt(data[i * 8 + b]!) << BigInt(8 * b);
    v[3] ^= m;
    for (let r = 0; r < cRounds; r++) sipRound64(v);
    v[0] ^= m;
  }

  let last = BigInt(data.length & 0xff) << 56n;
  const left = data.length % 8;
  const offset = fullWords * 8;
  for (let i = 0; i < left; i++) {
    last |= BigInt(data[offset + i]!) << BigInt(8 * i);
  }

  v[3] ^= last;
  for (let r = 0; r < cRounds; r++) sipRound64(v);
  v[0] ^= last;

  v[2] ^= 0xffn;
  for (let r = 0; r < dRounds; r++) sipRound64(v);

  const outVal = v[0] ^ v[1] ^ v[2] ^ v[3];
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) out[i] = Number((outVal >> BigInt(8 * i)) & 0xffn);
  return out;
}

export function siphash13(key: Uint8Array, data: Uint8Array): Uint8Array {
  return siphashGeneric(key, data, 1, 3);
}

export function siphash48(key: Uint8Array, data: Uint8Array): Uint8Array {
  return siphashGeneric(key, data, 4, 8);
}

function rotl32(n: number, b: number): number {
  return ((n << b) | (n >>> (32 - b))) >>> 0;
}

function halfSipRound(v: [number, number, number, number]): void {
  v[0] = (v[0] + v[1]) >>> 0;
  v[1] = rotl32(v[1], 5) ^ v[0];
  v[0] = rotl32(v[0], 16);

  v[2] = (v[2] + v[3]) >>> 0;
  v[3] = rotl32(v[3], 8) ^ v[2];

  v[0] = (v[0] + v[3]) >>> 0;
  v[3] = rotl32(v[3], 7) ^ v[0];

  v[2] = (v[2] + v[1]) >>> 0;
  v[1] = rotl32(v[1], 13) ^ v[2];
  v[2] = rotl32(v[2], 16);
}

export function halfSipHash24(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (key.length !== 8) throw new Error("HalfSipHash requires an 8-byte key.");

  let k0 = 0;
  let k1 = 0;
  for (let i = 0; i < 4; i++) k0 |= key[i]! << (8 * i);
  for (let i = 0; i < 4; i++) k1 |= key[4 + i]! << (8 * i);

  const v: [number, number, number, number] = [
    (0 ^ k0) >>> 0,
    (0 ^ k1) >>> 0,
    (0x6c796765 ^ k0) >>> 0,
    (0x74656462 ^ k1) >>> 0,
  ];

  const fullWords = Math.floor(data.length / 4);
  for (let i = 0; i < fullWords; i++) {
    let m = 0;
    for (let b = 0; b < 4; b++) m |= data[i * 4 + b]! << (8 * b);
    v[3] = (v[3] ^ m) >>> 0;
    halfSipRound(v);
    halfSipRound(v);
    v[0] = (v[0] ^ m) >>> 0;
  }

  let last = (data.length & 0xff) << 24;
  const left = data.length % 4;
  const offset = fullWords * 4;
  for (let i = 0; i < left; i++) {
    last |= data[offset + i]! << (8 * i);
  }

  v[3] = (v[3] ^ last) >>> 0;
  halfSipRound(v);
  halfSipRound(v);
  v[0] = (v[0] ^ last) >>> 0;

  v[2] = (v[2] ^ 0xff) >>> 0;
  halfSipRound(v);
  halfSipRound(v);
  halfSipRound(v);
  halfSipRound(v);

  const outVal = (v[1] ^ v[3]) >>> 0;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) out[i] = (outVal >>> (8 * i)) & 0xff;
  return out;
}
