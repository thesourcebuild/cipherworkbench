/**
 * Gray Code (Reflected Binary Code) Encoding and Decoding.
 * Binary encoding where adjacent values differ by exactly one bit.
 */

export function binaryToGray(n: bigint): bigint {
  return n ^ (n >> 1n);
}

export function grayToBinary(g: bigint): bigint {
  let b = g;
  while (g > 0n) {
    g >>= 1n;
    b ^= g;
  }
  return b;
}

export function encodeGrayBytes(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    const b = BigInt(input[i]!);
    out[i] = Number(binaryToGray(b) & 0xffn);
  }
  return out;
}

export function decodeGrayBytes(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    const g = BigInt(input[i]!);
    out[i] = Number(grayToBinary(g) & 0xffn);
  }
  return out;
}
