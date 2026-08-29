/**
 * KeeLoq -- 32-bit block / 64-bit key hopping code cipher used in automotive remote keyless entry.
 */

const NLF_TABLE = 0x3a5c742e;

function nlf(y: number): number {
  const index =
    ((y >>> 31) & 1) |
    (((y >>> 26) & 1) << 1) |
    (((y >>> 20) & 1) << 2) |
    (((y >>> 9) & 1) << 3) |
    (((y >>> 1) & 1) << 4);
  return (NLF_TABLE >>> index) & 1;
}

export function keeloqEncrypt(block: number, key: bigint, rounds: number = 528): number {
  let y = block >>> 0;
  for (let r = 0; r < rounds; r++) {
    const keyBit = Number((key >> BigInt(r % 64)) & 1n);
    const feedback = nlf(y) ^ ((y >>> 16) & 1) ^ (y & 1) ^ keyBit;
    y = ((y >>> 1) | (feedback << 31)) >>> 0;
  }
  return y;
}

export function keeloqDecrypt(block: number, key: bigint, rounds: number = 528): number {
  let y = block >>> 0;
  for (let r = rounds - 1; r >= 0; r--) {
    const keyBit = Number((key >> BigInt(r % 64)) & 1n);
    const msb = (y >>> 31) & 1;
    const yShifted = (y << 1) >>> 0;
    const feedback = nlf(yShifted) ^ ((yShifted >>> 16) & 1) ^ msb ^ keyBit;
    y = (yShifted | feedback) >>> 0;
  }
  return y;
}

export function keeloqEncryptBytes(keyBytes: Uint8Array, blockBytes: Uint8Array): Uint8Array {
  let key = 0n;
  for (let i = 0; i < Math.min(8, keyBytes.length); i++) {
    key |= BigInt(keyBytes[i]!) << BigInt(8 * i);
  }
  let block = 0;
  for (let i = 0; i < Math.min(4, blockBytes.length); i++) {
    block |= blockBytes[i]! << (8 * i);
  }
  const enc = keeloqEncrypt(block, key);
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    out[i] = (enc >>> (8 * i)) & 0xff;
  }
  return out;
}

export function keeloqDecryptBytes(keyBytes: Uint8Array, blockBytes: Uint8Array): Uint8Array {
  let key = 0n;
  for (let i = 0; i < Math.min(8, keyBytes.length); i++) {
    key |= BigInt(keyBytes[i]!) << BigInt(8 * i);
  }
  let block = 0;
  for (let i = 0; i < Math.min(4, blockBytes.length); i++) {
    block |= blockBytes[i]! << (8 * i);
  }
  const dec = keeloqDecrypt(block, key);
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    out[i] = (dec >>> (8 * i)) & 0xff;
  }
  return out;
}

export function createKeeloq(key: Uint8Array): {
  readonly blockSize: number;
  encryptBlock(src: Uint8Array, dst: Uint8Array): void;
  decryptBlock(src: Uint8Array, dst: Uint8Array): void;
} {
  return {
    blockSize: 4,
    encryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const res = keeloqEncryptBytes(key, src);
      dst.set(res, 0);
    },
    decryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const res = keeloqDecryptBytes(key, src);
      dst.set(res, 0);
    },
  };
}

