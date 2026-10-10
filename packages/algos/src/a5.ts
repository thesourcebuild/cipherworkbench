/**
 * GSM A5/1 and A5/2 Mobile Cellular Stream Ciphers.
 * A5/1 uses 3 LFSRs with majority-rule clocking.
 * A5/2 uses 4 LFSRs designed for lower-strength export compliance.
 */

function parity(v: number): number {
  v ^= v >>> 16;
  v ^= v >>> 8;
  v ^= v >>> 4;
  v ^= v >>> 2;
  v ^= v >>> 1;
  return v & 1;
}

function majority(a: number, b: number, c: number): number {
  return (a & b) | (a & c) | (b & c);
}

export interface A51Generator {
  /** Returns the next bytes of keystream without restarting the GSM frame state. */
  keystream(length: number): Uint8Array;
}

export function createA51(key: Uint8Array, count: number): A51Generator {
  if (key.length !== 8) {
    throw new Error(`A5/1 requires a 64-bit (8-byte) key, got ${key.length} bytes.`);
  }

  let r1 = 0; // 19 bits
  let r2 = 0; // 22 bits
  let r3 = 0; // 23 bits

  const clockR1 = (): void => {
    r1 = ((r1 << 1) | parity(r1 & 0x072000)) & 0x7ffff;
  };
  const clockR2 = (): void => {
    r2 = ((r2 << 1) | parity(r2 & 0x300000)) & 0x3fffff;
  };
  const clockR3 = (): void => {
    r3 = ((r3 << 1) | parity(r3 & 0x700080)) & 0x7fffff;
  };
  const clockAll = (): void => {
    clockR1();
    clockR2();
    clockR3();
  };
  const clockMajority = (): void => {
    const r1Clock = (r1 >>> 8) & 1;
    const r2Clock = (r2 >>> 10) & 1;
    const r3Clock = (r3 >>> 10) & 1;
    const m = majority(r1Clock, r2Clock, r3Clock);
    if (r1Clock === m) clockR1();
    if (r2Clock === m) clockR2();
    if (r3Clock === m) clockR3();
  };

  // Kc and COUNT are both loaded least-significant bit first.
  for (let i = 0; i < 64; i++) {
    const bit = (key[i >>> 3]! >>> (i & 7)) & 1;
    clockAll();
    r1 ^= bit;
    r2 ^= bit;
    r3 ^= bit;
  }

  // COUNT is a 22-bit value and is loaded least-significant bit first.
  for (let i = 0; i < 22; i++) {
    const bit = (count >>> i) & 1;
    clockAll();
    r1 ^= bit;
    r2 ^= bit;
    r3 ^= bit;
  }

  for (let i = 0; i < 100; i++) clockMajority();

  return {
    keystream(length: number): Uint8Array {
      const out = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        let byte = 0;
        for (let b = 0; b < 8; b++) {
          clockMajority();
          const outBit = ((r1 >>> 18) ^ (r2 >>> 21) ^ (r3 >>> 22)) & 1;
          byte |= outBit << (7 - b);
        }
        out[i] = byte;
      }
      return out;
    },
  };
}

export function a51Crypt(key: Uint8Array, count: number, length: number): Uint8Array {
  return createA51(key, count).keystream(length);
}

export function a51Encrypt(key: Uint8Array, count: number, data: Uint8Array): Uint8Array {
  const stream = a51Crypt(key, count, data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i]! ^ stream[i]!;
  }
  return out;
}
