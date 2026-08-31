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

export function a51Crypt(key: Uint8Array, count: number, length: number): Uint8Array {
  // Key: 64 bits (8 bytes), count (Fn): 22 bits
  let r1 = 0; // 19 bits
  let r2 = 0; // 22 bits
  let r3 = 0; // 23 bits

  // 1. Initialize with 64 key bits
  for (let i = 0; i < 64; i++) {
    const byte = key[Math.floor(i / 8)] ?? 0;
    const bit = (byte >>> (i % 8)) & 1;
    r1 = ((r1 << 1) | bit) & 0x7ffff;
    r2 = ((r2 << 1) | bit) & 0x3fffff;
    r3 = ((r3 << 1) | bit) & 0x7fffff;
  }

  // 2. Initialize with 22 frame counter bits
  for (let i = 0; i < 22; i++) {
    const bit = (count >>> i) & 1;
    r1 = ((r1 << 1) | bit) & 0x7ffff;
    r2 = ((r2 << 1) | bit) & 0x3fffff;
    r3 = ((r3 << 1) | bit) & 0x7fffff;
  }

  // 3. Warm up 100 clock cycles with majority stepping
  for (let i = 0; i < 100; i++) {
    const m = majority((r1 >>> 8) & 1, (r2 >>> 10) & 1, (r3 >>> 10) & 1);
    if (((r1 >>> 8) & 1) === m) {
      const fb = parity(r1 & 0x072000); // taps 18, 17, 16, 13
      r1 = ((r1 << 1) | fb) & 0x7ffff;
    }
    if (((r2 >>> 10) & 1) === m) {
      const fb = parity(r2 & 0x300000); // taps 21, 20
      r2 = ((r2 << 1) | fb) & 0x3fffff;
    }
    if (((r3 >>> 10) & 1) === m) {
      const fb = parity(r3 & 0x700080); // taps 22, 21, 20, 7
      r3 = ((r3 << 1) | fb) & 0x7fffff;
    }
  }

  // 4. Generate keystream bytes
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) {
      const m = majority((r1 >>> 8) & 1, (r2 >>> 10) & 1, (r3 >>> 10) & 1);
      if (((r1 >>> 8) & 1) === m) {
        const fb = parity(r1 & 0x072000);
        r1 = ((r1 << 1) | fb) & 0x7ffff;
      }
      if (((r2 >>> 10) & 1) === m) {
        const fb = parity(r2 & 0x300000);
        r2 = ((r2 << 1) | fb) & 0x3fffff;
      }
      if (((r3 >>> 10) & 1) === m) {
        const fb = parity(r3 & 0x700080);
        r3 = ((r3 << 1) | fb) & 0x7fffff;
      }
      const outBit = ((r1 >>> 18) ^ (r2 >>> 21) ^ (r3 >>> 22)) & 1;
      byte = (byte << 1) | outBit;
    }
    out[i] = byte;
  }

  return out;
}

export function a51Encrypt(key: Uint8Array, count: number, data: Uint8Array): Uint8Array {
  const stream = a51Crypt(key, count, data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i]! ^ stream[i]!;
  }
  return out;
}
