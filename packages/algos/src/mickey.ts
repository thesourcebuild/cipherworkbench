/**
 * MICKEY 2.0 (Mutual Irregular Clocking KEYstream Generator):
 * eSTREAM Profile 2 (hardware) stream cipher by Babbage and Dodd.
 * Uses an 80-bit key and variable IV (up to 80 bits).
 */

export class Mickey2Stream {
  private r = new Uint32Array(4); // 100-bit linear register
  private s = new Uint32Array(4); // 100-bit non-linear register

  constructor(key: Uint8Array, iv: Uint8Array = new Uint8Array(0)) {
    this.init(key, iv);
  }

  private clockR(inputBit: number, controlBit: number): void {
    const feedback = (this.r[0]! & 1) ^ inputBit;
    let carry = 0;
    for (let i = 3; i >= 0; i--) {
      const nextCarry = (this.r[i]! & 1) << 31;
      this.r[i] = (this.r[i]! >>> 1) | carry;
      carry = nextCarry;
    }
    if (feedback) {
      this.r[3]! ^= 0x12000000;
      this.r[0]! ^= 0x00000021;
    }
    if (controlBit) {
      this.r[1]! ^= 0x00400000;
    }
  }

  private clockS(inputBit: number, controlBit: number): void {
    const feedback = ((this.s[0]! & 1) ^ inputBit) & 1;
    let carry = 0;
    for (let i = 3; i >= 0; i--) {
      const nextCarry = (this.s[i]! & 1) << 31;
      this.s[i] = (this.s[i]! >>> 1) | carry;
      carry = nextCarry;
    }
    if (feedback) {
      this.s[3]! ^= 0x08000000;
      this.s[0]! ^= 0x00000013;
    }
    if (controlBit) {
      this.s[2]! ^= (this.s[1]! & 0x00100000) ? 0x00020000 : 0x00040000;
    }
  }

  private clock(inputBit = 0): number {
    const controlR = ((this.s[1]! >>> 17) ^ (this.r[2]! >>> 25)) & 1;
    const controlS = ((this.s[2]! >>> 21) ^ (this.r[1]! >>> 19)) & 1;
    const outBit = (this.r[0]! ^ this.s[0]!) & 1;

    this.clockR(inputBit, controlR);
    this.clockS(inputBit, controlS);
    return outBit;
  }

  private init(key: Uint8Array, iv: Uint8Array): void {
    this.r.fill(0);
    this.s.fill(0);

    // Key loading
    for (let i = 0; i < Math.min(10, key.length); i++) {
      const b = key[i]!;
      for (let bit = 7; bit >= 0; bit--) {
        this.clock((b >>> bit) & 1);
      }
    }

    // IV loading
    for (let i = 0; i < Math.min(10, iv.length); i++) {
      const b = iv[i]!;
      for (let bit = 7; bit >= 0; bit--) {
        this.clock((b >>> bit) & 1);
      }
    }

    // Pre-clocking mixing
    for (let i = 0; i < 100; i++) {
      this.clock(0);
    }
  }

  nextByte(): number {
    let b = 0;
    for (let i = 7; i >= 0; i--) {
      b |= this.clock(0) << i;
    }
    return b;
  }

  process(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      out[i] = data[i]! ^ this.nextByte();
    }
    return out;
  }
}

export function mickeyEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const stream = new Mickey2Stream(key, iv);
  return stream.process(data);
}

export function mickeyDecrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  return mickeyEncrypt(key, iv, data);
}
