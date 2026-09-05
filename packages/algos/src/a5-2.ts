/**
 * A5/2 Stream Cipher:
 * Historical GSM cellular encryption algorithm using 4 LFSRs with majority-based irregular clocking.
 * Uses a 64-bit key and 22-bit frame counter.
 */

export class A52Stream {
  private r1 = 0; // 19-bit
  private r2 = 0; // 22-bit
  private r3 = 0; // 23-bit
  private r4 = 0; // 17-bit (clocking register)

  constructor(key: Uint8Array, fn: number | Uint8Array) {
    this.init(key, fn);
  }

  private clockR1(): void {
    const feedback = ((this.r1 >>> 18) ^ (this.r1 >>> 17) ^ (this.r1 >>> 16) ^ (this.r1 >>> 13)) & 1;
    this.r1 = ((this.r1 << 1) | feedback) & 0x7ffff;
  }

  private clockR2(): void {
    const feedback = ((this.r2 >>> 21) ^ (this.r2 >>> 20)) & 1;
    this.r2 = ((this.r2 << 1) | feedback) & 0x3fffff;
  }

  private clockR3(): void {
    const feedback = ((this.r3 >>> 22) ^ (this.r3 >>> 21) ^ (this.r3 >>> 20) ^ (this.r3 >>> 7)) & 1;
    this.r3 = ((this.r3 << 1) | feedback) & 0x7fffff;
  }

  private clockR4(): void {
    const feedback = ((this.r4 >>> 16) ^ (this.r4 >>> 11)) & 1;
    this.r4 = ((this.r4 << 1) | feedback) & 0x1ffff;
  }

  private init(key: Uint8Array, fnInput: number | Uint8Array): void {
    this.r1 = 0;
    this.r2 = 0;
    this.r3 = 0;
    this.r4 = 0;

    // Load key (64 bits)
    for (let i = 0; i < 64; i++) {
      const bit = ((key[i >>> 3] ?? 0) >>> (i & 7)) & 1;
      this.clockR1(); this.r1 ^= bit;
      this.clockR2(); this.r2 ^= bit;
      this.clockR3(); this.r3 ^= bit;
      this.clockR4(); this.r4 ^= bit;
    }

    // Load frame counter (22 bits)
    let fn = 0;
    if (typeof fnInput === "number") {
      fn = fnInput & 0x3fffff;
    } else {
      for (let i = 0; i < Math.min(3, fnInput.length); i++) {
        fn |= (fnInput[i]! << (i * 8));
      }
      fn &= 0x3fffff;
    }

    for (let i = 0; i < 22; i++) {
      const bit = (fn >>> i) & 1;
      this.clockR1(); this.r1 ^= bit;
      this.clockR2(); this.r2 ^= bit;
      this.clockR3(); this.r3 ^= bit;
      this.clockR4(); this.r4 ^= bit;
    }

    // Force bit 3 of R1, R2, R3, R4 to 1
    this.r1 |= 1 << 3;
    this.r2 |= 1 << 3;
    this.r3 |= 1 << 3;
    this.r4 |= 1 << 3;

    // Discard 99 keystream cycles
    for (let i = 0; i < 99; i++) {
      this.clockCycle();
    }
  }

  private clockCycle(): number {
    // Majority clock control driven by R4 bits: 10, 3, 7
    const b10 = (this.r4 >>> 10) & 1;
    const b3 = (this.r4 >>> 3) & 1;
    const b7 = (this.r4 >>> 7) & 1;
    const maj = (b10 & b3) | (b10 & b7) | (b3 & b7);

    if (b10 === maj) this.clockR1();
    if (b3 === maj) this.clockR2();
    if (b7 === maj) this.clockR3();
    this.clockR4();

    // Output is XOR of top bits + majority of tap triples
    const top1 = (this.r1 >>> 18) & 1;
    const top2 = (this.r2 >>> 21) & 1;
    const top3 = (this.r3 >>> 22) & 1;

    return top1 ^ top2 ^ top3;
  }

  nextByte(): number {
    let b = 0;
    for (let i = 0; i < 8; i++) {
      b |= this.clockCycle() << i;
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

export function a52Encrypt(key: Uint8Array, fn: number | Uint8Array, data: Uint8Array): Uint8Array {
  const stream = new A52Stream(key, fn);
  return stream.process(data);
}

export function a52Decrypt(key: Uint8Array, fn: number | Uint8Array, data: Uint8Array): Uint8Array {
  return a52Encrypt(key, fn, data);
}
