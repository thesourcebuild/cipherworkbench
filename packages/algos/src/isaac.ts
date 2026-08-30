/**
 * ISAAC and ISAAC-64 Cryptographic Keystream PRNG (Bob Jenkins, 1996).
 * "Indirection, Shift, Accumulate, Add, and Count".
 */

export class Isaac {
  private mm = new Uint32Array(256);
  private aa = 0;
  private bb = 0;
  private cc = 0;
  private randrsl = new Uint32Array(256);
  private randcnt = 256;

  constructor(seed?: Uint8Array) {
    this.init(seed);
  }

  private init(seed?: Uint8Array): void {
    let a = 0x9e3779b9;
    let b = 0x9e3779b9;
    let c = 0x9e3779b9;
    let d = 0x9e3779b9;
    let e = 0x9e3779b9;
    let f = 0x9e3779b9;
    let g = 0x9e3779b9;
    let h = 0x9e3779b9;

    const mix = () => {
      a ^= b << 11; d = (d + a) >>> 0; b = (b + c) >>> 0;
      b ^= c >>> 2; e = (e + b) >>> 0; c = (c + d) >>> 0;
      c ^= d << 8;  f = (f + c) >>> 0; d = (d + e) >>> 0;
      d ^= e >>> 16; g = (g + d) >>> 0; e = (e + f) >>> 0;
      e ^= f << 10; h = (h + e) >>> 0; f = (f + g) >>> 0;
      f ^= g >>> 4; a = (a + f) >>> 0; g = (g + h) >>> 0;
      g ^= h << 8;  b = (b + g) >>> 0; h = (h + a) >>> 0;
      h ^= a >>> 9; c = (c + h) >>> 0; a = (a + b) >>> 0;
    };

    if (seed) {
      const len = Math.min(seed.length, 1024);
      for (let i = 0; i < len; i++) {
        const wordIdx = Math.floor(i / 4);
        const byteShift = (i % 4) * 8;
        this.randrsl[wordIdx] = ((this.randrsl[wordIdx] ?? 0) | (seed[i]! << byteShift)) >>> 0;
      }
    }

    for (let i = 0; i < 4; i++) mix();

    for (let i = 0; i < 256; i += 8) {
      a = (a + this.randrsl[i]!) >>> 0;
      b = (b + this.randrsl[i + 1]!) >>> 0;
      c = (c + this.randrsl[i + 2]!) >>> 0;
      d = (d + this.randrsl[i + 3]!) >>> 0;
      e = (e + this.randrsl[i + 4]!) >>> 0;
      f = (f + this.randrsl[i + 5]!) >>> 0;
      g = (g + this.randrsl[i + 6]!) >>> 0;
      h = (h + this.randrsl[i + 7]!) >>> 0;
      mix();
      this.mm[i] = a;
      this.mm[i + 1] = b;
      this.mm[i + 2] = c;
      this.mm[i + 3] = d;
      this.mm[i + 4] = e;
      this.mm[i + 5] = f;
      this.mm[i + 6] = g;
      this.mm[i + 7] = h;
    }

    this.isaac();
  }

  private isaac(): void {
    this.cc = (this.cc + 1) >>> 0;
    this.bb = (this.bb + this.cc) >>> 0;

    for (let i = 0; i < 256; i++) {
      const x = this.mm[i]!;
      switch (i % 4) {
        case 0: this.aa = (this.aa ^ (this.aa << 13)) >>> 0; break;
        case 1: this.aa = (this.aa ^ (this.aa >>> 6)) >>> 0; break;
        case 2: this.aa = (this.aa ^ (this.aa << 2)) >>> 0; break;
        case 3: this.aa = (this.aa ^ (this.aa >>> 16)) >>> 0; break;
      }
      this.aa = (this.mm[(i + 128) & 0xff]! + this.aa) >>> 0;
      const y = (this.mm[(x >>> 2) & 0xff]! + this.aa + this.bb) >>> 0;
      this.mm[i] = y;
      this.bb = (this.mm[(y >>> 10) & 0xff]! + x) >>> 0;
      this.randrsl[i] = this.bb;
    }
    this.randcnt = 0;
  }

  public nextUint32(): number {
    if (this.randcnt >= 256) {
      this.isaac();
    }
    return this.randrsl[this.randcnt++]!;
  }

  public crypt(input: Uint8Array): Uint8Array {
    const out = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) {
      if ((i & 3) === 0 && this.randcnt >= 256) {
        this.isaac();
      }
      const word = this.randrsl[Math.floor(i / 4) % 256]!;
      const byte = (word >>> ((i % 4) * 8)) & 0xff;
      out[i] = input[i]! ^ byte;
    }
    return out;
  }
}

export function isaacCrypt(key: Uint8Array, input: Uint8Array): Uint8Array {
  const cipher = new Isaac(key);
  return cipher.crypt(input);
}
