/**
 * Spritz -- A spongy RC4-like stream cipher and cryptographic sponge by Ron Rivest and Jacob Schuldt.
 */

export class SpritzCipher {
  s: Uint8Array = new Uint8Array(256);
  i: number = 0;
  j: number = 0;
  k: number = 0;
  z: number = 0;
  a: number = 0;
  w: number = 1;

  constructor() {
    this.init();
  }

  init(): void {
    for (let v = 0; v < 256; v++) this.s[v] = v;
    this.i = 0;
    this.j = 0;
    this.k = 0;
    this.z = 0;
    this.a = 0;
    this.w = 1;
  }

  update(): void {
    this.i = (this.i + this.w) & 0xff;
    this.j = (this.k + this.s[(this.j + this.s[this.i]!) & 0xff]!) & 0xff;
    this.k = (this.i + this.k + this.s[this.j]!) & 0xff;
    // swap s[i], s[j]
    const temp = this.s[this.i]!;
    this.s[this.i] = this.s[this.j]!;
    this.s[this.j] = temp;
  }

  output(): number {
    const y1 = (this.z + this.k) & 0xff;
    const y2 = (this.i + this.s[y1]!) & 0xff;
    const y3 = (this.j + this.s[y2]!) & 0xff;
    this.z = this.s[y3]!;
    return this.z;
  }

  drip(): number {
    if (this.a > 0) this.shuffle();
    this.update();
    return this.output();
  }

  absorb(data: Uint8Array): void {
    for (let idx = 0; idx < data.length; idx++) {
      this.absorbByte(data[idx]!);
    }
  }

  absorbByte(b: number): void {
    this.absorbNibble(b & 0x0f);
    this.absorbNibble((b >>> 4) & 0x0f);
  }

  absorbNibble(x: number): void {
    if (this.a === 128) this.shuffle();
    // swap s[a], s[128 + x]
    const temp = this.s[this.a]!;
    this.s[this.a] = this.s[128 + x]!;
    this.s[128 + x] = temp;
    this.a = (this.a + 1) & 0xff;
  }

  absorbStop(): void {
    if (this.a === 128) this.shuffle();
    this.a = (this.a + 1) & 0xff;
  }

  shuffle(): void {
    this.whip(512);
    this.crush();
    this.whip(512);
    this.crush();
    this.whip(512);
    this.a = 0;
  }

  whip(r: number): void {
    for (let v = 0; v < r; v++) this.update();
    this.w = (this.w + 2) & 0xff;
  }

  crush(): void {
    for (let v = 0; v < 128; v++) {
      if (this.s[v]! > this.s[255 - v]!) {
        const temp = this.s[v]!;
        this.s[v] = this.s[255 - v]!;
        this.s[255 - v] = temp;
      }
    }
  }

  key(k: Uint8Array): void {
    this.init();
    this.absorb(k);
  }

  crypt(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length);
    for (let v = 0; v < data.length; v++) {
      out[v] = data[v]! ^ this.drip();
    }
    return out;
  }
}

export function spritzEncrypt(key: Uint8Array, data: Uint8Array, iv?: Uint8Array): Uint8Array {
  const spritz = new SpritzCipher();
  spritz.key(key);
  if (iv && iv.length > 0) {
    spritz.absorbStop();
    spritz.absorb(iv);
  }
  return spritz.crypt(data);
}

export function spritzCrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  return spritzEncrypt(key, data, iv);
}


