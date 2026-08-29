/**
 * DECT Standard Cipher (DSC and DSC-2) -- Stream ciphers for cordless telephony (ETSI EN 300 175-7).
 */

export class DscCipher {
  lfsrA: number = 0; // 17 bits
  lfsrB: number = 0; // 14 bits

  init(key64: Uint8Array, iv35: Uint8Array): void {
    let k = 0n;
    for (let i = 0; i < Math.min(8, key64.length); i++) {
      k |= BigInt(key64[i]!) << BigInt(8 * i);
    }
    let iv = 0n;
    for (let i = 0; i < Math.min(5, iv35.length); i++) {
      iv |= BigInt(iv35[i]!) << BigInt(8 * i);
    }

    this.lfsrA = Number((k ^ iv) & 0x1ffffn);
    this.lfsrB = Number(((k >> 17n) ^ (iv >> 17n)) & 0x3fffn);
  }

  clock(): number {
    // Clock LFSR A (polynomial x^17 + x^14 + 1)
    const fbA = ((this.lfsrA >>> 16) ^ (this.lfsrA >>> 13)) & 1;
    this.lfsrA = ((this.lfsrA << 1) | fbA) & 0x1ffff;

    // Clock LFSR B (polynomial x^14 + x^13 + x^12 + x^2 + 1)
    const fbB =
      ((this.lfsrB >>> 13) ^ (this.lfsrB >>> 12) ^ (this.lfsrB >>> 11) ^ (this.lfsrB >>> 1)) & 1;
    this.lfsrB = ((this.lfsrB << 1) | fbB) & 0x3fff;

    // Non-linear combination
    const aOut = (this.lfsrA >>> 16) & 1;
    const bOut = (this.lfsrB >>> 13) & 1;
    const midA = (this.lfsrA >>> 8) & 1;
    const midB = (this.lfsrB >>> 6) & 1;

    return (aOut ^ bOut ^ (midA & midB)) & 1;
  }

  nextByte(): number {
    let b = 0;
    for (let i = 0; i < 8; i++) {
      b |= this.clock() << i;
    }
    return b;
  }

  crypt(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      out[i] = data[i]! ^ this.nextByte();
    }
    return out;
  }
}

export function dectDscEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const dsc = new DscCipher();
  dsc.init(key, iv);
  return dsc.crypt(data);
}

export function dectDscCrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  return dectDscEncrypt(key, iv, data);
}

