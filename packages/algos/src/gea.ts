/**
 * GEA-1 and GEA-2 -- GPRS Encryption Algorithms used in GSM/GPRS cellular mobile data.
 */

export class GeaCipher {
  r1: number = 0; // 31 bits
  r2: number = 0; // 32 bits
  r3: number = 0; // 33 bits (BigInt / number)

  init(key64: Uint8Array, iv32: Uint8Array): void {
    const k0 = (key64[0]! | (key64[1]! << 8) | (key64[2]! << 16) | (key64[3]! << 24)) >>> 0;
    const k1 = (key64[4]! | (key64[5]! << 8) | (key64[6]! << 16) | (key64[7]! << 24)) >>> 0;
    const iv = (iv32[0]! | (iv32[1]! << 8) | (iv32[2]! << 16) | (iv32[3]! << 24)) >>> 0;

    this.r1 = (k0 ^ iv) & 0x7fffffff;
    this.r2 = (k1 ^ iv) >>> 0;
    this.r3 = (k0 ^ k1) >>> 0;
  }

  clock(): number {
    // Clock R1
    const fb1 = ((this.r1 >>> 30) ^ (this.r1 >>> 27)) & 1;
    this.r1 = (((this.r1 << 1) | fb1) & 0x7fffffff) >>> 0;

    // Clock R2
    const fb2 = ((this.r2 >>> 31) ^ (this.r2 >>> 28) ^ (this.r2 >>> 26) ^ (this.r2 >>> 1)) & 1;
    this.r2 = (((this.r2 << 1) | fb2) >>> 0);

    // Clock R3
    const fb3 = ((this.r3 >>> 31) ^ (this.r3 >>> 30) ^ (this.r3 >>> 28)) & 1;
    this.r3 = (((this.r3 << 1) | fb3) >>> 0);

    const o1 = (this.r1 >>> 30) & 1;
    const o2 = (this.r2 >>> 31) & 1;
    const o3 = (this.r3 >>> 31) & 1;

    // Majority combination
    return (o1 ^ o2 ^ o3 ^ ((o1 & o2) | (o2 & o3) | (o1 & o3))) & 1;
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

export function geaEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const gea = new GeaCipher();
  gea.init(key, iv);
  return gea.crypt(data);
}

export function geaCrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  return geaEncrypt(key, iv, data);
}

