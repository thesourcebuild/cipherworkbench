/**
 * Mifare Crypto-1 -- 48-bit proprietary stream cipher used in Mifare Classic RFID smart cards.
 */

function parity32(x: number): number {
  x ^= x >>> 16;
  x ^= x >>> 8;
  x ^= x >>> 4;
  x ^= x >>> 2;
  x ^= x >>> 1;
  return x & 1;
}

const FA_TABLE = 0x9e98; // 4-variable boolean function
const FB_TABLE = 0xb48e; // 4-variable boolean function
const FC_TABLE = 0xec57e80a; // 5-variable boolean function

function filter(state: bigint): number {
  const getBit = (n: number) => Number((state >> BigInt(n)) & 1n);

  const a0 = (getBit(9) << 3) | (getBit(11) << 2) | (getBit(13) << 1) | getBit(15);
  const a1 = (getBit(17) << 3) | (getBit(19) << 2) | (getBit(21) << 1) | getBit(23);
  const a2 = (getBit(25) << 3) | (getBit(27) << 2) | (getBit(29) << 1) | getBit(31);
  const a3 = (getBit(33) << 3) | (getBit(35) << 2) | (getBit(37) << 1) | getBit(39);
  const a4 = (getBit(41) << 3) | (getBit(43) << 2) | (getBit(45) << 1) | getBit(47);

  const fa0 = (FA_TABLE >>> a0) & 1;
  const fb1 = (FB_TABLE >>> a1) & 1;
  const fb2 = (FB_TABLE >>> a2) & 1;
  const fa3 = (FA_TABLE >>> a3) & 1;
  const fb4 = (FB_TABLE >>> a4) & 1;

  const c = (fa0 << 4) | (fb1 << 3) | (fb2 << 2) | (fa3 << 1) | fb4;
  return (FC_TABLE >>> c) & 1;
}

export class Crypto1State {
  state: bigint = 0n;

  constructor(key48: bigint) {
    this.state = key48 & 0xffffffffffffn;
  }

  clock(inputBit: number = 0, isKeyed: boolean = false): number {
    const outBit = filter(this.state);
    // Feedback polynomial taps
    const taps =
      ((this.state >> 0n) & 1n) ^
      ((this.state >> 5n) & 1n) ^
      ((this.state >> 9n) & 1n) ^
      ((this.state >> 10n) & 1n) ^
      ((this.state >> 12n) & 1n) ^
      ((this.state >> 14n) & 1n) ^
      ((this.state >> 15n) & 1n) ^
      ((this.state >> 17n) & 1n) ^
      ((this.state >> 19n) & 1n) ^
      ((this.state >> 24n) & 1n) ^
      ((this.state >> 25n) & 1n) ^
      ((this.state >> 27n) & 1n) ^
      ((this.state >> 29n) & 1n) ^
      ((this.state >> 35n) & 1n) ^
      ((this.state >> 39n) & 1n) ^
      ((this.state >> 41n) & 1n) ^
      ((this.state >> 42n) & 1n) ^
      ((this.state >> 43n) & 1n);

    const feedback = Number(taps) ^ inputBit ^ (isKeyed ? outBit : 0);
    this.state = ((this.state >> 1n) | (BigInt(feedback & 1) << 47n)) & 0xffffffffffffn;
    return outBit;
  }

  nextByte(): number {
    let byte = 0;
    for (let i = 0; i < 8; i++) {
      byte |= this.clock() << i;
    }
    return byte;
  }
}

export function crypto1Stream(key64: Uint8Array, length: number): Uint8Array {
  let key = 0n;
  for (let i = 0; i < Math.min(6, key64.length); i++) {
    key |= BigInt(key64[i]!) << BigInt(8 * i);
  }
  const c1 = new Crypto1State(key);
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = c1.nextByte();
  }
  return out;
}

export function crypto1Crypt(key64: Uint8Array, data: Uint8Array): Uint8Array {
  const stream = crypto1Stream(key64, data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i]! ^ stream[i]!;
  }
  return out;
}
