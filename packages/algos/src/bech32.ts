/**
 * Bech32 and Bech32m (BIP-173 / BIP-350).
 * Checksummed Base32 format designed for Bitcoin SegWit and Taproot addresses,
 * using a BCH error-detecting polynomial code over GF(32).
 */

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;

const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3] as const;

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >>> i) & 1) {
        chk ^= GEN[i]!;
      }
    }
  }
  return chk;
}

function hrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) {
    ret.push(hrp.charCodeAt(i) >>> 5);
  }
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) {
    ret.push(hrp.charCodeAt(i) & 31);
  }
  return ret;
}

export function convertBits(data: Uint8Array | number[], fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) {
      throw new Error("Invalid bit value.");
    }
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) {
      ret.push((acc << (toBits - bits)) & maxv);
    }
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error("Invalid padding.");
  }
  return ret;
}

export function encodeBech32(hrp: string, data: Uint8Array, spec: "bech32" | "bech32m" = "bech32"): string {
  const hrpLower = hrp.toLowerCase();
  const data5Bit = convertBits(data, 8, 5, true);
  const constant = spec === "bech32m" ? BECH32M_CONST : BECH32_CONST;

  const values = hrpExpand(hrpLower).concat(data5Bit).concat([0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ constant;

  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) {
    checksum.push((mod >>> (5 * (5 - i))) & 31);
  }

  let combined = hrpLower + "1";
  for (const d of data5Bit.concat(checksum)) {
    combined += BECH32_CHARSET[d]!;
  }
  return combined;
}

export function decodeBech32(str: string): { hrp: string; data: Uint8Array; spec: "bech32" | "bech32m" } {
  const clean = str.trim().toLowerCase();
  const sepIdx = clean.lastIndexOf("1");
  if (sepIdx < 1 || sepIdx + 7 > clean.length || clean.length > 90) {
    throw new Error("Invalid Bech32 format.");
  }

  const hrp = clean.slice(0, sepIdx);
  const dataChars = clean.slice(sepIdx + 1);
  const data5Bit: number[] = [];

  for (let i = 0; i < dataChars.length; i++) {
    const idx = BECH32_CHARSET.indexOf(dataChars[i]!);
    if (idx === -1) throw new Error(`Invalid Bech32 character: "${dataChars[i]}"`);
    data5Bit.push(idx);
  }

  const values = hrpExpand(hrp).concat(data5Bit);
  const mod = polymod(values);

  let spec: "bech32" | "bech32m";
  if (mod === BECH32_CONST) spec = "bech32";
  else if (mod === BECH32M_CONST) spec = "bech32m";
  else throw new Error("Invalid Bech32 checksum.");

  const payload5Bit = data5Bit.slice(0, -6);
  const data8Bit = convertBits(payload5Bit, 5, 8, false);

  return { hrp, data: new Uint8Array(data8Bit), spec };
}
