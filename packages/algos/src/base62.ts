/**
 * Base62 Encoding and Decoding.
 * Uses the 62 alphanumeric characters [0-9A-Za-z] with no punctuation,
 * widely used in URL shorteners, distributed ID systems, and tokens.
 */

const BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

export function encodeBase62(data: Uint8Array): string {
  if (data.length === 0) return "";

  // Count leading zeros
  let leadingZeros = 0;
  while (leadingZeros < data.length && data[leadingZeros] === 0) {
    leadingZeros++;
  }

  // Convert bytes to BigInt
  let num = 0n;
  for (let i = 0; i < data.length; i++) {
    num = (num << 8n) | BigInt(data[i]!);
  }

  // Convert BigInt to Base62 digits
  let result = "";
  while (num > 0n) {
    const rem = Number(num % 62n);
    result = BASE62_ALPHABET[rem] + result;
    num /= 62n;
  }

  return "0".repeat(leadingZeros) + (result || (leadingZeros === 0 ? "0" : ""));
}

export function decodeBase62(str: string): Uint8Array {
  const clean = str.trim();
  if (clean.length === 0) return new Uint8Array(0);

  // Count leading zeros
  let leadingZeros = 0;
  while (leadingZeros < clean.length && clean[leadingZeros] === "0") {
    leadingZeros++;
  }

  let num = 0n;
  for (let i = 0; i < clean.length; i++) {
    const idx = BASE62_ALPHABET.indexOf(clean[i]!);
    if (idx === -1) {
      throw new Error(`Invalid Base62 character: "${clean[i]}"`);
    }
    num = num * 62n + BigInt(idx);
  }

  // Convert BigInt to byte array
  const hex = num.toString(16);
  const paddedHex = hex.length % 2 === 0 ? hex : "0" + hex;
  const bytes: number[] = [];
  for (let i = 0; i < leadingZeros; i++) {
    bytes.push(0);
  }
  if (num > 0n) {
    for (let i = 0; i < paddedHex.length; i += 2) {
      bytes.push(parseInt(paddedHex.slice(i, i + 2), 16));
    }
  }

  return new Uint8Array(bytes);
}
