/**
 * Base36 Encoding and Decoding.
 * Uses 36 case-insensitive alphanumeric characters [0-9A-Z].
 */

const BASE36_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

export function encodeBase36(data: Uint8Array): string {
  if (data.length === 0) return "";

  let leadingZeros = 0;
  while (leadingZeros < data.length && data[leadingZeros] === 0) {
    leadingZeros++;
  }

  let num = 0n;
  for (let i = 0; i < data.length; i++) {
    num = (num << 8n) | BigInt(data[i]!);
  }

  let result = "";
  while (num > 0n) {
    const rem = Number(num % 36n);
    result = BASE36_ALPHABET[rem] + result;
    num /= 36n;
  }

  return "0".repeat(leadingZeros) + (result || (leadingZeros === 0 ? "0" : ""));
}

export function decodeBase36(str: string): Uint8Array {
  const clean = str.trim().toUpperCase();
  if (clean.length === 0) return new Uint8Array(0);

  let leadingZeros = 0;
  while (leadingZeros < clean.length && clean[leadingZeros] === "0") {
    leadingZeros++;
  }

  let num = 0n;
  for (let i = 0; i < clean.length; i++) {
    const idx = BASE36_ALPHABET.indexOf(clean[i]!);
    if (idx === -1) {
      throw new Error(`Invalid Base36 character: "${clean[i]}"`);
    }
    num = num * 36n + BigInt(idx);
  }

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
