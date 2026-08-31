/**
 * Base58Check Encoding and Decoding.
 * Extends Base58 with an optional version prefix byte and a 4-byte double SHA-256 checksum,
 * standard for Bitcoin addresses (P2PKH, P2SH) and private keys (WIF).
 */

import { sha256 } from "@noble/hashes/sha2.js";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58RawEncode(data: Uint8Array): string {
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
    const rem = Number(num % 58n);
    result = BASE58_ALPHABET[rem] + result;
    num /= 58n;
  }

  return "1".repeat(leadingZeros) + (result || (leadingZeros === 0 ? "1" : ""));
}

function base58RawDecode(str: string): Uint8Array {
  let leadingZeros = 0;
  while (leadingZeros < str.length && str[leadingZeros] === "1") {
    leadingZeros++;
  }

  let num = 0n;
  for (let i = 0; i < str.length; i++) {
    const idx = BASE58_ALPHABET.indexOf(str[i]!);
    if (idx === -1) throw new Error(`Invalid Base58 character: "${str[i]}"`);
    num = num * 58n + BigInt(idx);
  }

  const hex = num.toString(16);
  const paddedHex = hex.length % 2 === 0 ? hex : "0" + hex;
  const bytes: number[] = [];
  for (let i = 0; i < leadingZeros; i++) bytes.push(0);
  if (num > 0n) {
    for (let i = 0; i < paddedHex.length; i += 2) {
      bytes.push(parseInt(paddedHex.slice(i, i + 2), 16));
    }
  }

  return new Uint8Array(bytes);
}

export function encodeBase58Check(payload: Uint8Array, versionByte?: number): string {
  const withVersion = versionByte !== undefined ? new Uint8Array([versionByte, ...payload]) : payload;
  const hash = sha256(sha256(withVersion));
  const checksum = hash.slice(0, 4);

  const full = new Uint8Array(withVersion.length + 4);
  full.set(withVersion, 0);
  full.set(checksum, withVersion.length);

  return base58RawEncode(full);
}

export function decodeBase58Check(str: string): { payload: Uint8Array; versionByte?: number } {
  const full = base58RawDecode(str.trim());
  if (full.length < 4) {
    throw new Error("Invalid Base58Check data length.");
  }

  const data = full.slice(0, -4);
  const checksum = full.slice(-4);

  const hash = sha256(sha256(data));
  const expectedChecksum = hash.slice(0, 4);

  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expectedChecksum[i]) {
      throw new Error("Invalid Base58Check checksum.");
    }
  }

  return {
    payload: data.length > 1 ? data.slice(1) : data,
    versionByte: data.length > 0 ? data[0] : undefined,
  };
}
