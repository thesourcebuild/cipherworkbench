/**
 * NIST SP 800-56A / SP 800-56C One-Step Key Derivation Function (Concatenation KDF):
 * Derives cryptographic keying material using Hash or HMAC over Counter || Secret || OtherInfo.
 */

import { sha256 } from "@noble/hashes/sha2.js";

export interface OneStepKdfOptions {
  otherInfo?: Uint8Array;
  hash?: (data: Uint8Array) => Uint8Array;
}

export function oneStepKdf(
  sharedSecret: Uint8Array,
  keyLengthBytes: number,
  options: OneStepKdfOptions = {},
): Uint8Array {
  const hashFn = options.hash ?? sha256;
  const otherInfo = options.otherInfo ?? new Uint8Array(0);

  const hashLen = hashFn(new Uint8Array(0)).length;
  const reps = Math.ceil(keyLengthBytes / hashLen);
  const derived = new Uint8Array(reps * hashLen);

  for (let counter = 1; counter <= reps; counter++) {
    const cBlock = new Uint8Array(4);
    new DataView(cBlock.buffer).setUint32(0, counter, false);

    const input = new Uint8Array(4 + sharedSecret.length + otherInfo.length);
    input.set(cBlock, 0);
    input.set(sharedSecret, 4);
    input.set(otherInfo, 4 + sharedSecret.length);

    const blockHash = hashFn(input);
    derived.set(blockHash, (counter - 1) * hashLen);
  }

  return derived.slice(0, keyLengthBytes);
}
