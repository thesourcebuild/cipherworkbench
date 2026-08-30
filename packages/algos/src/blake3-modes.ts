/**
 * BLAKE3 Modes: Keyed MAC and Context-Bound Key Derivation.
 *
 * Implements:
 * - BLAKE3 in Keyed MAC mode (using 32-byte secret key).
 * - BLAKE3 in Key Derivation mode (using context string).
 * - Extensible output length (XOF).
 */

import { blake3 } from "@noble/hashes/blake3.js";

export function blake3Mac(
  key: Uint8Array, // exactly 32 bytes
  message: Uint8Array,
  outputLen: number = 32,
): Uint8Array {
  if (key.length !== 32) {
    throw new Error(`BLAKE3 Keyed MAC requires exactly a 32-byte key; received ${key.length} bytes`);
  }
  return blake3(message, { key: key as unknown as Uint8Array<ArrayBuffer>, dkLen: outputLen });
}

export function blake3DeriveKey(
  context: string,
  keyMaterial: Uint8Array,
  outputLen: number = 32,
): Uint8Array {
  const ctxBytes = new TextEncoder().encode(context);
  return blake3(keyMaterial, { context: ctxBytes, dkLen: outputLen });
}
