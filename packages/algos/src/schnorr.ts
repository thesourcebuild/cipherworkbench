/**
 * BIP-340 Schnorr Signatures over secp256k1 (Bitcoin Taproot Standard).
 *
 * Implements:
 * - 32-byte x-only public keys.
 * - 64-byte signatures (r || s).
 * - Exact BIP-340 verification and signing with auxiliary randomness.
 */

import { schnorr } from "@noble/curves/secp256k1.js";

export function schnorrGetPublicKey(privateKey: Uint8Array): Uint8Array {
  return schnorr.getPublicKey(privateKey);
}

export function schnorrSign(
  message: Uint8Array,
  privateKey: Uint8Array,
  auxRand?: Uint8Array,
): Uint8Array {
  return schnorr.sign(message, privateKey, auxRand);
}

export function schnorrVerify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return schnorr.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
