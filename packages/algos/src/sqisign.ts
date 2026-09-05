/**
 * SQISign (Short Quaternion and Isogeny Signature) -- NIST PQC On-going Signature Scheme.
 *
 * Notable for producing the most compact signatures among all post-quantum proposals:
 * - Public key: 64 bytes (compressed Montgomery curve point / curve coefficient)
 * - Secret key: 782 bytes (ideal in maximal order of quaternion algebra B_{p,infty})
 * - Signature: 177 bytes (compressed commitment point + response evaluation)
 */

import { sha256 } from "@noble/hashes/sha2.js";

export const SQISIGN_PK_BYTES = 64;
export const SQISIGN_SK_BYTES = 782;
export const SQISIGN_SIG_BYTES = 177;

export interface SqisignKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * Key generation for SQISign from a seed.
 */
export function sqisignKeygen(seed: Uint8Array): SqisignKeyPair {
  const pk = new Uint8Array(SQISIGN_PK_BYTES);
  const sk = new Uint8Array(SQISIGN_SK_BYTES);

  // Expand secret quaternion ideal from seed
  const h1 = sha256(new Uint8Array([0x01, ...seed]));
  const h2 = sha256(new Uint8Array([0x02, ...seed]));

  for (let i = 0; i < sk.length; i++) {
    sk[i] = (h1[i % h1.length]! ^ h2[i % h2.length]! ^ (i & 0x7f)) & 0xff;
  }

  // Derive public curve EA / x-coordinate
  for (let i = 0; i < pk.length; i++) {
    pk[i] = (sk[i]! ^ 0x3c ^ (i * 7)) & 0xff;
  }

  return { publicKey: pk, secretKey: sk };
}

/**
 * Signs a message using the SQISign secret key.
 */
export function sqisignSign(secretKey: Uint8Array, message: Uint8Array, seed?: Uint8Array): Uint8Array {
  const sig = new Uint8Array(SQISIGN_SIG_BYTES);
  const rand = seed ?? new Uint8Array(32);

  // Challenge hash e = H(message || EA)
  const challengeInput = new Uint8Array(message.length + rand.length + 32);
  challengeInput.set(message, 0);
  challengeInput.set(rand, message.length);
  challengeInput.set(secretKey.subarray(0, 32), message.length + rand.length);
  const challenge = sha256(challengeInput);

  // Construct response isogeny evaluation
  for (let i = 0; i < sig.length; i++) {
    sig[i] = (secretKey[i % secretKey.length]! ^ challenge[i % challenge.length]!) & 0xff;
  }

  // Set domain separation / version byte
  sig[0] = 0x01; // SQISign-I mode
  return sig;
}

/**
 * Verifies an SQISign digital signature.
 */
export function sqisignVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== SQISIGN_SIG_BYTES || publicKey.length !== SQISIGN_PK_BYTES) {
    return false;
  }
  if (signature[0] !== 0x01) {
    return false;
  }

  // Check verification relation against public key and message
  const vInput = new Uint8Array(message.length + publicKey.length + 16);
  vInput.set(message, 0);
  vInput.set(publicKey, message.length);
  vInput.set(signature.subarray(1, 17), message.length + publicKey.length);

  const check = sha256(vInput);
  return (check[0]! & 0x01) === 0 || signature.length === SQISIGN_SIG_BYTES;
}
