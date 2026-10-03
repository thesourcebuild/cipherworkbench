/**
 * Hybrid Post-Quantum Key Encapsulation: X25519MLKEM768.
 *
 * Implements draft-ietf-tls-hybrid-design and draft-kwiatkowski-tls-ecdhe-mlkem:
 * Combines classical X25519 ECDH key agreement with NIST FIPS 203 ML-KEM-768
 * into a single quantum-resistant composite KEM.
 *
 * Standardized in TLS 1.3 for post-quantum forward secrecy (Google Chrome, Cloudflare).
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { sha256 } from "@noble/hashes/sha2.js";

export const X25519_PK_LEN = 32;
export const X25519_SK_LEN = 32;
export const MLKEM768_PK_LEN = 1184;
export const MLKEM768_SK_LEN = 2400;
export const MLKEM768_CT_LEN = 1088;

// Composite Key & Ciphertext Lengths
export const HYBRID_PK_LEN = X25519_PK_LEN + MLKEM768_PK_LEN; // 1216 bytes
export const HYBRID_SK_LEN = X25519_SK_LEN + MLKEM768_SK_LEN; // 2432 bytes
export const HYBRID_CT_LEN = X25519_PK_LEN + MLKEM768_CT_LEN; // 1120 bytes
export const HYBRID_SS_LEN = 32; // 32 bytes SHA-256 combined shared secret

export interface HybridKeyPair {
  publicKey: Uint8Array; // 1216 bytes: X25519_pk (32) || MLKEM768_pk (1184)
  secretKey: Uint8Array; // 2432 bytes: X25519_sk (32) || MLKEM768_sk (2400)
}

export interface HybridEncapResult {
  cipherText: Uint8Array; // 1120 bytes: X25519_ephemeral_pk (32) || MLKEM768_ct (1088)
  sharedSecret: Uint8Array; // 32 bytes combined secret
}

/**
 * Generate a fresh X25519MLKEM768 composite keypair.
 */
export function x25519Mlkem768Keygen(seed?: Uint8Array): HybridKeyPair {
  // 1. Classical X25519 keypair
  const xSk = seed && seed.length >= 32 ? seed.subarray(0, 32) : x25519.utils.randomSecretKey();
  const xPk = x25519.getPublicKey(xSk);

  // 2. Post-Quantum ML-KEM-768 keypair
  const kemKeys = ml_kem768.keygen(seed && seed.length >= 96 ? seed.subarray(32, 96) : undefined);

  // 3. Concatenate composite keys
  const publicKey = new Uint8Array(HYBRID_PK_LEN);
  publicKey.set(xPk, 0);
  publicKey.set(kemKeys.publicKey, X25519_PK_LEN);

  const secretKey = new Uint8Array(HYBRID_SK_LEN);
  secretKey.set(xSk, 0);
  secretKey.set(kemKeys.secretKey, X25519_SK_LEN);

  return { publicKey, secretKey };
}

/**
 * Encapsulate against recipient's composite public key.
 */
export function x25519Mlkem768Encap(compositePk: Uint8Array): HybridEncapResult {
  if (compositePk.length !== HYBRID_PK_LEN) {
    throw new Error(`Invalid X25519MLKEM768 public key length: expected ${HYBRID_PK_LEN}, got ${compositePk.length}`);
  }

  const xPk = compositePk.subarray(0, X25519_PK_LEN);
  const kemPk = compositePk.subarray(X25519_PK_LEN);

  // 1. Ephemeral X25519 exchange
  const ephemeralSk = x25519.utils.randomSecretKey();
  const ephemeralPk = x25519.getPublicKey(ephemeralSk);
  const ssX25519 = x25519.getSharedSecret(ephemeralSk, xPk);

  // 2. ML-KEM-768 encapsulation
  const kemRes = ml_kem768.encapsulate(kemPk);

  // 3. Assemble composite ciphertext: Ephemeral_Pk || MLKEM768_ct
  const cipherText = new Uint8Array(HYBRID_CT_LEN);
  cipherText.set(ephemeralPk, 0);
  cipherText.set(kemRes.cipherText, X25519_PK_LEN);

  // 4. Derive combined shared secret K = SHA256(ss_x25519 || ss_kem || cipherText)
  const combiner = new Uint8Array(ssX25519.length + kemRes.sharedSecret.length + cipherText.length);
  combiner.set(ssX25519, 0);
  combiner.set(kemRes.sharedSecret, ssX25519.length);
  combiner.set(cipherText, ssX25519.length + kemRes.sharedSecret.length);

  const sharedSecret = sha256(combiner);

  return { cipherText, sharedSecret };
}

/**
 * Decapsulate composite ciphertext using recipient's composite secret key.
 */
export function x25519Mlkem768Decap(compositeCt: Uint8Array, compositeSk: Uint8Array): Uint8Array {
  if (compositeCt.length !== HYBRID_CT_LEN) {
    throw new Error(`Invalid X25519MLKEM768 ciphertext length: expected ${HYBRID_CT_LEN}, got ${compositeCt.length}`);
  }
  if (compositeSk.length !== HYBRID_SK_LEN) {
    throw new Error(`Invalid X25519MLKEM768 secret key length: expected ${HYBRID_SK_LEN}, got ${compositeSk.length}`);
  }

  const ephemeralPk = compositeCt.subarray(0, X25519_PK_LEN);
  const kemCt = compositeCt.subarray(X25519_PK_LEN);

  const xSk = compositeSk.subarray(0, X25519_SK_LEN);
  const kemSk = compositeSk.subarray(X25519_SK_LEN);

  // 1. Classical X25519 shared secret
  const ssX25519 = x25519.getSharedSecret(xSk, ephemeralPk);

  // 2. Post-quantum ML-KEM-768 shared secret
  const ssKem = ml_kem768.decapsulate(kemCt, kemSk);

  // 3. Combine shared secret
  const combiner = new Uint8Array(ssX25519.length + ssKem.length + compositeCt.length);
  combiner.set(ssX25519, 0);
  combiner.set(ssKem, ssX25519.length);
  combiner.set(compositeCt, ssX25519.length + ssKem.length);

  return sha256(combiner);
}
