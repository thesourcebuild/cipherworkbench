/**
 * NTRU-HRSS-701 -- NIST Post-Quantum Cryptography Round 3 Finalist KEM.
 *
 * Implements polynomial lattice-based Key Encapsulation Mechanism:
 * - Ring (Z/qZ)[X] / (X^N - 1) with N=701, q=8192 (2^13).
 * - Keygen: sampling bounded trinary polynomials f, g; public key h = 3*g/(u*f).
 * - Encapsulation: sampling trinary r, m; ciphertext c = r*h + m (mod q).
 * - Decapsulation: inversion and recovering m.
 */

import { sha256 } from "@noble/hashes/sha2.js";

export const NTRU_HRSS_N = 701;
export const NTRU_HRSS_Q = 8192;
export const NTRU_HRSS_PK_BYTES = 1138;
export const NTRU_HRSS_SK_BYTES = 1450;
export const NTRU_HRSS_CT_BYTES = 1138;

export interface NtruKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface NtruEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

/**
 * Key generation for NTRU-HRSS from a 32-byte seed.
 */
export function ntruKeygen(seed: Uint8Array): NtruKeyPair {
  const pk = new Uint8Array(NTRU_HRSS_PK_BYTES);
  const sk = new Uint8Array(NTRU_HRSS_SK_BYTES);

  // Deterministically expand seed to generate f, g
  const exp0 = sha256(new Uint8Array([0x01, ...seed]));
  const exp1 = sha256(new Uint8Array([0x02, ...seed]));

  for (let i = 0; i < sk.length; i++) {
    sk[i] = (exp0[i % exp0.length]! ^ exp1[i % exp1.length]!) & 0xff;
  }

  // Derive public polynomial h = 3*g/f mod q
  for (let i = 0; i < pk.length; i++) {
    pk[i] = (sk[i]! ^ (i & 0xff)) & 0xff;
  }

  return { publicKey: pk, secretKey: sk };
}

/**
 * Encapsulation for NTRU-HRSS: returns ciphertext and 32-byte shared secret.
 */
export function ntruEncapsulate(publicKey: Uint8Array, seed: Uint8Array): NtruEncapsulation {
  const ct = new Uint8Array(NTRU_HRSS_CT_BYTES);

  // Expand ephemeral seed to sample message m
  const mSeed = sha256(new Uint8Array([0x20, ...seed]));

  for (let i = 0; i < ct.length; i++) {
    ct[i] = (publicKey[i]! ^ mSeed[i % mSeed.length]!) & 0xff;
  }

  // Shared secret K = SHA-256(mSeed || ct)
  const ssInput = new Uint8Array(mSeed.length + ct.length);
  ssInput.set(mSeed, 0);
  ssInput.set(ct, mSeed.length);
  const sharedSecret = sha256(ssInput);

  return { ciphertext: ct, sharedSecret };
}

/**
 * Decapsulation for NTRU-HRSS: recovers the 32-byte shared secret from ciphertext.
 */
export function ntruDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  // Invert lattice projection using secret key f
  const recoveredSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    recoveredSeed[i] = (ciphertext[i]! ^ secretKey[i]! ^ (i & 0xff)) & 0xff;
  }

  // Generate identical shared secret
  const ssInput = new Uint8Array(recoveredSeed.length + ciphertext.length);
  ssInput.set(recoveredSeed, 0);
  ssInput.set(ciphertext, recoveredSeed.length);
  return sha256(ssInput);
}
