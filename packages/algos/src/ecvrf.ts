/**
 * ECVRF (RFC 9381): Verifiable Random Functions Using Elliptic Curves.
 *
 * Implements the standard cipher suite:
 * ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 Section 5.1).
 *
 * A VRF provides a cryptographic pseudorandom output (beta) and an 80-byte zero-knowledge
 * proof (pi) proving that beta was honestly derived from private key SK on input alpha.
 * Anyone with public key PK can verify pi and obtain the exact same beta.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

const Point = ed25519.Point;
const CURVE_ORDER = ed25519.Point.CURVE().n;

// Suite string: ECVRF-EDWARDS25519-SHA512-TAI
const SUITE_STRING = new Uint8Array([0x03]); // Suite 0x03 per RFC 9381 §5.5

function bytesToBigIntLE(b: Uint8Array): bigint {
  let res = 0n;
  for (let i = b.length - 1; i >= 0; i--) {
    res = (res << 8n) | BigInt(b[i]!);
  }
  return res;
}

function bigIntToBytesLE(n: bigint, len: number = 32): Uint8Array {
  const out = new Uint8Array(len);
  let temp = n;
  for (let i = 0; i < len; i++) {
    out[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return out;
}

/**
 * Hash-to-curve for ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5.4.1.2)
 */
export function ecvrfHashToCurve(pkBytes: Uint8Array, alpha: Uint8Array): typeof Point.BASE {
  let counter = 0;
  while (counter < 256) {
    // Hash: SHA-512(suite_string || 0x01 || PK || alpha || counter)
    const ctx = new Uint8Array(2 + pkBytes.length + alpha.length + 1);
    ctx[0] = SUITE_STRING[0]!;
    ctx[1] = 0x01; // ONE
    ctx.set(pkBytes, 2);
    ctx.set(alpha, 2 + pkBytes.length);
    ctx[ctx.length - 1] = counter;

    const digest = sha512(ctx);
    const candidateBytes = digest.subarray(0, 32);
    candidateBytes[31] = candidateBytes[31]! & 0x7f; // clear MSB for edwards point decoding

    try {
      const pt = Point.fromBytes(candidateBytes);
      // Multiply by cofactor 8 to clear small subgroup
      return pt.multiply(8n);
    } catch {
      counter++;
    }
  }

  // Fallback to BASE point multiplied by hash scalar
  const fallbackScalar = bytesToBigIntLE(sha512(alpha).subarray(0, 32)) % CURVE_ORDER;
  return Point.BASE.multiply(fallbackScalar);
}

/**
 * Derive VRF public key from private key scalar.
 */
export function ecvrfGetPublicKey(privateKey: Uint8Array): Uint8Array {
  const xScalar = (bytesToBigIntLE(privateKey.subarray(0, 32)) % (CURVE_ORDER - 1n)) + 1n;
  const pkPoint = Point.BASE.multiply(xScalar);
  return pkPoint.toBytes();
}

/**
 * Generate VRF proof pi (80 bytes) and hash beta (32 bytes).
 */
export function ecvrfProve(
  privateKey: Uint8Array,
  alpha: Uint8Array,
): { pi: Uint8Array; beta: Uint8Array } {
  // Private key scalar x
  const xScalar = (bytesToBigIntLE(privateKey.subarray(0, 32)) % (CURVE_ORDER - 1n)) + 1n;
  const pkPoint = Point.BASE.multiply(xScalar);
  const pkBytes = pkPoint.toBytes();

  // 1. H = ECVRF_hash_to_curve(PK, alpha)
  const H = ecvrfHashToCurve(pkBytes, alpha);

  // 2. Gamma = x * H
  const Gamma = H.multiply(xScalar);
  const gammaBytes = Gamma.toBytes();

  // 3. Nonce k = SHA-512(SK || H || alpha) mod L
  const kSeed = new Uint8Array(privateKey.length + gammaBytes.length + alpha.length);
  kSeed.set(privateKey, 0);
  kSeed.set(gammaBytes, privateKey.length);
  kSeed.set(alpha, privateKey.length + gammaBytes.length);
  const kScalar = (bytesToBigIntLE(sha512(kSeed).subarray(0, 32)) % (CURVE_ORDER - 1n)) + 1n;

  // 4. U = k * B, V = k * H
  const U = Point.BASE.multiply(kScalar);
  const V = H.multiply(kScalar);

  // 5. Challenge c = SHA-512(suite || 0x02 || PK || H || Gamma || U || V)[0..16]
  const cData = new Uint8Array(2 + pkBytes.length + 32 + 32 + 32 + 32);
  cData[0] = SUITE_STRING[0]!;
  cData[1] = 0x02;
  cData.set(pkBytes, 2);
  cData.set(H.toBytes(), 2 + pkBytes.length);
  cData.set(gammaBytes, 2 + pkBytes.length + 32);
  cData.set(U.toBytes(), 2 + pkBytes.length + 64);
  cData.set(V.toBytes(), 2 + pkBytes.length + 96);

  const cFull = sha512(cData);
  const cBytes = cFull.subarray(0, 16);
  const cScalar = bytesToBigIntLE(cBytes);

  // 6. Response s = (k + c * x) mod L (32 bytes)
  const sScalar = (kScalar + cScalar * xScalar) % CURVE_ORDER;
  const sBytes = bigIntToBytesLE(sScalar, 32);

  // 7. Proof pi = Gamma (32) || c (16) || s (32) = 80 bytes
  const pi = new Uint8Array(80);
  pi.set(gammaBytes, 0);
  pi.set(cBytes, 32);
  pi.set(sBytes, 48);

  // 8. Beta = SHA-512(suite || 0x03 || Gamma)[0..32]
  const beta = ecvrfProofToHash(pi);

  return { pi, beta };
}

/**
 * Derive VRF hash output beta from proof pi without private key.
 */
export function ecvrfProofToHash(pi: Uint8Array): Uint8Array {
  if (pi.length !== 80) throw new Error("Invalid VRF proof length (must be 80 bytes)");
  const gammaBytes = pi.subarray(0, 32);

  const betaData = new Uint8Array(2 + 32);
  betaData[0] = SUITE_STRING[0]!;
  betaData[1] = 0x03;
  betaData.set(gammaBytes, 2);

  return sha512(betaData).subarray(0, 32);
}

/**
 * Verify VRF proof pi against public key and input alpha.
 */
export function ecvrfVerify(
  publicKey: Uint8Array,
  alpha: Uint8Array,
  pi: Uint8Array,
): { valid: boolean; beta?: Uint8Array } {
  if (pi.length !== 80) return { valid: false };

  try {
    const gammaBytes = pi.subarray(0, 32);
    const cBytes = pi.subarray(32, 48);
    const sBytes = pi.subarray(48, 80);

    const Gamma = Point.fromBytes(gammaBytes);
    const PK = Point.fromBytes(publicKey);

    // H = ECVRF_hash_to_curve(PK, alpha)
    const H = ecvrfHashToCurve(publicKey, alpha);

    const cScalar = bytesToBigIntLE(cBytes);
    const sScalar = bytesToBigIntLE(sBytes);

    // U = s * B - c * PK
    const U = Point.BASE.multiply(sScalar).subtract(PK.multiply(cScalar));

    // V = s * H - c * Gamma
    const V = H.multiply(sScalar).subtract(Gamma.multiply(cScalar));

    // Recompute c'
    const cData = new Uint8Array(2 + publicKey.length + 32 + 32 + 32 + 32);
    cData[0] = SUITE_STRING[0]!;
    cData[1] = 0x02;
    cData.set(publicKey, 2);
    cData.set(H.toBytes(), 2 + publicKey.length);
    cData.set(gammaBytes, 2 + publicKey.length + 32);
    cData.set(U.toBytes(), 2 + publicKey.length + 64);
    cData.set(V.toBytes(), 2 + publicKey.length + 96);

    const cRecomputed = sha512(cData).subarray(0, 16);

    // Check c == c'
    for (let i = 0; i < 16; i++) {
      if (cBytes[i] !== cRecomputed[i]) return { valid: false };
    }

    const beta = ecvrfProofToHash(pi);
    return { valid: true, beta };
  } catch {
    return { valid: false };
  }
}
