/**
 * BIP-340 Schnorr Signatures over secp256k1 & BIP-341 Taproot Key Derivation
 * Specifications:
 *   - BIP-340: Schnorr Signatures for secp256k1
 *   - BIP-341: Taproot: SegWit version 1 spending rules
 *
 * Characteristics:
 *   - 32-byte x-only public keys (eliminating malleability and saving 1 byte)
 *   - 64-byte deterministic/hedged signatures (32-byte R.x + 32-byte s)
 *   - Native batch verification support
 *   - Taproot tweaking (key-path vs script-path spending)
 */

import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";

export const BIP340_PUBKEY_SIZE = 32;
export const BIP340_SIGNATURE_SIZE = 64;
export const BIP340_SECRET_KEY_SIZE = 32;

function parseHexOrBytes(val: Uint8Array | string): Uint8Array {
  if (typeof val === "string") {
    const clean = val.replace(/^0x/i, "").trim();
    if (clean.length % 2 !== 0) throw new Error("Invalid hex string length");
    const arr = new Uint8Array(clean.length / 2);
    for (let i = 0; i < arr.length; i++) {
      arr[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return arr;
  }
  return val;
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let res = 0n;
  for (let i = 0; i < bytes.length; i++) {
    res = (res << 8n) | BigInt(bytes[i]!);
  }
  return res;
}

function bigIntToBytesBE(num: bigint, len: number): Uint8Array {
  const res = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    res[i] = Number(num & 0xffn);
    num >>= 8n;
  }
  return res;
}

/**
 * Generates a fresh BIP-340 keypair (32-byte secret key scalar, 32-byte x-only public key).
 */
export function bip340Keygen(seed?: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
  let sk: Uint8Array;
  if (seed) {
    if (seed.length < 32) throw new Error("Seed must be at least 32 bytes");
    sk = seed.slice(0, 32);
  } else {
    sk = schnorr.utils.randomSecretKey();
  }

  const pk = schnorr.getPublicKey(sk);
  return { secretKey: sk, publicKey: pk };
}

/**
 * Derives a 32-byte x-only public key from a 32-byte private key.
 */
export function bip340GetPublicKey(secretKey: Uint8Array | string): Uint8Array {
  const sk = parseHexOrBytes(secretKey);
  return schnorr.getPublicKey(sk);
}

/**
 * Signs a message using BIP-340 Schnorr signature (64 bytes).
 * @param message 32-byte message hash or arbitrary byte message
 * @param secretKey 32-byte secret key
 * @param auxRand optional 32-byte auxiliary random data for hedged nonces
 */
export function bip340Sign(
  message: Uint8Array,
  secretKey: Uint8Array | string,
  auxRand?: Uint8Array,
): Uint8Array {
  const sk = parseHexOrBytes(secretKey);
  return schnorr.sign(message, sk, auxRand);
}

/**
 * Verifies a 64-byte BIP-340 Schnorr signature against a 32-byte x-only public key.
 */
export function bip340Verify(
  signature: Uint8Array | string,
  message: Uint8Array,
  publicKey: Uint8Array | string,
): boolean {
  try {
    const sig = parseHexOrBytes(signature);
    const pk = parseHexOrBytes(publicKey);
    if (sig.length !== BIP340_SIGNATURE_SIZE || pk.length !== BIP340_PUBKEY_SIZE) {
      return false;
    }
    return schnorr.verify(sig, message, pk);
  } catch {
    return false;
  }
}

/**
 * Computes a BIP-340 Tagged Hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
 */
export function bip340TaggedHash(tag: string, message: Uint8Array): Uint8Array {
  return schnorr.utils.taggedHash(tag, message);
}

/**
 * BIP-341 Taproot Tweak for public keys:
 * Q = P + tagged_hash("TapTweak", P.x || merkleRoot) * G
 *
 * @param internalPublicKey 32-byte x-only internal public key
 * @param merkleRoot optional 32-byte script tree root hash (empty for key-path only)
 * @returns 32-byte tweaked x-only public key and parity flag
 */
export function bip341TaprootTweakPublicKey(
  internalPublicKey: Uint8Array | string,
  merkleRoot?: Uint8Array,
): { tweakedPublicKey: Uint8Array; parity: number } {
  const pkBytes = parseHexOrBytes(internalPublicKey);
  if (pkBytes.length !== 32) throw new Error("Internal public key must be 32 bytes");

  // Lift internal key x to Point with even y
  const x = bytesToBigIntBE(pkBytes);
  const p = schnorr.utils.lift_x(x);

  // Compute tweak data: P.x || merkleRoot
  const tweakData = new Uint8Array(32 + (merkleRoot?.length ?? 0));
  tweakData.set(pkBytes, 0);
  if (merkleRoot && merkleRoot.length > 0) {
    tweakData.set(merkleRoot, 32);
  }

  const tweakHash = schnorr.utils.taggedHash("TapTweak", tweakData);
  const tweakScalar = bytesToBigIntBE(tweakHash);
  if (tweakScalar >= secp256k1.Point.Fn.ORDER) {
    throw new Error("Taproot tweak exceeds curve order");
  }

  // Q = P + tweak * G
  const tweakPoint = secp256k1.Point.BASE.multiply(tweakScalar);
  const q = p.add(tweakPoint);
  if (q.equals(secp256k1.Point.ZERO)) {
    throw new Error("Tweaked point is point at infinity");
  }

  const parity = Number(q.y & 1n);
  const tweakedPublicKey = bigIntToBytesBE(q.x, 32);
  return { tweakedPublicKey, parity };
}

/**
 * BIP-341 Taproot Tweak for private keys:
 * d' = (d + t) mod n, adjusting for negation if P.y is odd.
 */
export function bip341TaprootTweakSecretKey(
  secretKey: Uint8Array | string,
  merkleRoot?: Uint8Array,
): Uint8Array {
  const skBytes = parseHexOrBytes(secretKey);
  if (skBytes.length !== 32) throw new Error("Secret key must be 32 bytes");

  const n = secp256k1.Point.Fn.ORDER;
  let d = bytesToBigIntBE(skBytes) % n;
  if (d === 0n) throw new Error("Secret key cannot be 0");

  const p = secp256k1.Point.BASE.multiply(d);
  if ((p.y & 1n) !== 0n) {
    d = n - d; // Negate if y is odd
  }

  const pkBytes = bigIntToBytesBE(p.x, 32);
  const tweakData = new Uint8Array(32 + (merkleRoot?.length ?? 0));
  tweakData.set(pkBytes, 0);
  if (merkleRoot && merkleRoot.length > 0) {
    tweakData.set(merkleRoot, 32);
  }

  const tweakHash = schnorr.utils.taggedHash("TapTweak", tweakData);
  const t = bytesToBigIntBE(tweakHash) % n;
  const tweakedSk = (d + t) % n;
  if (tweakedSk === 0n) throw new Error("Tweaked secret key cannot be 0");

  return bigIntToBytesBE(tweakedSk, 32);
}

/**
 * Batch verification of multiple BIP-340 signatures:
 * sum(a_i * s_i) * G == sum(a_i * R_i) + sum(a_i * e_i * P_i)
 */
export function bip340VerifyBatch(
  signatures: (Uint8Array | string)[],
  messages: Uint8Array[],
  publicKeys: (Uint8Array | string)[],
): boolean {
  try {
    if (signatures.length === 0 || signatures.length !== messages.length || signatures.length !== publicKeys.length) {
      return false;
    }

    const n = secp256k1.Point.Fn.ORDER;
    let sumS = 0n;
    let rightSide = secp256k1.Point.ZERO;

    for (let i = 0; i < signatures.length; i++) {
      const sig = parseHexOrBytes(signatures[i]!);
      const pkBytes = parseHexOrBytes(publicKeys[i]!);
      const msg = messages[i]!;

      if (sig.length !== 64 || pkBytes.length !== 32) return false;

      const rBytes = sig.slice(0, 32);
      const sBytes = sig.slice(32, 64);
      const r = bytesToBigIntBE(rBytes);
      const s = bytesToBigIntBE(sBytes);

      if (r >= secp256k1.Point.Fp.ORDER || s >= n) return false;

      const pkX = bytesToBigIntBE(pkBytes);
      const p = schnorr.utils.lift_x(pkX);
      const rPoint = schnorr.utils.lift_x(r);

      // Challenge e = taggedHash("BIP0340/challenge", r || P.x || msg) mod n
      const eData = new Uint8Array(64 + msg.length);
      eData.set(rBytes, 0);
      eData.set(pkBytes, 32);
      eData.set(msg, 64);
      const eHash = schnorr.utils.taggedHash("BIP0340/challenge", eData);
      const e = bytesToBigIntBE(eHash) % n;

      // Random weight a_i (a_0 = 1, a_i random 128-bit)
      const a = i === 0 ? 1n : (bytesToBigIntBE(globalThis.crypto.getRandomValues(new Uint8Array(16))) % n);

      sumS = (sumS + a * s) % n;

      // R_i + e_i * P_i
      const term = rPoint.add(p.multiply(e)).multiply(a);
      rightSide = rightSide.add(term);
    }

    const leftSide = secp256k1.Point.BASE.multiply(sumS);
    return leftSide.equals(rightSide);
  } catch {
    return false;
  }
}
