/**
 * ElGamal Public-Key Cryptosystem (Taher Elgamal, 1985 / IEEE 1363).
 *
 * Implements:
 * - Keypair generation over secp256k1:
 *   sk = random scalar, pk = sk * G
 * - Encryption (homomorphic):
 *   Given ephemeral k, c1 = k * G, c2 = m XOR KDF(k * pk)
 * - Decryption:
 *   m = c2 XOR KDF(sk * c1)
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";

const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export interface ElGamalCiphertext {
  c1: Uint8Array; // Ephemeral public key (33 bytes)
  c2: Uint8Array; // Masked payload (encrypted bytes)
}

export interface ElGamalKeyPair {
  publicKey: Uint8Array; // 33 bytes compressed point
  privateKey: Uint8Array; // 32 bytes scalar
}

function bytesToBigInt(b: Uint8Array): bigint {
  let res = 0n;
  for (let i = 0; i < b.length; i++) {
    res = (res << 8n) | BigInt(b[i]!);
  }
  return res;
}

function bigIntToBytes(n: bigint, len: number = 32): Uint8Array {
  const out = new Uint8Array(len);
  let temp = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return out;
}

export function elgamalKeygen(seed: Uint8Array): ElGamalKeyPair {
  const skNum = (bytesToBigInt(sha256(seed)) % (SECP256K1_ORDER - 1n)) + 1n;
  const privateKey = bigIntToBytes(skNum, 32);
  const publicKey = secp256k1.Point.BASE.multiply(skNum).toBytes(true);

  return { privateKey, publicKey };
}

export function elgamalEncrypt(
  message: Uint8Array,
  recipientPublicKey: Uint8Array,
  ephemeralSeed: Uint8Array,
): ElGamalCiphertext {
  const kNum = (bytesToBigInt(sha256(ephemeralSeed)) % (SECP256K1_ORDER - 1n)) + 1n;

  // c1 = k * G
  const c1 = secp256k1.Point.BASE.multiply(kNum).toBytes(true);

  // Shared secret S = k * pk
  const pkPoint = secp256k1.Point.fromBytes(recipientPublicKey);
  const sharedAffine = pkPoint.multiply(kNum).toAffine();
  const sharedBytes = sha256(bigIntToBytes(sharedAffine.x, 32));

  // c2 = message XOR KDF(sharedSecret)
  const c2 = new Uint8Array(message.length);
  for (let i = 0; i < message.length; i++) {
    c2[i] = message[i]! ^ sharedBytes[i % sharedBytes.length]!;
  }

  return { c1, c2 };
}

export function elgamalDecrypt(
  ciphertext: ElGamalCiphertext,
  recipientPrivateKey: Uint8Array,
): Uint8Array {
  const skNum = bytesToBigInt(recipientPrivateKey);

  // Recover shared secret S = sk * c1
  const c1Point = secp256k1.Point.fromBytes(ciphertext.c1);
  const sharedAffine = c1Point.multiply(skNum).toAffine();
  const sharedBytes = sha256(bigIntToBytes(sharedAffine.x, 32));

  const plaintext = new Uint8Array(ciphertext.c2.length);
  for (let i = 0; i < ciphertext.c2.length; i++) {
    plaintext[i] = ciphertext.c2[i]! ^ sharedBytes[i % sharedBytes.length]!;
  }

  return plaintext;
}
