/**
 * RFC 9180: Hybrid Public Key Encryption (HPKE)
 *
 * Implements standard Hybrid Public Key Encryption combining:
 *  - KEM: DHKEM(X25519, HKDF-SHA256) (0x0020) and DHKEM(P-256, HKDF-SHA256) (0x0010)
 *  - KDF: HKDF-SHA256 (0x0001)
 *  - AEAD: AES-128-GCM (0x0001), AES-256-GCM (0x0002), ChaCha20-Poly1305 (0x0003)
 *
 * Supported Modes:
 *  - Mode 0x00: Base (authenticated to recipient via asymmetric public key)
 *
 * Used in: TLS 1.3 Encrypted Client Hello (ECH), Messaging Layer Security (MLS),
 * Apple Privacy-Preserving Measurement, Oblivious HTTP (OHTTP).
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { extract, expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { gcm } from "@noble/ciphers/aes.js";

export const HPKE_KEM_P256_SHA256 = 0x0010;
export const HPKE_KEM_X25519_SHA256 = 0x0020;

export const HPKE_KDF_HKDF_SHA256 = 0x0001;

export const HPKE_AEAD_AES_128_GCM = 0x0001;
export const HPKE_AEAD_AES_256_GCM = 0x0002;
export const HPKE_AEAD_CHACHA20_POLY1305 = 0x0003;

export const HPKE_MODE_BASE = 0x00;

const TEXT_ENCODER = new TextEncoder();

export function hpkeI2osp(val: number, len: number): Uint8Array {
  const buf = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    buf[i] = val & 0xff;
    val >>= 8;
  }
  return buf;
}

export function hpkeConcat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function parseBytes(val: Uint8Array | string): Uint8Array {
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

export function hpkeKemSuiteId(kemId: number): Uint8Array {
  return hpkeConcat(TEXT_ENCODER.encode("KEM"), hpkeI2osp(kemId, 2));
}

export function hpkeSuiteId(kemId: number, kdfId: number, aeadId: number): Uint8Array {
  return hpkeConcat(TEXT_ENCODER.encode("HPKE"), hpkeI2osp(kemId, 2), hpkeI2osp(kdfId, 2), hpkeI2osp(aeadId, 2));
}

export function labeledExtract(
  suiteId: Uint8Array,
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array,
): Uint8Array {
  const labeledIkm = hpkeConcat(TEXT_ENCODER.encode("HPKE-v1"), suiteId, TEXT_ENCODER.encode(label), ikm);
  return extract(sha256, labeledIkm, salt.length > 0 ? salt : undefined);
}

export function labeledExpand(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const labeledInfo = hpkeConcat(hpkeI2osp(length, 2), TEXT_ENCODER.encode("HPKE-v1"), suiteId, TEXT_ENCODER.encode(label), info);
  return expand(sha256, prk, labeledInfo, length);
}

export interface HpkeKeypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Generates an HPKE recipient keypair for the specified KEM.
 */
export function hpkeKeygen(kemId: number = HPKE_KEM_X25519_SHA256, seed?: Uint8Array): HpkeKeypair {
  if (kemId === HPKE_KEM_X25519_SHA256) {
    let sk: Uint8Array;
    if (seed && seed.length >= 32) {
      sk = seed.slice(0, 32);
    } else {
      sk = x25519.utils.randomSecretKey();
    }
    const pk = x25519.getPublicKey(sk);
    return { secretKey: sk, publicKey: pk };
  } else if (kemId === HPKE_KEM_P256_SHA256) {
    let sk: Uint8Array;
    if (seed && seed.length >= 32) {
      sk = seed.slice(0, 32);
    } else {
      sk = p256.utils.randomSecretKey();
    }
    // Uncompressed 65-byte public key
    const pk = p256.getPublicKey(sk, false);
    return { secretKey: sk, publicKey: pk };
  }
  throw new Error(`Unsupported KEM ID: ${kemId}`);
}

export function hpkeDerivePublic(secretKey: Uint8Array, kemId: number = HPKE_KEM_X25519_SHA256): Uint8Array {
  if (kemId === HPKE_KEM_X25519_SHA256) {
    return x25519.getPublicKey(secretKey);
  } else if (kemId === HPKE_KEM_P256_SHA256) {
    return p256.getPublicKey(secretKey, false);
  }
  throw new Error(`Unsupported KEM ID: ${kemId}`);
}

function dhPerform(kemId: number, secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (kemId === HPKE_KEM_X25519_SHA256) {
    if (secretKey.length !== 32 || publicKey.length !== 32) {
      throw new Error(`X25519 keys must be 32 bytes`);
    }
    return x25519.getSharedSecret(secretKey, publicKey);
  } else if (kemId === HPKE_KEM_P256_SHA256) {
    if (secretKey.length !== 32) {
      throw new Error(`P-256 secret key must be 32 bytes`);
    }
    const ss = p256.getSharedSecret(secretKey, publicKey);
    // RFC 9180 §7.1.3: DHKEM(P-256) zz is the 32-byte x-coordinate
    if (ss.length === 33) return ss.slice(1, 33);
    if (ss.length === 65) return ss.slice(1, 33);
    return ss.slice(0, 32);
  }
  throw new Error(`Unsupported KEM ID: ${kemId}`);
}

function kemLengths(kemId: number): { nSecret: number; nEnc: number; nPk: number } {
  if (kemId === HPKE_KEM_X25519_SHA256) {
    return { nSecret: 32, nEnc: 32, nPk: 32 };
  } else if (kemId === HPKE_KEM_P256_SHA256) {
    return { nSecret: 32, nEnc: 65, nPk: 65 };
  }
  throw new Error(`Unsupported KEM ID: ${kemId}`);
}

function aeadLengths(aeadId: number): { nk: number; nn: number; nt: number } {
  if (aeadId === HPKE_AEAD_AES_128_GCM) {
    return { nk: 16, nn: 12, nt: 16 };
  } else if (aeadId === HPKE_AEAD_AES_256_GCM) {
    return { nk: 32, nn: 12, nt: 16 };
  } else if (aeadId === HPKE_AEAD_CHACHA20_POLY1305) {
    return { nk: 32, nn: 12, nt: 16 };
  }
  throw new Error(`Unsupported AEAD ID: ${aeadId}`);
}

function aeadEncrypt(aeadId: number, key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
  if (aeadId === HPKE_AEAD_CHACHA20_POLY1305) {
    const cipher = chacha20poly1305(key, nonce, aad);
    return cipher.encrypt(plaintext);
  } else if (aeadId === HPKE_AEAD_AES_128_GCM || aeadId === HPKE_AEAD_AES_256_GCM) {
    const cipher = gcm(key, nonce, aad);
    return cipher.encrypt(plaintext);
  }
  throw new Error(`Unsupported AEAD ID: ${aeadId}`);
}

function aeadDecrypt(aeadId: number, key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array {
  if (aeadId === HPKE_AEAD_CHACHA20_POLY1305) {
    const cipher = chacha20poly1305(key, nonce, aad);
    return cipher.decrypt(ciphertext);
  } else if (aeadId === HPKE_AEAD_AES_128_GCM || aeadId === HPKE_AEAD_AES_256_GCM) {
    const cipher = gcm(key, nonce, aad);
    return cipher.decrypt(ciphertext);
  }
  throw new Error(`Unsupported AEAD ID: ${aeadId}`);
}

export interface HpkeSealOptions {
  recipientPublicKey: Uint8Array | string;
  plaintext: Uint8Array;
  kemId?: number;
  kdfId?: number;
  aeadId?: number;
  info?: Uint8Array;
  aad?: Uint8Array;
  ephemeralSeed?: Uint8Array;
}

export interface HpkeSealResult {
  encapsulatedKey: Uint8Array;
  ciphertext: Uint8Array;
  container: Uint8Array;
}

/**
 * HPKE Single-Shot Seal (Mode 0x00 Base).
 * Encapsulates ephemeral key, derives encryption key, and encrypts plaintext.
 */
export function hpkeSeal(options: HpkeSealOptions): HpkeSealResult {
  const kemId = options.kemId ?? HPKE_KEM_X25519_SHA256;
  const kdfId = options.kdfId ?? HPKE_KDF_HKDF_SHA256;
  const aeadId = options.aeadId ?? HPKE_AEAD_CHACHA20_POLY1305;
  const pkR = parseBytes(options.recipientPublicKey);
  const info = options.info ?? new Uint8Array(0);
  const aad = options.aad ?? new Uint8Array(0);

  const { nSecret } = kemLengths(kemId);
  const { nk, nn } = aeadLengths(aeadId);

  // 1. Generate ephemeral keypair
  const ephemeral = hpkeKeygen(kemId, options.ephemeralSeed);
  const enc = ephemeral.publicKey;

  // 2. Perform DH
  const zz = dhPerform(kemId, ephemeral.secretKey, pkR);

  // 3. ExtractAndExpand for KEM
  const kemSuite = hpkeKemSuiteId(kemId);
  const kemContext = hpkeConcat(enc, pkR);
  const eaePrk = labeledExtract(kemSuite, new Uint8Array(0), "eae_prk", zz);
  const sharedSecret = labeledExpand(kemSuite, eaePrk, "shared_secret", kemContext, nSecret);

  // 4. KeySchedule
  const hpkeSuite = hpkeSuiteId(kemId, kdfId, aeadId);
  const emptyBytes = new Uint8Array(0);
  const pskIdHash = labeledExtract(hpkeSuite, emptyBytes, "psk_id_hash", emptyBytes);
  const infoHash = labeledExtract(hpkeSuite, emptyBytes, "info_hash", info);
  const ksContext = hpkeConcat(new Uint8Array([HPKE_MODE_BASE]), pskIdHash, infoHash);

  const secret = labeledExtract(hpkeSuite, sharedSecret, "secret", emptyBytes);
  const key = labeledExpand(hpkeSuite, secret, "key", ksContext, nk);
  const baseNonce = labeledExpand(hpkeSuite, secret, "base_nonce", ksContext, nn);

  // 5. AEAD Seal
  const ciphertext = aeadEncrypt(aeadId, key, baseNonce, options.plaintext, aad);
  const container = hpkeConcat(enc, ciphertext);

  return {
    encapsulatedKey: enc,
    ciphertext,
    container,
  };
}

export interface HpkeOpenOptions {
  recipientSecretKey: Uint8Array | string;
  recipientPublicKey?: Uint8Array | string;
  encapsulatedKey?: Uint8Array | string;
  ciphertext?: Uint8Array | string;
  container?: Uint8Array | string;
  kemId?: number;
  kdfId?: number;
  aeadId?: number;
  info?: Uint8Array;
  aad?: Uint8Array;
}

/**
 * HPKE Single-Shot Open (Mode 0x00 Base).
 * Decapsulates shared secret, derives decryption key, and decrypts ciphertext.
 */
export function hpkeOpen(options: HpkeOpenOptions): Uint8Array {
  const kemId = options.kemId ?? HPKE_KEM_X25519_SHA256;
  const kdfId = options.kdfId ?? HPKE_KDF_HKDF_SHA256;
  const aeadId = options.aeadId ?? HPKE_AEAD_CHACHA20_POLY1305;
  const skR = parseBytes(options.recipientSecretKey);
  const info = options.info ?? new Uint8Array(0);
  const aad = options.aad ?? new Uint8Array(0);

  const { nSecret, nEnc } = kemLengths(kemId);
  const { nk, nn } = aeadLengths(aeadId);

  let enc: Uint8Array;
  let ciphertext: Uint8Array;

  if (options.container) {
    const rawContainer = parseBytes(options.container);
    if (rawContainer.length < nEnc) {
      throw new Error(`HPKE container too short: must be at least ${nEnc} bytes`);
    }
    enc = rawContainer.slice(0, nEnc);
    ciphertext = rawContainer.slice(nEnc);
  } else if (options.encapsulatedKey && options.ciphertext) {
    enc = parseBytes(options.encapsulatedKey);
    ciphertext = parseBytes(options.ciphertext);
  } else {
    throw new Error("Must provide either 'container' or both 'encapsulatedKey' and 'ciphertext'");
  }

  // Derive recipient public key if not explicitly passed
  let pkR: Uint8Array;
  if (options.recipientPublicKey) {
    pkR = parseBytes(options.recipientPublicKey);
  } else {
    pkR = kemId === HPKE_KEM_X25519_SHA256 ? x25519.getPublicKey(skR) : p256.getPublicKey(skR, false);
  }

  // 1. Perform DH
  const zz = dhPerform(kemId, skR, enc);

  // 2. ExtractAndExpand for KEM
  const kemSuite = hpkeKemSuiteId(kemId);
  const kemContext = hpkeConcat(enc, pkR);
  const eaePrk = labeledExtract(kemSuite, new Uint8Array(0), "eae_prk", zz);
  const sharedSecret = labeledExpand(kemSuite, eaePrk, "shared_secret", kemContext, nSecret);

  // 3. KeySchedule
  const hpkeSuite = hpkeSuiteId(kemId, kdfId, aeadId);
  const emptyBytes = new Uint8Array(0);
  const pskIdHash = labeledExtract(hpkeSuite, emptyBytes, "psk_id_hash", emptyBytes);
  const infoHash = labeledExtract(hpkeSuite, emptyBytes, "info_hash", info);
  const ksContext = hpkeConcat(new Uint8Array([HPKE_MODE_BASE]), pskIdHash, infoHash);

  const secret = labeledExtract(hpkeSuite, sharedSecret, "secret", emptyBytes);
  const key = labeledExpand(hpkeSuite, secret, "key", ksContext, nk);
  const baseNonce = labeledExpand(hpkeSuite, secret, "base_nonce", ksContext, nn);

  // 4. AEAD Open
  return aeadDecrypt(aeadId, key, baseNonce, ciphertext, aad);
}
